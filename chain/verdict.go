package main

// The verdict-publish path: the WRITE half of the Nostr transport (kind 1445)
// and the periodic state commitment (kind 1447).  See
// notes/REPLY-nostr-verdict-contract.md and MERGED-PROTOCOL-SPEC.md §9, which
// fix this contract.
//
// THE RULE THAT KEEPS IT HONEST: THE RELAY NOTIFIES, THE CHAIN DECIDES, THE
// ANCHOR PROVES.  The chain stays the source of truth for ordering, time and
// validity.  A verdict published here is a signed CLAIM about ALREADY-COMMITTED
// chain state; it is not a query result and it is not authoritative.  Three
// rules shape everything in this file, and they are non-negotiable:
//
//  1. PUBLISH ONLY AFTER COMMIT, ANCHORED TO THAT BLOCK.  A verdict carries the
//     committed height and the block hash of a COMMITTED block.  A claim a reorg
//     can contradict is worse than no claim, so we never publish for a pending
//     or uncommitted height.  The publisher (verdictpublish.go) enforces this by
//     reading ONLY the app's committed snapshot and refusing to emit a verdict
//     whose committed block hash it cannot yet read.
//
//  2. THE ANCHOR IS MANDATORY.  Every verdict and every state commitment
//     carries (height, hash).  A client MUST ignore an unanchored verdict --
//     ParseVerdict refuses it by name (ErrVerdictUnanchored), so the refusal is
//     assertable in a test.
//
//  3. VERDICTS ARE APPEND-ONLY.  Kind 1445 is a REGULAR kind (NIP-01 1000 <= n
//     < 10000): a relay stores every event and replaces nothing.  We do NOT
//     make 1445 parametrised-replaceable.  A lifecycle change (placed -> won ->
//     settled) is a NEW verdict event, and a client resolves latest-per-validator
//     for display.  This is what preserves the audit trail the whole security
//     argument rests on.
//
// Regular kinds, never the NIP-01 ephemeral range (20000-29999): khatru
// (`nak serve`) refuses an ephemeral EVENT with no matching live subscription
// ("mute: no one was listening for this") and does not buffer it.  A verdict
// that only exists while somebody happens to be subscribed is not a verdict.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	// VerdictSchema is the content schema of a kind-1445 verdict event.
	VerdictSchema = "arena.verdict.v1"
	// StateCommitSchema is the content schema of a kind-1447 state commitment.
	StateCommitSchema = "arena.statecommit.v1"
	// DerivedFromCommittedState states the determinism claim ON THE WIRE: the
	// outcome is a pure function of committed state, not a validator opinion.
	DerivedFromCommittedState = "committed_state"
	// StateCommitEvery is the default cadence, in blocks, of a state commitment.
	StateCommitEvery int64 = 100
)

// The four outcomes the state machine can decide.  Kept as plain strings so the
// value on the wire and the value in code cannot drift.
const (
	OutcomeWinner        = "winner"
	OutcomeReserveNotMet = "reserve_not_met"
	OutcomeCancelled     = "cancelled"
	OutcomeAborted       = "aborted"
)

// Named refusals.  A client ignores an unanchored verdict; naming the refusal
// lets a test assert exactly which rule fired.
var (
	ErrVerdictKind            = errors.New("not_a_verdict_event")
	ErrVerdictBadSchema       = errors.New("bad_verdict_schema")
	ErrVerdictUnanchored      = errors.New("unanchored_verdict")
	ErrVerdictBadSignature    = errors.New("bad_verdict_signature")
	ErrVerdictNotInRoster     = errors.New("verdict_not_in_roster")
	ErrCommitmentKind         = errors.New("not_a_state_commitment")
	ErrCommitmentBadSchema    = errors.New("bad_state_commitment_schema")
	ErrCommitmentBadSignature = errors.New("bad_state_commitment_signature")
	ErrCommitmentUnanchored   = errors.New("unanchored_state_commitment")
)

// ValidatorKey is one roster entry: a validator's Nostr pubkey, its moniker and
// its 1-based index.  The roster lives in Params, so it is inside the AppHash:
// a state commitment (kind 1447) commits to the roster at that height, which is
// why a client needs no separate roster-verification pass in this increment
// (REPLY §3.4).
type ValidatorKey struct {
	Pubkey string `json:"pubkey"` // x-only Nostr pubkey (64 lowercase hex)
	Name   string `json:"name"`
	Index  int    `json:"index"` // 1..N
}

// Roster returns the validator pubkeys as a set, for the client-side check.
func (p Params) Roster() map[string]ValidatorKey {
	out := make(map[string]ValidatorKey, len(p.Validators))
	for _, v := range p.Validators {
		out[v.Pubkey] = v
	}
	return out
}

// IsValidator reports whether pubkey is on the roster.
func (p Params) IsValidator(pubkey string) bool {
	_, ok := p.Roster()[pubkey]
	return ok
}

// Verdict is what committed state decides about one auction.  It is derived
// ONLY from committed state -- no clocks, no node-local data -- so two honest
// validators given the same state derive the same verdict.  That is the
// determinism property that makes a quorum of verdicts meaningful.
type Verdict struct {
	AuctionID string
	BidID     string // "" when the auction has no winning bid
	Outcome   string
}

// DeriveVerdict returns the verdict the committed state implies for auctionID,
// or ok=false when the auction has not closed (no verdict exists yet, so
// nothing should be published).  It reads only s, and it is deliberately total
// and side-effect free:
//
//   - a closed auction with a winning bid  -> winner (bid_id = the winning bid)
//   - a closed auction with no winning bid -> reserve_not_met (no bid_id)
//
// cancelled/aborted are reserved for the funding-abort path (kind 1446); they
// are not reachable from closeDue today, so this function never invents them.
// Because it is a pure function of committed state, two validators that agree on
// the state agree on the verdict -- the property the whole publish path rests
// on, and the first thing a reviewer should ask for.
func DeriveVerdict(s *State, auctionID string) (Verdict, bool) {
	au := s.Auctions[auctionID]
	if au == nil || au.Status != "closed" {
		return Verdict{}, false
	}
	if au.Winner != "" {
		return Verdict{AuctionID: au.ID, BidID: au.Winner, Outcome: OutcomeWinner}, true
	}
	return Verdict{AuctionID: au.ID, Outcome: OutcomeReserveNotMet}, true
}

// VerdictContent is the exact content JSON of a kind-1445 verdict event.
type VerdictContent struct {
	Schema            string  `json:"schema"`
	AuctionID         string  `json:"auction_id"`
	BidID             string  `json:"bid_id"`
	Outcome           string  `json:"outcome"`
	PayoutTokenSHA256 *string `json:"payout_token_sha256"` // null when no payout is claimed
	Height            int64   `json:"height"`
	BlockHash         string  `json:"block_hash"`
	DerivedFrom       string  `json:"derived_from"`
}

// StateCommitmentContent is the exact content JSON of a kind-1447 state commit.
type StateCommitmentContent struct {
	Schema  string `json:"schema"`
	Height  int64  `json:"height"`
	AppHash string `json:"app_hash"`
	Time    int64  `json:"time"`
}

// NostrPubkeyHex is the x-only Nostr pubkey (64 lowercase hex) for a secp256k1
// key.  This is the identity a validator signs its verdicts under, and the key
// a client roster-checks.
func NostrPubkeyHex(sk *btcec.PrivateKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(sk.PubKey()))
}

// verdictKeyFile is a validator's own verdict-signing key, written by
// `arena init` to that validator's home.  Like the FROST share it is per
// validator: a verdict signed under one key must stay distinguishable from a
// verdict signed under another, so there is never a shared publisher key.  One
// shared publisher would make a forged verdict indistinguishable from a real
// one, and the quorum argument would collapse.
type verdictKeyFile struct {
	Pubkey string `json:"pubkey"` // x-only Nostr pubkey (64 lowercase hex)
	Secret string `json:"secret"` // secp256k1 secret scalar (32-byte hex)
}

// loadVerdictKey reads a verdict-signing key from disk.
func loadVerdictKey(path string) (*btcec.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f verdictKeyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(f.Secret)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("verdict key: secret must be 32-byte hex")
	}
	sk, _ := btcec.PrivKeyFromBytes(raw)
	if NostrPubkeyHex(sk) != f.Pubkey {
		return nil, errors.New("verdict key: pubkey does not match the secret")
	}
	return sk, nil
}

// SignEvent builds and BIP-340 signs a Nostr event with this module's canonical
// serializer, so the event id and signature are exactly what Event.Verify
// accepts.  It is the one signer both the verdict and the commitment use.
func SignEvent(sk *btcec.PrivateKey, kind int, content string, tags [][]string, at int64) (*Event, error) {
	ev := &Event{Pubkey: NostrPubkeyHex(sk), CreatedAt: at, Kind: kind, Tags: tags, Content: content}
	h := sha256.Sum256([]byte(ev.Serialize()))
	ev.ID = hex.EncodeToString(h[:])
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		return nil, err
	}
	ev.Sig = hex.EncodeToString(sig.Serialize())
	return ev, nil
}

// BuildVerdictEvent builds a signed kind-1445 verdict event.  The height and
// block hash are MANDATORY: an empty block hash or a non-positive height is an
// error here, so an unanchored verdict cannot be built at all.  The event is
// signed under sk -- the validator's OWN key.  There is never one shared
// publisher key: a forged verdict must stay distinguishable from a real one.
func BuildVerdictEvent(sk *btcec.PrivateKey, v Verdict, height int64, blockHash string, payoutTokenSHA256 *string, at int64) (*Event, error) {
	if height <= 0 || blockHash == "" {
		return nil, ErrVerdictUnanchored
	}
	if v.AuctionID == "" || v.Outcome == "" {
		return nil, fmt.Errorf("verdict needs an auction id and an outcome")
	}
	c := VerdictContent{
		Schema:            VerdictSchema,
		AuctionID:         v.AuctionID,
		BidID:             v.BidID,
		Outcome:           v.Outcome,
		PayoutTokenSHA256: payoutTokenSHA256,
		Height:            height,
		BlockHash:         blockHash,
		DerivedFrom:       DerivedFromCommittedState,
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	tags := [][]string{
		{"auction", v.AuctionID},
	}
	// The bid tag is omitted for a no-bid / aborted auction (REPLY §3.2).
	if v.BidID != "" {
		tags = append(tags, []string{"bid", v.BidID})
	}
	tags = append(tags,
		[]string{"height", strconv.FormatInt(height, 10)},
		[]string{"hash", blockHash},
		[]string{"outcome", v.Outcome},
		[]string{"p", NostrPubkeyHex(sk)},
	)
	return SignEvent(sk, KindOutcome, string(body), tags, at)
}

// ParseVerdict reads a kind-1445 event as a client would: it verifies the
// signature, the schema, and the MANDATORY anchor, and refuses by name when the
// anchor is missing.  roster, when non-nil, additionally checks membership.
func ParseVerdict(ev *Event, roster map[string]ValidatorKey) (*VerdictContent, error) {
	if ev == nil || ev.Kind != KindOutcome {
		return nil, ErrVerdictKind
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerdictBadSignature, err)
	}
	var c VerdictContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		return nil, ErrVerdictBadSchema
	}
	if c.Schema != VerdictSchema {
		return nil, fmt.Errorf("%w: %q", ErrVerdictBadSchema, c.Schema)
	}
	// The anchor is read from the TAGS (indexable) and cross-checked against the
	// content, so a relay that re-framed one cannot hide the other.
	tagHeight, okH := tagValue(ev.Tags, "height")
	tagHash, okHash := tagValue(ev.Tags, "hash")
	if !okH || !okHash || tagHeight == "" || tagHash == "" || c.Height <= 0 || c.BlockHash == "" {
		return nil, ErrVerdictUnanchored
	}
	if tagHeight != strconv.FormatInt(c.Height, 10) || tagHash != c.BlockHash {
		return nil, ErrVerdictUnanchored
	}
	if roster != nil {
		if _, ok := roster[ev.Pubkey]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrVerdictNotInRoster, ev.Pubkey)
		}
	}
	return &c, nil
}

// BuildStateCommitmentEvent builds a signed kind-1447 state commitment.  The
// anchor (height + app hash) is mandatory, as on a verdict.
func BuildStateCommitmentEvent(sk *btcec.PrivateKey, height int64, appHashHex string, at int64) (*Event, error) {
	if height <= 0 || appHashHex == "" {
		return nil, ErrCommitmentUnanchored
	}
	c := StateCommitmentContent{Schema: StateCommitSchema, Height: height, AppHash: appHashHex, Time: at}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	tags := [][]string{
		{"height", strconv.FormatInt(height, 10)},
		{"hash", appHashHex},
		{"p", NostrPubkeyHex(sk)},
	}
	return SignEvent(sk, KindStateCommit, string(body), tags, at)
}

// ParseStateCommitment reads a kind-1447 event, verifying signature, schema and
// the mandatory anchor.
func ParseStateCommitment(ev *Event, roster map[string]ValidatorKey) (*StateCommitmentContent, error) {
	if ev == nil || ev.Kind != KindStateCommit {
		return nil, ErrCommitmentKind
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCommitmentBadSignature, err)
	}
	var c StateCommitmentContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		return nil, ErrCommitmentBadSchema
	}
	if c.Schema != StateCommitSchema {
		return nil, fmt.Errorf("%w: %q", ErrCommitmentBadSchema, c.Schema)
	}
	tagHeight, okH := tagValue(ev.Tags, "height")
	tagHash, okHash := tagValue(ev.Tags, "hash")
	if !okH || !okHash || tagHeight == "" || tagHash == "" || c.Height <= 0 || c.AppHash == "" {
		return nil, ErrCommitmentUnanchored
	}
	if tagHeight != strconv.FormatInt(c.Height, 10) || tagHash != c.AppHash {
		return nil, ErrCommitmentUnanchored
	}
	if roster != nil {
		if _, ok := roster[ev.Pubkey]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrVerdictNotInRoster, ev.Pubkey)
		}
	}
	return &c, nil
}

// ClientOutcome is what a relay-only client reconstructs from verdict events
// alone: the resolved outcome for one auction, and the height it was anchored
// to.  latest-per-validator is resolved here (append-only: the newest anchored
// verdict per validator wins for DISPLAY).
type ClientOutcome struct {
	AuctionID string
	Outcome   string
	BidID     string
	Height    int64
	BlockHash string
	Signers   []string
}

// verdictClaim is one validator's newest anchored verdict for an auction.
type verdictClaim struct {
	content *VerdictContent
	at      int64
	id      string
}

// ResolveOutcome folds a stream of relay events into one auction's outcome,
// using ONLY data read from the relay.  It ignores anything that is not a
// well-formed, anchored, roster-signed verdict for that auction (ParseVerdict
// is the gate).  latest-per-validator wins; ties break on created_at then id,
// so the fold is deterministic.
func ResolveOutcome(auctionID string, events []*Event, roster map[string]ValidatorKey) (ClientOutcome, bool) {
	perValidator := map[string]verdictClaim{}
	for _, ev := range events {
		if ev == nil || ev.Kind != KindOutcome {
			continue
		}
		if a, ok := tagValue(ev.Tags, "auction"); !ok || a != auctionID {
			continue
		}
		c, err := ParseVerdict(ev, roster)
		if err != nil {
			continue // unanchored / off-roster / malformed: ignore
		}
		prev, seen := perValidator[ev.Pubkey]
		if !seen || ev.CreatedAt > prev.at || (ev.CreatedAt == prev.at && ev.ID > prev.id) {
			perValidator[ev.Pubkey] = verdictClaim{content: c, at: ev.CreatedAt, id: ev.ID}
		}
	}
	if len(perValidator) == 0 {
		return ClientOutcome{}, false
	}
	signers := make([]string, 0, len(perValidator))
	for pubkey := range perValidator {
		signers = append(signers, pubkey)
	}
	sort.Strings(signers)

	// The quorum view: the outcome the most validators signed, ties broken by
	// the lexicographically smallest outcome for determinism.  A demo client
	// trusts the quorum (see REPLY §2); this is the same security model as the
	// chain's, relocated to the transport.
	counts := map[string]int{}
	for _, pubkey := range signers {
		counts[perValidator[pubkey].content.Outcome]++
	}
	chosen, bestCount := "", -1
	for _, outcome := range sortedKeys(counts, func(k string) string { return k }) {
		if counts[outcome] > bestCount {
			chosen, bestCount = outcome, counts[outcome]
		}
	}
	// The newest anchored verdict among the validators that signed that view.
	var best verdictClaim
	for _, pubkey := range signers {
		cl := perValidator[pubkey]
		if cl.content.Outcome != chosen {
			continue
		}
		if best.content == nil || cl.at > best.at || (cl.at == best.at && cl.id > best.id) {
			best = cl
		}
	}
	out := ClientOutcome{AuctionID: best.content.AuctionID, Outcome: best.content.Outcome, BidID: best.content.BidID,
		Height: best.content.Height, BlockHash: best.content.BlockHash, Signers: signers}
	return out, true
}

// sortedKeys returns the keys of m sorted by key(k); it exists so every fold
// over a map in this file is deterministic.
func sortedKeys[V any](m map[string]V, key func(string) string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}
