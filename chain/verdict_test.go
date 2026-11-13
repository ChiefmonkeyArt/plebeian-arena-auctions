package main

// Unit tests for the verdict-publish contract (spec §9, REPLY §3.2–§3.5).
//
// They pin the three non-negotiable rules and the determinism precondition:
//   - a state commitment carries a valid signature and the mandatory anchor;
//   - an UNANCHORED verdict is refused BY NAME (ErrVerdictUnanchored);
//   - a verdict is published only AFTER its height is committed (ordering);
//   - two honest validators derive the SAME verdict from the same state, with
//     a specific no-bid -> reserve_not_met case;
//   - the verdict kind is regular (never the ephemeral range khatru drops).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// testBlockHash is a deterministic stand-in for CometBFT's block hash.  In
// production the publisher reads it from the node's BlockStore; the tests only
// need a 32-byte lowercase-hex value that is NOT the app hash, so the tests can
// prove the verdict is anchored to the block hash source and not to the app
// hash by accident.
func testBlockHash(height int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("arena-test-block:%d", height)))
	return hex.EncodeToString(sum[:])
}

// blockHashOK is the production-shaped block-hash source for tests.
func blockHashOK(height int64) (string, bool) { return testBlockHash(height), true }

// recordingRelay is an in-memory RelayWriter.  The publisher does not know the
// difference between it and a real nak relay.
type recordingRelay struct {
	mu     sync.Mutex
	events []*Event
}

func (r *recordingRelay) Publish(_ context.Context, ev *Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingRelay) all() []*Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Event(nil), r.events...)
}

func testVerifierKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	sk, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// tagOf returns the first value of the named tag, failing the test if absent.
func tagOf(t *testing.T, ev *Event, name string) string {
	t.Helper()
	v, ok := tagValue(ev.Tags, name)
	if !ok {
		t.Fatalf("event has no %q tag: %v", name, ev.Tags)
	}
	return v
}

// closedLot: an app with one lot that has a winning bid, both committed.  The
// closing block is height 12 (its block time is past EndAt).  Returns the app,
// the winning bid's event id, and the auction's coordinate key.
func closedLot(t *testing.T) (*App, string, string) {
	t.Helper()
	a, m, coord := liveApp(t)
	alice := newBidder(t)
	ev, tx := m.bidTx(t, a, alice, coord, 200, "beef76")
	if res := finalize(t, a, 11, tNow+1, tx); res.TxResults[0].Code != 0 {
		t.Fatalf("bid refused: %s", res.TxResults[0].Log)
	}
	finalize(t, a, 12, tNow+101) // the block that decides the auction (winner)
	au := a.st.Auctions[coord]
	if au == nil || au.Status != "closed" || au.Winner != ev.ID {
		t.Fatalf("lot must be closed with the bid as winner: %+v", au)
	}
	return a, ev.ID, coord
}

// --- rule 2: the anchor is mandatory --------------------------------------

// TestStateCommitmentPublishedWithValidSignatureAndAnchor: a kind-1447 event
// signs under the validator key, verifies, and carries the mandatory
// (height, app_hash) anchor in tags AND content.
func TestStateCommitmentPublishedWithValidSignatureAndAnchor(t *testing.T) {
	sk := testVerifierKey(t)
	ev, err := BuildStateCommitmentEvent(sk, 12345, strings.Repeat("ab", 32), tNow)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != KindStateCommit {
		t.Fatalf("state commitment kind = %d, want %d", ev.Kind, KindStateCommit)
	}
	if err := ev.Verify(); err != nil {
		t.Fatalf("state commitment must verify: %v", err)
	}
	if ev.Pubkey != NostrPubkeyHex(sk) {
		t.Fatalf("signed by %s, want the validator key %s", ev.Pubkey, NostrPubkeyHex(sk))
	}
	if got := tagOf(t, ev, "height"); got != "12345" {
		t.Fatalf("height tag = %q", got)
	}
	if got := tagOf(t, ev, "hash"); got != strings.Repeat("ab", 32) {
		t.Fatalf("hash tag = %q", got)
	}
	if got := tagOf(t, ev, "p"); got != NostrPubkeyHex(sk) {
		t.Fatalf("p tag = %q, want the validator pubkey", got)
	}
	var c StateCommitmentContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != StateCommitSchema || c.Height != 12345 || c.AppHash != strings.Repeat("ab", 32) {
		t.Fatalf("content = %+v", c)
	}
	// the anchor is mandatory: a zero height or empty hash cannot be built.
	if _, err := BuildStateCommitmentEvent(sk, 0, strings.Repeat("ab", 32), tNow); err != ErrCommitmentUnanchored {
		t.Fatalf("zero height must refuse as %v, got %v", ErrCommitmentUnanchored, err)
	}
}

// TestUnanchoredVerdictIsRefusedByName: a client MUST ignore a verdict with no
// (height, hash) anchor.  ParseVerdict names the refusal so the rule is
// assertable, not merely documented.
func TestUnanchoredVerdictIsRefusedByName(t *testing.T) {
	sk := testVerifierKey(t)
	good, err := BuildVerdictEvent(sk, Verdict{AuctionID: "a", BidID: "b", Outcome: OutcomeWinner}, 7, testBlockHash(7), nil, tNow)
	if err != nil {
		t.Fatal(err)
	}

	// drop the height tag but keep the content: unanchored.
	noHeight := resignCopy(t, sk, good, dropTag(good.Tags, "height"))
	if _, err := ParseVerdict(noHeight, nil); err != ErrVerdictUnanchored {
		t.Fatalf("missing height tag: want %v, got %v", ErrVerdictUnanchored, err)
	}
	// drop the hash tag.
	noHash := resignCopy(t, sk, good, dropTag(good.Tags, "hash"))
	if _, err := ParseVerdict(noHash, nil); err != ErrVerdictUnanchored {
		t.Fatalf("missing hash tag: want %v, got %v", ErrVerdictUnanchored, err)
	}
	// a tag that disagrees with the content is also unanchored.
	mismatch := resignCopy(t, sk, good, replaceTag(good.Tags, "height", "999"))
	if _, err := ParseVerdict(mismatch, nil); err != ErrVerdictUnanchored {
		t.Fatalf("tag/content disagreement: want %v, got %v", ErrVerdictUnanchored, err)
	}
	// the intact event parses.
	if _, err := ParseVerdict(good, nil); err != nil {
		t.Fatalf("the anchored verdict must parse: %v", err)
	}
}

// TestVerdictOffRosterIsRefused: a signature valid for a key NOT on the roster
// is refused, so a forged verdict is distinguishable from a real one.
func TestVerdictOffRosterIsRefused(t *testing.T) {
	sk := testVerifierKey(t)
	stranger := testVerifierKey(t)
	roster := map[string]ValidatorKey{NostrPubkeyHex(sk): {Pubkey: NostrPubkeyHex(sk), Name: "v1", Index: 1}}
	ev, err := BuildVerdictEvent(stranger, Verdict{AuctionID: "a", Outcome: OutcomeWinner}, 7, testBlockHash(7), nil, tNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVerdict(ev, roster); err == nil || !strings.Contains(err.Error(), ErrVerdictNotInRoster.Error()) {
		t.Fatalf("off-roster verdict must refuse as %v, got %v", ErrVerdictNotInRoster, err)
	}
}

// --- rule 3: append-only, regular kinds ------------------------------------

// TestVerdictKindIsRegularAndAppendOnly: 1445 is in NIP-01's regular range, so
// a relay stores every verdict and replaces nothing.  There is no replaceable
// mechanism (e.g. no 30440 semantics) anywhere in the event shape.
func TestVerdictKindIsRegularAndAppendOnly(t *testing.T) {
	if KindOutcome != 1445 {
		t.Fatalf("outcome kind = %d, want 1445", KindOutcome)
	}
	if !regularKind(KindOutcome) {
		t.Fatalf("kind %d is not in the regular range 1000..9999; khatru would drop it", KindOutcome)
	}
	if KindOutcome >= 20000 && KindOutcome <= 29999 {
		t.Fatal("the verdict kind must never be in the ephemeral range")
	}
	sk := testVerifierKey(t)
	// a lifecycle change is a NEW event, not a replacement: two events for the
	// same auction from the same validator coexist, and both verify.
	e1, _ := BuildVerdictEvent(sk, Verdict{AuctionID: "a", Outcome: OutcomeWinner}, 7, testBlockHash(7), nil, tNow)
	e2, _ := BuildVerdictEvent(sk, Verdict{AuctionID: "a", Outcome: OutcomeWinner}, 9, testBlockHash(9), nil, tNow+5)
	if e1.Kind != e2.Kind || e1.ID == e2.ID {
		t.Fatal("distinct anchored verdicts must be distinct events")
	}
}

// --- the ordering rule ----------------------------------------------------

// TestVerdictPublishedOnlyAfterCommit asserts the ORDERING, not just the
// outcome: nothing is published for an uncommitted view, no verdict exists for
// an auction until the block that closes it is committed, and the verdict's
// anchor height equals that committed height.
func TestVerdictPublishedOnlyAfterCommit(t *testing.T) {
	a, m, coord := liveApp(t)
	alice := newBidder(t)
	_, tx := m.bidTx(t, a, alice, coord, 200, "beef76")

	rec := &recordingRelay{}
	sk := testVerifierKey(t)
	pub, err := NewPublisher(PublisherConfig{Key: sk, Relay: rec, App: a, Every: 1,
		BlockHash: blockHashOK, Now: func() int64 { return tNow }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// (1) nothing committed yet: Step publishes NOTHING -- never for a pending
	// view.
	pub.Step(ctx)
	if len(rec.all()) != 0 || len(pub.Records()) != 0 {
		t.Fatalf("nothing may be published before the first commit: %d events, %v", len(rec.all()), pub.Records())
	}

	// (2) commit the bid at height 11; the lot is still open (tNow+1 < EndAt).
	if res := finalize(t, a, 11, tNow+1, tx); res.TxResults[0].Code != 0 {
		t.Fatalf("bid refused: %s", res.TxResults[0].Log)
	}
	pub.Step(ctx)
	for _, r := range pub.Records() {
		if r.Op == "verdict" && r.AuctionID == coord {
			t.Fatal("a verdict must not exist while the auction is still open at the committed height")
		}
	}

	// (3) the block that closes the lot commits at height 12.
	finalize(t, a, 12, tNow+101)
	pub.Step(ctx)

	var verdictRec *PublishRecord
	for i, r := range pub.Records() {
		if r.Op == "verdict" && r.AuctionID == coord {
			verdictRec = &pub.Records()[i]
		}
	}
	if verdictRec == nil {
		t.Fatal("a verdict must be published once the closing block is committed")
	}
	if verdictRec.CommittedHeight != 12 {
		t.Fatalf("verdict CommittedHeight = %d, want the committed height 12", verdictRec.CommittedHeight)
	}
	if verdictRec.Height != 12 {
		t.Fatalf("verdict anchor height = %d, want 12", verdictRec.Height)
	}
	// the anchor is the BLOCK hash, not the app hash.
	if verdictRec.Hash != testBlockHash(12) {
		t.Fatalf("verdict anchor hash = %s, want the committed block hash %s", verdictRec.Hash, testBlockHash(12))
	}
	if !strings.Contains(verdictRec.Outcome, OutcomeWinner) {
		t.Fatalf("verdict outcome = %q, want winner", verdictRec.Outcome)
	}
}

// TestVerdictRefusedWhenCommittedBlockHashUnavailable: if the committed block
// hash at the anchor height cannot be read, the verdict is REFUSED by name and
// never published -- an unanchorable claim is not a claim.
func TestVerdictRefusedWhenCommittedBlockHashUnavailable(t *testing.T) {
	a, _, coord := closedLot(t)
	rec := &recordingRelay{}
	pub, err := NewPublisher(PublisherConfig{Key: testVerifierKey(t), Relay: rec, App: a, Every: 1,
		BlockHash: func(int64) (string, bool) { return "", false }, Now: func() int64 { return tNow }})
	if err != nil {
		t.Fatal(err)
	}
	pub.Step(context.Background())
	for _, ev := range rec.all() {
		if ev.Kind == KindOutcome {
			t.Fatal("no verdict may be published when the committed block hash is unknown")
		}
	}
	found := false
	for _, r := range pub.Records() {
		if r.Op == "refused" && r.AuctionID == coord && r.Reason == "committed_block_hash_unknown" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a refusal named committed_block_hash_unknown, got %v", pub.Records())
	}
}

// --- determinism: the precondition for publishing verdicts honestly --------

// TestDeterminismTwoValidatorsSameVerdictFromSameState: two honest validators
// given the SAME committed state derive the SAME verdict.  This is the property
// that makes a quorum of verdicts meaningful, and it is the first thing a
// reviewer should ask for.
func TestDeterminismTwoValidatorsSameVerdictFromSameState(t *testing.T) {
	origin, _, coord := closedLot(t)
	_, _, _, raw := origin.committedSnapshot()
	if len(raw) == 0 {
		t.Fatal("no committed state")
	}

	// Two independent validators, each rebuilding its state from the same
	// committed bytes.
	derive := func() Verdict {
		s := newState()
		if err := json.Unmarshal(raw, s); err != nil {
			t.Fatal(err)
		}
		v, ok := DeriveVerdict(s, coord)
		if !ok {
			t.Fatal("a closed auction must yield a verdict")
		}
		return v
	}
	v1, v2 := derive(), derive()
	if v1 != v2 {
		t.Fatalf("two validators derived different verdicts from the same state: %+v vs %+v", v1, v2)
	}
	if v1.Outcome != OutcomeWinner {
		t.Fatalf("outcome = %q, want winner", v1.Outcome)
	}
	if v1.BidID == "" {
		t.Fatal("a winner verdict must carry the winning bid id")
	}
}

// TestDeterminismNoBidReserveNotMet: a lot that closes with no bid yields
// reserve_not_met, identically on every validator, and carries no bid id.
func TestDeterminismNoBidReserveNotMet(t *testing.T) {
	a, _, coord := liveApp(t)
	finalize(t, a, 11, tNow+101) // closes with no bid
	_, _, _, raw := a.committedSnapshot()

	derive := func() Verdict {
		s := newState()
		if err := json.Unmarshal(raw, s); err != nil {
			t.Fatal(err)
		}
		v, ok := DeriveVerdict(s, coord)
		if !ok {
			t.Fatal("a closed auction must yield a verdict")
		}
		return v
	}
	v1, v2 := derive(), derive()
	if v1 != v2 || v1.Outcome != OutcomeReserveNotMet || v1.BidID != "" {
		t.Fatalf("no-bid determinism: %+v vs %+v (want equal reserve_not_met, empty bid)", v1, v2)
	}
	// and the wire form omits the bid tag for a no-bid auction.
	sk := testVerifierKey(t)
	ev, err := BuildVerdictEvent(sk, v1, 11, testBlockHash(11), nil, tNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tagValue(ev.Tags, "bid"); ok {
		t.Fatal("a no-bid verdict must omit the bid tag")
	}
	c, err := ParseVerdict(ev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.BidID != "" || c.PayoutTokenSHA256 != nil {
		t.Fatalf("no-bid content: bid_id=%q payout=%v (want empty and null)", c.BidID, c.PayoutTokenSHA256)
	}
}

// --- relay-only reconstruction -------------------------------------------

// TestResolveOutcomeLatestPerValidator: a client folds relay events; the newest
// anchored verdict per validator wins for display, and an unanchored or invalid
// verdict is ignored entirely.
func TestResolveOutcomeLatestPerValidator(t *testing.T) {
	sk := testVerifierKey(t)
	roster := map[string]ValidatorKey{NostrPubkeyHex(sk): {Pubkey: NostrPubkeyHex(sk), Index: 1}}
	mk := func(height int64, at int64) *Event {
		ev, err := BuildVerdictEvent(sk, Verdict{AuctionID: "auc", BidID: "b1", Outcome: OutcomeWinner}, height, testBlockHash(height), nil, at)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	older, newer := mk(7, tNow), mk(9, tNow+5)
	// an unanchored event from the same validator must be ignored.
	stripped := resignCopy(t, sk, newer, dropTag(newer.Tags, "hash"))

	out, ok := ResolveOutcome("auc", []*Event{older, stripped, newer}, roster)
	if !ok {
		t.Fatal("must resolve")
	}
	if out.Height != 9 || out.BlockHash != testBlockHash(9) {
		t.Fatalf("latest-per-validator wrong: %+v", out)
	}
	if len(out.Signers) != 1 || out.Signers[0] != NostrPubkeyHex(sk) {
		t.Fatalf("signers = %v", out.Signers)
	}
}

// --- helpers --------------------------------------------------------------

func dropTag(tags [][]string, name string) [][]string {
	out := make([][]string, 0, len(tags))
	for _, t := range tags {
		if len(t) >= 1 && t[0] == name {
			continue
		}
		out = append(out, t)
	}
	return out
}

func replaceTag(tags [][]string, name, value string) [][]string {
	out := make([][]string, 0, len(tags))
	for _, t := range tags {
		if len(t) >= 2 && t[0] == name {
			out = append(out, []string{name, value})
			continue
		}
		out = append(out, t)
	}
	return out
}

// resignCopy re-signs an existing event with new tags, keeping its kind and
// content, so a test can build a validly signed but altered event.
func resignCopy(t *testing.T, sk *btcec.PrivateKey, ev *Event, tags [][]string) *Event {
	t.Helper()
	out := &Event{Pubkey: ev.Pubkey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: tags, Content: ev.Content}
	h := sha256.Sum256([]byte(out.Serialize()))
	out.ID = hex.EncodeToString(h[:])
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out.Sig = hex.EncodeToString(sig.Serialize())
	return out
}
