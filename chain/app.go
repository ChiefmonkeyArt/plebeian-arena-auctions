package main

// The auction state machine. Every validator runs this identically; the
// AppHash (sha256 of the canonical JSON state) proves they agree.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

type Params struct {
	MintURL        string            `json:"mintUrl"`
	KeysetID       string            `json:"keysetId"`
	Keys           map[string]string `json:"keys"`
	GroupKey       string            `json:"groupKey"`    // FROST 3-of-4 escrow key (compressed hex); no single validator holds it
	FrostPublic    json.RawMessage   `json:"frostPublic"` // FROST public key package: group key + each validator's verifying share
	ValidatorNames []string          `json:"validatorNames"`
	MinWindowSec   int64             `json:"minWindowSec"` // anti-snipe window bounds (ADR 0009)
	MaxWindowSec   int64             `json:"maxWindowSec"`
	// SettlementSafetySec is how long after the end a bid itself establishes
	// the settlement must land, before the bidder's unilateral refund branch
	// opens (spec §2.1). It replaces LockMarginSec as the lock driver.
	SettlementSafetySec int64 `json:"settlementSafetySec"`
	// BidToConsensusLatencySec covers the gap between the bidder's clock and
	// the block that admits the bid (spec §2.1). It replaces lockGraceSec.
	BidToConsensusLatencySec int64 `json:"bidToConsensusLatencySec"`
	// LockMarginSec is retired as a lock driver: settlement_safety is the lock
	// rule now (spec §10). Kept for the CLI flag's meaning in existing config.
	LockMarginSec  int64 `json:"lockMarginSec,omitempty"`
	MinDurationSec int64 `json:"minDurationSec"`
	MaxDurationSec int64 `json:"maxDurationSec"`
	MaxProofs      int   `json:"maxProofs"`
	Threshold      int   `json:"threshold"`
}

type Auction struct {
	ID           string   `json:"id"` // coordinate a = 1440:<seller>:<d>; the auction's stable identity
	Seller       string   `json:"seller"`
	SellerWallet string   `json:"sellerWallet"`
	SellerName   string   `json:"sellerName"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Image        string   `json:"image"`
	Category     string   `json:"category"`
	StartPrice   int64    `json:"startPrice"`
	MinIncrement int64    `json:"minIncrement"`
	CreatedAt    int64    `json:"createdAt"`
	CreatedH     int64    `json:"createdHeight"`
	EndAt        int64    `json:"endAt"`
	Mode         string   `json:"mode"`      // fixed | antisnipe (ADR 0009)
	WindowSec    int64    `json:"windowSec"` // antisnipe: a bid with less than this left resets the clock to it
	Status       string   `json:"status"` // open | closed
	HighBid      string   `json:"highBid"`
	HighAmount   int64    `json:"highAmount"`
	Bids         []string `json:"bids"`
	Extensions   int      `json:"extensions"`
	Winner       string   `json:"winner"`          // bid id
	Expired      bool     `json:"expired,omitempty"` // antisnipe ran so long the leading escrow neared its locktime: no sale
	Voids        []string `json:"voids,omitempty"` // late bids, refundable at once (ADR 0007)
	ClosedAt     int64    `json:"closedAt"`
	ClosedH      int64    `json:"closedHeight"`

	// Root pinning and supersession (owner decision 2026-11-12, spec §8). The
	// auction's identity is (seller, d); the FIRST 1440 event for it is the
	// root and its id is auction_root_event_id. Later 1440 events are
	// supersessions gated by the immutable allow-list, and this struct always
	// holds the latest ACCEPTED version — the one resolution a regular kind
	// does not get from the relay.
	D                string `json:"d"`                // the d tag = auction_id
	RootID           string `json:"rootId"`           // auction_root_event_id
	VersionID        string `json:"versionId"`        // event id of the canonical (latest accepted) version
	VersionCreatedAt int64  `json:"versionCreatedAt"` // created_at of that version; gates supersession order
	DurationSec      int64  `json:"durationSec"`      // frozen duration; EndAt is its materialisation
}

type Bid struct {
	ID       string  `json:"id"`
	Auction  string  `json:"auction"`
	Bidder   string  `json:"bidder"`
	Name     string  `json:"name"`
	Wallet   string  `json:"wallet"`
	Amount   int64   `json:"amount"`
	Proofs   []Proof `json:"proofs"`
	Locktime int64   `json:"locktime"`
	Height   int64   `json:"height"`
	Time     int64   `json:"time"`
	Status   string  `json:"status"` // leading | outbid | won | lost | void
	Extended bool    `json:"extended"`
	// Push settlement (ADR 0009): the validators moved the escrow themselves.
	Settled string  `json:"settled,omitempty"` // refund | payout, once the new ecash is minted
	Out     []Proof `json:"out,omitempty"`     // that ecash, P2PK-locked to the recipient
	Relocks int     `json:"relocks,omitempty"` // antisnipe: escrow re-locked with a later locktime
}

type Rejection struct {
	Height int64  `json:"height"`
	Time   int64  `json:"time"`
	Kind   int    `json:"kind"`
	Pubkey string `json:"pubkey"`
	Event  string `json:"event"`
	Reason string `json:"reason"`
}

// Height and Time are kept in memory and published, but hashed as zero
// (canonical): an empty block then leaves the app hash unchanged, so
// CometBFT does not need a block to prove it (ADR 0003 §1). They must stay
// the first two fields: publish() rewrites that prefix.
type State struct {
	Height     int64               `json:"height"`
	Time       int64               `json:"time"`
	Params     Params              `json:"params"`
	Auctions   map[string]*Auction `json:"auctions"`
	Order      []string            `json:"order"`
	Bids       map[string]*Bid     `json:"bids"`
	UsedY      map[string]string   `json:"usedY"`
	Rejections []Rejection         `json:"rejections"`
	TxCount    int64               `json:"txCount"`
}

func newState() *State {
	return &State{Auctions: map[string]*Auction{}, Bids: map[string]*Bid{}, UsedY: map[string]string{}, Rejections: []Rejection{}, Order: []string{}}
}

// canonical is the hashed encoding: the state with Height and Time zeroed.
// Go sorts map keys, so it is deterministic.
func (s *State) canonical() []byte {
	c := *s
	c.Height, c.Time = 0, 0
	b, _ := json.Marshal(&c)
	return b
}

func (s *State) hash() []byte {
	h := sha256.Sum256(s.canonical())
	return h[:]
}

const canonPrefix = `{"height":0,"time":0,`

// publish turns canonical bytes into the published state by filling in the
// height and time.
func publish(canon []byte, h, t int64) []byte {
	if !bytes.HasPrefix(canon, []byte(canonPrefix)) {
		return canon
	}
	out := make([]byte, 0, len(canon)+24)
	out = append(out, `{"height":`...)
	out = strconv.AppendInt(out, h, 10)
	out = append(out, `,"time":`...)
	out = strconv.AppendInt(out, t, 10)
	out = append(out, ',')
	return append(out, canon[len(canonPrefix):]...)
}

type App struct {
	abci.BaseApplication
	mu         sync.RWMutex
	st         *State
	committed  []byte  // canonical JSON of the last committed state (Height, Time zero)
	committedH int64   // height of that snapshot
	committedT int64   // its block time
	pending    []byte  // snapshot made in FinalizeBlock, published at Commit
	ledger     *ledger // per-block tx archive (ADR 0003 §4); nil in tests
	retain     int64   // keep this many blocks below the newest snapshot; 0 keeps all
	pendLines  []ledgerLine
	appHash    []byte
	// hash of committed; Info reports it with committedH (ADR 0003 §2)
	committedHash []byte
	snap          *snapshotter // nil: no snapshots (tests)
	commitCh      chan struct{} // closed and replaced at every Commit (for /height?after=)
}

// waitCommit blocks until the committed height is above after, the context
// ends or max passes; it returns the committed height then.
func (a *App) waitCommit(ctx context.Context, after int64, max time.Duration) int64 {
	t := time.NewTimer(max)
	defer t.Stop()
	for {
		a.mu.Lock()
		h := a.committedH
		if a.commitCh == nil {
			a.commitCh = make(chan struct{})
		}
		ch := a.commitCh
		a.mu.Unlock()
		if h > after {
			return h
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return h
		case <-t.C:
			return h
		}
	}
}

func NewApp() *App { return &App{st: newState()} }

// Snapshot is the published committed state (with its height and time).
func (a *App) Snapshot() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return publish(a.committed, a.committedH, a.committedT)
}

func (a *App) Read(f func(s *State)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	f(a.st)
}

func (a *App) Info(context.Context, *abci.InfoRequest) (*abci.InfoResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// The committed height and hash: 0 on a fresh start (CometBFT replays
	// from genesis), or a restored snapshot's (it replays only what follows).
	return &abci.InfoResponse{Data: "arena-auctions", Version: "0.5.2", AppVersion: 1,
		LastBlockHeight: a.committedH, LastBlockAppHash: a.committedHash}, nil
}

func (a *App) InitChain(_ context.Context, req *abci.InitChainRequest) (*abci.InitChainResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st = newState()
	if err := json.Unmarshal(req.AppStateBytes, &a.st.Params); err != nil {
		return nil, fmt.Errorf("bad app_state: %w", err)
	}
	a.committed = a.st.canonical()
	return &abci.InitChainResponse{}, nil
}

type CreateContent struct {
	Title        string `json:"title"`
	Description  string `json:"description"`
	Image        string `json:"image"`
	Category     string `json:"category"`
	StartPrice   int64  `json:"startPrice"`
	MinIncrement int64  `json:"minIncrement"`
	DurationSec  int64  `json:"durationSec"`
	Mode         string `json:"mode"`
	WindowSec    int64  `json:"windowSec"`
	SellerWallet string `json:"sellerWallet"`
	Name         string `json:"name"`
}

type BidContent struct {
	Auction string  `json:"auction"`
	Amount  int64   `json:"amount"`
	Wallet  string  `json:"wallet"`
	Name    string  `json:"name"`
	Proofs  []Proof `json:"proofs"`
}

// closeTx is the validators' own "close what is due" transaction (ADR 0003
// §1): close:<auction id>:<endAt>:<unix seconds sent>. It is not a Nostr
// event, so the gateway's /api/tx (JSON only) cannot submit one.
const closePrefix = "close:"

type closeTx struct {
	Auction string
	EndAt   int64
	Sent    int64
}

func parseClose(tx []byte) (*closeTx, bool) {
	if !bytes.HasPrefix(tx, []byte(closePrefix)) || len(tx) > 128 {
		return nil, false
	}
	parts := strings.Split(string(tx[len(closePrefix):]), ":")
	if len(parts) != 3 || !lowerHex(parts[0], 64) {
		return nil, false
	}
	end, e1 := strconv.ParseInt(parts[1], 10, 64)
	sent, e2 := strconv.ParseInt(parts[2], 10, 64)
	if e1 != nil || e2 != nil {
		return nil, false
	}
	return &closeTx{parts[0], end, sent}, true
}

func makeClose(id string, endAt, now int64) []byte {
	return []byte(fmt.Sprintf("%s%s:%d:%d", closePrefix, id, endAt, now))
}

// lateBid is a bid that is well formed and fully locked to the escrow key
// but lost a race (too low, already leading, lot ended). The chain records
// it as void so the validators can refund it at once (ADR 0007).
type lateBid struct{ reason string }

func (e *lateBid) Error() string { return e.reason }

// maxVoids caps the late bids one auction keeps; past it they are refused
// (the bidder reclaims after locktime, as before).
const maxVoids = 256

func decodeTx(tx []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(tx, &ev); err != nil {
		return nil, errors.New("tx is not a Nostr event")
	}
	if ev.Kind != KindCreate && ev.Kind != KindBid {
		return nil, fmt.Errorf("unsupported kind %d", ev.Kind)
	}
	if err := ev.Verify(); err != nil {
		return nil, err
	}
	return &ev, nil
}

// safeImage allows an empty image, a same-site path or an https URL made of
// URL-safe characters only, so it can never break out of an HTML attribute
// (internal audit A5).
func safeImage(s string) bool {
	if s == "" {
		return true
	}
	if !(strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//")) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~:/?#[]@!$&()*+,;=%", c) >= 0) {
			return false
		}
	}
	return true
}

func isPubHex(s string) bool {
	if len(s) != 66 || !(strings.HasPrefix(s, "02") || strings.HasPrefix(s, "03")) {
		return false
	}
	_, err := parsePub(s)
	return err == nil
}

// validD: the d tag (auction_id). NIP-01 addressable/parametrised-replaceable
// charset — [A-Za-z0-9_-], 1..64 chars. An auction whose d fails this is not
// an auction: the coordinate a = 1440:<seller>:<d> would not be parseable.
func validD(d string) bool {
	if len(d) < 1 || len(d) > 64 {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// coordOf is OUR coordinate convention for a regular kind: a =
// 1440:<seller_pubkey>:<d>. This is not NIP-01 addressability — 1440 is
// regular, so the relay replaces nothing and the latest accepted version must
// be resolved explicitly (spec §7, §8). The coordinate is the auction's stable
// identity: bids and the auction map are keyed by it, not by a mutable version
// event id.
func coordOf(seller, d string) string {
	return strconv.Itoa(KindCreate) + ":" + seller + ":" + d
}

// tagValue returns the first value of the named tag.
func tagValue(tags [][]string, name string) (string, bool) {
	for _, t := range tags {
		if len(t) >= 2 && t[0] == name {
			return t[1], true
		}
	}
	return "", false
}

// immutableFields is the allow-list's immutable half, remapped onto his current
// create payload (owner decision 2026-11-12, spec §8). The principle is
// display is mutable; money, time and cryptography are not:
//
//   - StartPrice        money  — the absolute floor every bid is checked against
//   - MinIncrement      money  — the step rule
//   - Mode              time   — fixed | antisnipe decides whether EndAt can move
//   - WindowSec         time   — the anti-snipe reset amount; EndAt derives from it
//   - DurationSec       time   — when a fixed lot closes
//   - SellerWallet      crypto — where settlement pays; the lock's refund/data key
//
// The d value and the seller are immutable structurally: they are the
// coordinate (seller, d), so changing either is a different auction, never an
// edit. Title, Description and Image are display and stay editable. Category
// and SellerName are judgement calls, both mutable (see the report): a
// category is metadata, and a display name is a display field with no bearing
// on money, time or the lock.
func immutableChanged(cur *Auction, c *CreateContent, mode string) string {
	switch {
	case c.StartPrice != cur.StartPrice:
		return "StartPrice"
	case c.MinIncrement != cur.MinIncrement:
		return "MinIncrement"
	case mode != cur.Mode:
		return "Mode"
	case c.WindowSec != cur.WindowSec:
		return "WindowSec"
	case c.DurationSec != cur.DurationSec:
		return "DurationSec"
	case strings.ToLower(c.SellerWallet) != cur.SellerWallet:
		return "SellerWallet"
	}
	return ""
}

// canonicalAuction resolves (seller, d) to the canonical auction: the latest
// 1440 event that passed the immutable check. Because 1440 is a regular kind,
// no relay performed this replacement for us, so the persisted state IS the
// resolution — a root that never existed, or an update that failed the check,
// simply never overwrote it, and the entity holds the last accepted version.
func (s *State) canonicalAuction(seller, d string) *Auction {
	return s.Auctions[coordOf(seller, d)]
}

// byRoot finds the auction whose root event id is rootID — or, as a
// convenience for callers that name the auction by its coordinate, the auction
// stored under that coordinate key. The validators' own close tx names an
// auction by its stable root id, not by a mutable version.
func (s *State) byRoot(rootID string) *Auction {
	if au := s.Auctions[rootID]; au != nil {
		return au
	}
	for _, au := range s.Auctions {
		if au.RootID == rootID {
			return au
		}
	}
	return nil
}

// applyCreate validates and (if apply) executes a 1440 create event at block
// time now.
//
// The auction's identity is (seller, d), keyed by the coordinate
// a = 1440:<seller>:<d>. The FIRST event for a coordinate is the ROOT; its
// event id is auction_root_event_id. A later event for the same coordinate is a
// SUPERSESSION: it must carry e = <auction_root_event_id> and may change only
// the allow-listed display fields. A change to any immutable field (money,
// time, cryptography) is refused with "immutable_field_changed <field>" and
// ignored — the state keeps the last accepted version.
func (s *State) applyCreate(ev *Event, now, height int64, apply bool) error {
	d, ok := tagValue(ev.Tags, "d")
	if !ok || !validD(d) {
		return errors.New("create needs a valid d tag")
	}
	coord := coordOf(ev.Pubkey, d)
	root, hasRoot := tagValue(ev.Tags, "e")

	var c CreateContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		return errors.New("bad create content")
	}
	p := s.Params
	switch {
	case len(strings.TrimSpace(c.Title)) == 0 || len(c.Title) > 120:
		return errors.New("title required (max 120 chars)")
	case len(c.Description) > 2000 || len(c.Image) > 500 || len(c.Category) > 40 || len(c.Name) > 40:
		return errors.New("field too long")
	case !safeImage(c.Image):
		return errors.New("image must be a same-site path or an https URL")
	case c.StartPrice < 1 || c.StartPrice > 10_000_000:
		return errors.New("start price out of range")
	case c.MinIncrement < 1 || c.MinIncrement > 1_000_000:
		return errors.New("increment out of range")
	case c.DurationSec < p.MinDurationSec || c.DurationSec > p.MaxDurationSec:
		return fmt.Errorf("duration must be %d-%d seconds", p.MinDurationSec, p.MaxDurationSec)
	case !isPubHex(strings.ToLower(c.SellerWallet)):
		return errors.New("seller wallet pubkey invalid")
	case c.Mode != "" && c.Mode != "fixed" && c.Mode != "antisnipe":
		return errors.New("mode must be fixed or antisnipe")
	case c.Mode == "antisnipe" && (c.WindowSec < p.MinWindowSec || c.WindowSec > p.MaxWindowSec):
		return fmt.Errorf("anti-snipe window must be %d-%d seconds", p.MinWindowSec, p.MaxWindowSec)
	case c.Mode != "antisnipe" && c.WindowSec != 0:
		return errors.New("a fixed-time lot has no anti-snipe window")
	}
	mode := c.Mode
	if mode == "" {
		mode = "fixed"
	}

	cur := s.Auctions[coord]
	if cur == nil {
		// The root: the first 1440 for this (seller, d). It must not claim a
		// root it cannot know about — only a supersession carries e.
		if hasRoot {
			return errors.New("first create for this (seller, d) must not carry an e tag")
		}
		if !apply {
			return nil
		}
		end := now + c.DurationSec
		s.Auctions[coord] = &Auction{
			ID: coord, D: d, RootID: ev.ID, VersionID: ev.ID, VersionCreatedAt: ev.CreatedAt, DurationSec: c.DurationSec,
			Seller: ev.Pubkey, SellerWallet: strings.ToLower(c.SellerWallet), SellerName: c.Name,
			Title: c.Title, Description: c.Description, Image: c.Image, Category: c.Category,
			StartPrice: c.StartPrice, MinIncrement: c.MinIncrement, CreatedAt: now, CreatedH: height,
			EndAt: end, Mode: mode, WindowSec: c.WindowSec, Status: "open", Bids: []string{},
		}
		s.Order = append(s.Order, coord)
		return nil
	}

	// A supersession. It must point at the ROOT — not at whatever version it
	// last saw. That is what keeps bids (which also point at the root)
	// attached across an edit.
	if !hasRoot || root != cur.RootID {
		return errors.New("update must reference the auction root (e = auction_root_event_id)")
	}
	// Immutable check against the canonical (latest accepted) version. A
	// refused supersession is ignored, never applied: the state below stays
	// untouched, so the canonical auction remains the last accepted one.
	if f := immutableChanged(cur, &c, mode); f != "" {
		return fmt.Errorf("immutable_field_changed %s", f)
	}
	// Latest by created_at that passes the check: an edit no newer than the
	// canonical version does not win, and a replay is ignored.
	if ev.CreatedAt <= cur.VersionCreatedAt {
		return errors.New("stale update ignored")
	}
	if !apply {
		return nil
	}
	// Only display fields change; money, time and cryptography stay put, and
	// EndAt is never recomputed.
	cur.Title, cur.Description, cur.Image, cur.Category, cur.SellerName = c.Title, c.Description, c.Image, c.Category, c.Name
	cur.VersionID, cur.VersionCreatedAt, cur.CreatedH = ev.ID, ev.CreatedAt, height
	return nil
}

// lockGraceSec: an anti-snipe bid's locktime is checked against the block
// time, which the bidder can only estimate, so it may fall this short.
const lockGraceSec = 30

// minLocktime is the earliest refund locktime a bid on au may carry at block
// time now. Fixed lots never move their end, so the lock covers end+margin.
// Anti-snipe lots have no end in advance: the lock covers margin from now and
// the validators re-lock a leading escrow before it gets close (ADR 0009).
func (s *State) minLocktime(au *Auction, now int64) int64 {
	if au.Mode == "antisnipe" {
		return now + s.Params.LockMarginSec - lockGraceSec
	}
	return au.EndAt + s.Params.LockMarginSec
}

// checkLock enforces the 3-of-4 validator lock with the bidder's refund path.
func (s *State) checkLock(proofs []Proof, wallet string, minLock int64) (int64, error) {
	p := s.Params
	var firstTags string
	var lt int64
	for i, pr := range proofs {
		l, err := parseP2PK(pr.Secret)
		if err != nil {
			return 0, err
		}
		if l.Data != strings.ToLower(p.GroupKey) || len(l.Pubkeys) != 0 || l.NSigs != 1 {
			return 0, errors.New("proofs not locked to the validators' FROST group key")
		}
		if l.SigFlag != "SIG_ALL" {
			return 0, errors.New("lock must use SIG_ALL")
		}
		if len(l.Refund) != 1 || l.Refund[0] != wallet {
			return 0, errors.New("refund path must be the bidder's wallet key only")
		}
		if l.Locktime < minLock {
			return 0, errors.New("locktime too early: validators need time to settle")
		}
		if i == 0 {
			firstTags = l.TagsJSON
			lt = l.Locktime
		} else if l.TagsJSON != firstTags {
			return 0, errors.New("all proofs must share one lock")
		}
	}
	return lt, nil
}

func lower(a []string) []string {
	out := make([]string, len(a))
	for i, v := range a {
		out[i] = strings.ToLower(v)
	}
	return out
}

func (s *State) applyBid(ev *Event, now, height int64, apply, timed bool) error {
	if _, ok := s.Bids[ev.ID]; ok {
		return errors.New("bid already recorded")
	}
	var b BidContent
	if err := json.Unmarshal([]byte(ev.Content), &b); err != nil {
		return errors.New("bad bid content")
	}
	au, ok := s.Auctions[b.Auction]
	if !ok {
		return errors.New("unknown auction")
	}
	// 0. The bid binds to the auction ROOT, not to the latest version: it must
	// carry e = <auction_root_event_id>. This check lives HERE, in the
	// deterministic transition, not only in CheckTx: admission is a mempool
	// filter and a Byzantine proposer can include a transaction that never
	// passed it (spec §8).
	if e, ok := tagValue(ev.Tags, "e"); !ok || e != au.RootID {
		return errors.New("bid must reference the auction root (auction_root_event_id)")
	}
	// The coordinate convention a = 1440:<seller>:<d>, if present, must match.
	if a, ok := tagValue(ev.Tags, "a"); ok && a != au.ID {
		return errors.New("bid's a coordinate does not match the auction")
	}
	// 1. Is it a real, fully locked escrow? If not, refuse it outright.
	wallet := strings.ToLower(b.Wallet)
	if !isPubHex(wallet) {
		return errors.New("wallet pubkey invalid")
	}
	if len(b.Proofs) == 0 || len(b.Proofs) > s.Params.MaxProofs {
		return errors.New("bad proof count")
	}
	var sum int64
	seen := map[string]bool{}
	ys := make([]string, 0, len(b.Proofs))
	for _, pr := range b.Proofs {
		if pr.ID != s.Params.KeysetID {
			return errors.New("proof from unpinned keyset")
		}
		kh, ok := s.Params.Keys[fmt.Sprint(pr.Amount)]
		if !ok || pr.Amount <= 0 {
			return errors.New("bad proof amount")
		}
		A, err := parsePub(kh)
		if err != nil {
			return errors.New("bad keyset key")
		}
		if err := verifyDLEQ(pr, A); err != nil {
			return err
		}
		y, err := proofY(pr.Secret)
		if err != nil {
			return err
		}
		if seen[y] {
			return errors.New("duplicate proof")
		}
		if _, used := s.UsedY[y]; used {
			return errors.New("proof already used in another bid")
		}
		seen[y] = true
		ys = append(ys, y)
		if sum > math.MaxInt64-pr.Amount {
			return errors.New("proof total overflows")
		}
		sum += pr.Amount
	}
	if sum != b.Amount {
		return fmt.Errorf("proofs total %d but bid is %d", sum, b.Amount)
	}
	lt, err := s.checkLock(b.Proofs, wallet, s.minLocktime(au, now))
	if err != nil {
		return err
	}
	// 2. Did it lose a race? Then it is late: recorded as void, refundable now.
	var late error
	min := au.StartPrice
	if au.HighBid != "" {
		min = au.HighAmount + au.MinIncrement
	}
	switch {
	case au.Status != "open" || (timed && now >= au.EndAt):
		late = &lateBid{"auction closed"}
	case ev.Pubkey == au.Seller:
		late = &lateBid{"seller cannot bid on own lot"}
	case au.HighBid != "" && s.Bids[au.HighBid].Bidder == ev.Pubkey:
		late = &lateBid{"you are already the highest bidder"}
	case b.Amount < min:
		late = &lateBid{fmt.Sprintf("bid must be at least %d sats", min)}
	}
	if late != nil && len(au.Voids) >= maxVoids {
		return errors.New(late.Error() + " (late-bid limit reached for this lot)")
	}
	if !apply {
		return late
	}
	bid := &Bid{ID: ev.ID, Auction: au.ID, Bidder: ev.Pubkey, Name: b.Name, Wallet: wallet, Amount: b.Amount,
		Proofs: b.Proofs, Locktime: lt, Height: height, Time: now, Status: "leading"}
	s.Bids[ev.ID] = bid
	for _, y := range ys {
		s.UsedY[y] = ev.ID
	}
	if late != nil {
		bid.Status = "void"
		au.Voids = append(au.Voids, ev.ID)
		return late
	}
	if au.HighBid != "" {
		s.Bids[au.HighBid].Status = "outbid"
	}
	// Anti-snipe (ADR 0009): a bid with less than the window left puts the
	// clock back to the window. No cap: the lot ends when the bidding stops.
	// Fixed lots end at their set time, whatever happens.
	if au.Mode == "antisnipe" && au.EndAt-now < au.WindowSec {
		au.EndAt = now + au.WindowSec
		au.Extensions++
		bid.Extended = true
	}
	au.HighBid, au.HighAmount = ev.ID, b.Amount
	au.Bids = append(au.Bids, ev.ID)
	return nil
}

// expiring: an anti-snipe lot's leading escrow is within a quarter of the
// lock margin of its locktime, so no relock has landed in time.
func (s *State) expiring(au *Auction, now int64) bool {
	return au.Mode == "antisnipe" && au.HighBid != "" && s.Bids[au.HighBid].Locktime-now < s.Params.LockMarginSec/4
}

func (s *State) closeDue(now, height int64) {
	ids := append([]string{}, s.Order...)
	sort.Strings(ids)
	for _, id := range ids {
		au := s.Auctions[id]
		if au.Status == "open" && now < au.EndAt && s.expiring(au, now) {
			// the leading escrow is near the point where its bidder could take
			// it back alone (no relock landed): close with no sale, refund all
			au.Status, au.ClosedAt, au.ClosedH, au.Expired = "closed", now, height, true
			for _, bid := range au.Bids {
				s.Bids[bid].Status = "lost"
			}
			continue
		}
		if au.Status == "open" && now >= au.EndAt {
			au.Status, au.ClosedAt, au.ClosedH = "closed", now, height
			if au.HighBid != "" {
				au.Winner = au.HighBid
				s.Bids[au.HighBid].Status = "won"
			}
			for _, bid := range au.Bids {
				if bid != au.Winner {
					s.Bids[bid].Status = "lost"
				}
			}
		}
	}
}

func (a *App) CheckTx(_ context.Context, req *abci.CheckTxRequest) (*abci.CheckTxResponse, error) {
	if c, ok := parseClose(req.Tx); ok {
		return a.checkClose(c, time.Now().Unix()), nil
	}
	if st, ok := parseSettle(req.Tx); ok {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if _, err := a.st.verifySettle(st, a.st.Time); err != nil {
			return &abci.CheckTxResponse{Code: 4, Log: err.Error()}, nil
		}
		return &abci.CheckTxResponse{Code: 0}, nil
	}
	ev, err := decodeTx(req.Tx)
	if err != nil {
		return &abci.CheckTxResponse{Code: 1, Log: err.Error()}, nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch ev.Kind {
	case KindCreate:
		err = a.st.applyCreate(ev, a.st.Time, a.st.Height, false)
	case KindBid:
		err = a.st.applyBid(ev, a.st.Time, a.st.Height, false, false)
	}
	var late *lateBid
	if errors.As(err, &late) {
		return &abci.CheckTxResponse{Code: 0, Log: "late: " + late.reason}, nil
	}
	if err != nil {
		return &abci.CheckTxResponse{Code: 2, Log: err.Error()}, nil
	}
	return &abci.CheckTxResponse{Code: 0}, nil
}

// checkClose admits a close transaction only while that auction is open,
// still ends at endAt, and endAt has passed on this validator's clock; and
// only if it was made in the last 30 s. Anything else is refused, so it is
// no use for spam.
func (a *App) checkClose(c *closeTx, now int64) *abci.CheckTxResponse {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// The close tx names the auction by its stable ROOT id, never by a mutable
	// version event id: an edit must not be able to orphan an in-flight close.
	au := a.st.byRoot(c.Auction)
	switch {
	case au == nil || au.Status != "open" || au.EndAt != c.EndAt:
		return &abci.CheckTxResponse{Code: 3, Log: "nothing to close"}
	case c.EndAt > now && !a.st.expiring(au, now):
		return &abci.CheckTxResponse{Code: 3, Log: "not due yet"}
	case c.Sent < now-30 || c.Sent > now+5:
		return &abci.CheckTxResponse{Code: 3, Log: "stale close"}
	}
	return &abci.CheckTxResponse{Code: 0}
}

func (a *App) FinalizeBlock(_ context.Context, req *abci.FinalizeBlockRequest) (*abci.FinalizeBlockResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.st
	now := req.Time.Unix()
	s.Height, s.Time = req.Height, now
	s.closeDue(now, req.Height)
	res := make([]*abci.ExecTxResult, len(req.Txs))
	lines := make([]ledgerLine, 0, len(req.Txs))
	for i, tx := range req.Txs {
		if _, ok := parseClose(tx); ok {
			// closeDue above already did the work; the tx only made the block
			res[i] = &abci.ExecTxResult{Code: 0}
			continue
		}
		if st, ok := parseSettle(tx); ok {
			v, err := s.verifySettle(st, now)
			if err != nil {
				// not a rejection a user caused: just not recorded
				res[i] = &abci.ExecTxResult{Code: 4, Log: err.Error()}
				continue
			}
			s.applySettle(st, v)
			s.TxCount++
			res[i] = &abci.ExecTxResult{Code: 0}
			lines = append(lines, ledgerLine{Height: req.Height, Time: now, Event: st.Bid, Result: "settled", Reason: st.Move, Tx: json.RawMessage(tx[len(settlePrefix):])})
			continue
		}
		ev, err := decodeTx(tx)
		if err == nil {
			switch ev.Kind {
			case KindCreate:
				err = s.applyCreate(ev, now, req.Height, true)
			case KindBid:
				err = s.applyBid(ev, now, req.Height, true, true)
			}
		}
		var late *lateBid
		if errors.As(err, &late) {
			s.TxCount++
			res[i] = &abci.ExecTxResult{Code: 0, Log: "void: " + late.reason}
			lines = append(lines, ledgerLine{Height: req.Height, Time: now, Kind: ev.Kind, Event: ev.ID, Result: "void", Reason: late.reason})
			continue
		}
		if err != nil {
			r := Rejection{Height: req.Height, Time: now, Reason: err.Error()}
			if ev != nil {
				r.Kind, r.Pubkey, r.Event = ev.Kind, ev.Pubkey, ev.ID
			}
			s.Rejections = append(s.Rejections, r)
			if len(s.Rejections) > 50 {
				s.Rejections = s.Rejections[len(s.Rejections)-50:]
			}
			res[i] = &abci.ExecTxResult{Code: 2, Log: err.Error()}
			ll := ledgerLine{Height: req.Height, Time: now, Result: "rejected", Reason: err.Error()}
			if ev != nil {
				ll.Kind, ll.Event = ev.Kind, ev.ID
			}
			lines = append(lines, ll)
			continue
		}
		s.TxCount++
		res[i] = &abci.ExecTxResult{Code: 0}
		lines = append(lines, ledgerLine{Height: req.Height, Time: now, Kind: ev.Kind, Event: ev.ID, Result: "ok", Tx: json.RawMessage(tx)})
	}
	a.pendLines = lines
	// One serialisation per block: the app hash is the SHA-256 of the same
	// canonical JSON that Commit publishes (identical to s.hash()).
	b := s.canonical()
	h := sha256.Sum256(b)
	a.appHash, a.pending = h[:], b
	return &abci.FinalizeBlockResponse{TxResults: res, AppHash: a.appHash}, nil
}

func (a *App) Commit(context.Context, *abci.CommitRequest) (*abci.CommitResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != nil {
		a.committed, a.pending = a.pending, nil
		a.committedHash = a.appHash
	} else {
		a.committed = a.st.canonical()
		h := sha256.Sum256(a.committed)
		a.committedHash = h[:]
	}
	a.committedH, a.committedT = a.st.Height, a.st.Time
	if a.commitCh != nil {
		close(a.commitCh)
		a.commitCh = nil
	}
	// the ledger line goes to disk before any block it covers can be pruned
	if a.ledger != nil {
		if err := a.ledger.append(a.committedH, a.pendLines); err != nil {
			log.Printf("ledger %d: %v", a.committedH, err)
		}
	}
	a.pendLines = nil
	var retain int64
	if a.retain > 0 && a.snap != nil {
		if r := a.snap.lastHeight() - a.retain; r > 0 {
			retain = r
		}
	}
	if a.snap != nil && a.snap.every > 0 && a.committedH%a.snap.every == 0 {
		h, t, hash, raw := a.committedH, a.committedT, a.committedHash, a.committed
		go func() {
			if err := a.snap.write(h, t, hash, raw); err != nil {
				log.Printf("snapshot %d: %v", h, err)
			}
		}()
	}
	return &abci.CommitResponse{RetainHeight: retain}, nil
}
