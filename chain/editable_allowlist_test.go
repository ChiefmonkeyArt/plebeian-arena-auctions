package main

// Tests for the editable-allow-list mechanism and the 1440 kind map.
//
// Owner decision 2026-11-12, merged protocol spec §7 (the kind map) and §8
// (the editable allow-list), ported onto v0.5.2 and REMAPPED onto his current
// create payload: the old branch's immutable set named late-bid fields he has
// since deleted, so the set here is StartPrice, MinIncrement, Mode, WindowSec,
// DurationSec and SellerWallet — display is mutable, money/time/cryptography
// are not.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// resignWithTags re-signs an existing event with new tags (so a block can carry
// a validly signed bid whose e tag a Byzantine proposer chose).
func resignWithTags(t *testing.T, sk *btcec.PrivateKey, ev *Event, tags [][]string) *Event {
	t.Helper()
	out := &Event{Pubkey: ev.Pubkey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: tags, Content: ev.Content}
	h := sha256Sum(out.Serialize())
	out.ID = hex.EncodeToString(h[:])
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out.Sig = hex.EncodeToString(sig.Serialize())
	return out
}

// ---- the kind map (spec §7) ----------------------------------------------

// TestKindMapIsRegularRange asserts the whole 1440 series sits in NIP-01's
// regular range (1000 <= n < 10000), never the ephemeral range khatru drops.
func TestKindMapIsRegularRange(t *testing.T) {
	if len(AuctionKinds) == 0 {
		t.Fatal("AuctionKinds must not be empty")
	}
	want := map[string]int{
		"create": KindCreate, "bid": KindBid, "chat": KindChat, "refund": KindRefund,
		"settle": KindSettle, "outcome": KindOutcome, "funding_abort": KindFundingAbort, "state_commit": KindStateCommit,
	}
	for role, k := range want {
		if AuctionKinds[role] != k {
			t.Errorf("AuctionKinds[%q] = %d, want %d", role, AuctionKinds[role], k)
		}
	}
	for role, k := range AuctionKinds {
		if !regularKind(k) {
			t.Errorf("kind %q = %d is outside the regular range 1000..9999", role, k)
		}
	}
	// the series must line up with the spec's exact numbering
	for role, k := range map[string]int{"create": 1440, "bid": 1441, "chat": 1442, "refund": 1443, "settle": 1444, "outcome": 1445, "funding_abort": 1446, "state_commit": 1447} {
		if AuctionKinds[role] != k {
			t.Errorf("role %q must be %d, got %d", role, k, AuctionKinds[role])
		}
	}
}

// TestNoScatteredKindLiterals greps the tree: the kind numbers may appear only
// in the const/map block in nostr.go, never as code literals anywhere else
// (decision §2). The 2864x numbers of the old ephemeral POC are checked as a
// class. Comments and the coordinate string form ("1440:<seller>:<d>") are not
// kind literals and are allowed.
func TestNoScatteredKindLiterals(t *testing.T) {
	old := regexp.MustCompile(`\b28(6[3-9]\d|6[5-9]\d)\b`) // the POC's 2864x ephemeral range
	// a bare 144x used AS A NUMBER (not preceded by a quote, not part of a
	// coordinate string like "1440:" and not in a kind: json field)
	bare := regexp.MustCompile(`(^|[^\w"'])(144[0-7])([^\w":]|$)`)
	root := "."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "nostr.go") || strings.HasSuffix(path, "editable_allowlist_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := line
			if j := strings.Index(code, "//"); j >= 0 {
				code = code[:j] // comments may name the kind in prose
			}
			if old.MatchString(code) {
				t.Errorf("%s:%d: removed POC kind literal: %s", path, i+1, strings.TrimSpace(line))
			}
			if bare.MatchString(code) && !strings.Contains(code, "Kind") {
				t.Errorf("%s:%d: scattered kind literal: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ---- root pinning (spec §8, decision §4) ----------------------------------

func baseLot() CreateContent {
	return CreateContent{Title: "Vintage camera", Description: "tested", Image: "https://img.example/m3.jpg",
		Category: "Art", StartPrice: 100, MinIncrement: 10, DurationSec: 60, SellerWallet: tW, Name: "Seller"}
}

func auctionState() *State {
	s := newState()
	s.Height, s.Time = 1, tNow
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 7200, MinWindowSec: 15, MaxWindowSec: 900}
	return s
}

// createEv signs a 1440 create for (seller, d). extra tags carry the root
// reference ["e", rootID] on a supersession.
func createEv(t *testing.T, sk *btcec.PrivateKey, d string, c CreateContent, at int64, extra ...[2]string) *Event {
	t.Helper()
	tags := [][]string{{"d", d}}
	for _, tg := range extra {
		tags = append(tags, []string{tg[0], tg[1]})
	}
	b, _ := json.Marshal(c)
	return signEventTags(t, sk, KindCreate, string(b), at, tags)
}

func TestFirstCreateBecomesRoot(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	ev := createEv(t, seller.sk, "lot-1", baseLot(), tNow)
	if err := s.applyCreate(ev, tNow, 1, true); err != nil {
		t.Fatalf("root create: %v", err)
	}
	coord := coordOf(seller.pub, "lot-1")
	au := s.canonicalAuction(seller.pub, "lot-1")
	if au == nil {
		t.Fatal("auction not stored under its (seller, d) coordinate")
	}
	if au.ID != coord || au.RootID != ev.ID || au.VersionID != ev.ID || au.D != "lot-1" {
		t.Fatalf("root pinning wrong: %+v", au)
	}
	if au.EndAt != tNow+60 || au.DurationSec != 60 {
		t.Fatalf("timing materialised wrong: end=%d dur=%d", au.EndAt, au.DurationSec)
	}
	// the coordinate is ours, a = 1440:<seller>:<d>
	if !strings.HasPrefix(au.ID, "1440:") {
		t.Fatalf("coordinate must start with 1440:, got %s", au.ID)
	}
	// a create without a d tag is not an auction
	noD := signEventTags(t, seller.sk, KindCreate, string(must(json.Marshal(baseLot()))), tNow, [][]string{})
	if err := s.applyCreate(noD, tNow, 2, true); err == nil {
		t.Fatal("a create without a d tag must be refused")
	}
	// a d with illegal characters is not a coordinate
	for _, bad := range []string{"", "has space", "bad/slash", strings.Repeat("x", 65)} {
		ev := createEv(t, seller.sk, bad, baseLot(), tNow)
		if err := s.applyCreate(ev, tNow, 2, true); err == nil {
			t.Fatalf("d %q must be refused", bad)
		}
	}
}

// ---- the allow-list (spec §8) ---------------------------------------------

func TestEditDisplayFieldsAccepted(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	root := createEv(t, seller.sk, "lot-2", baseLot(), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatal(err)
	}
	c := baseLot()
	c.Title, c.Description, c.Image, c.Category, c.Name = "Vintage camera (v2)", "tested, ships worldwide", "https://img.example/m3-front.jpg", "Cameras", "Seller Co"
	edit := createEv(t, seller.sk, "lot-2", c, tNow+10, [2]string{"e", root.ID})
	if err := s.applyCreate(edit, tNow+10, 2, true); err != nil {
		t.Fatalf("display-only edit must be accepted: %v", err)
	}
	au := s.canonicalAuction(seller.pub, "lot-2")
	if au.Title != c.Title || au.Image != c.Image || au.Category != c.Category || au.SellerName != c.Name {
		t.Fatalf("edit not applied: %+v", au)
	}
	if au.RootID != root.ID || au.VersionID != edit.ID {
		t.Fatalf("root must stay and the version must advance: root=%s ver=%s", au.RootID, au.VersionID)
	}
}

func TestEditMoneyFieldRefused(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	root := createEv(t, seller.sk, "lot-3", baseLot(), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatal(err)
	}
	c := baseLot()
	c.StartPrice = 200
	edit := createEv(t, seller.sk, "lot-3", c, tNow+10, [2]string{"e", root.ID})
	err := s.applyCreate(edit, tNow+10, 2, true)
	if err == nil || err.Error() != "immutable_field_changed StartPrice" {
		t.Fatalf("want immutable_field_changed StartPrice, got %v", err)
	}
	if au := s.canonicalAuction(seller.pub, "lot-3"); au.StartPrice != 100 || au.VersionID != root.ID {
		t.Fatalf("a refused edit must not change the canonical auction: %+v", au)
	}
}

// TestEditEachImmutableFieldRefused mutates every immutable field by itself and
// asserts the exact refusal names it. The set is the REMAPPED one: StartPrice,
// MinIncrement, Mode, WindowSec, DurationSec, SellerWallet.
func TestEditEachImmutableFieldRefused(t *testing.T) {
	cases := map[string]func(c *CreateContent){
		"StartPrice":   func(c *CreateContent) { c.StartPrice = 200 },
		"MinIncrement": func(c *CreateContent) { c.MinIncrement = 50 },
		"Mode":         func(c *CreateContent) { c.Mode = "fixed"; c.WindowSec = 0 },
		"WindowSec":    func(c *CreateContent) { c.WindowSec = 60 },
		"DurationSec":  func(c *CreateContent) { c.DurationSec = 120 },
		"SellerWallet": func(c *CreateContent) { c.SellerWallet = "02" + strings.Repeat("44", 32) },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			s := auctionState()
			seller := newBidder(t)
			// the root is an antisnipe lot so both Mode and WindowSec are live
			base := baseLot()
			base.Mode, base.WindowSec = "antisnipe", 30
			root := createEv(t, seller.sk, "lot-x", base, tNow)
			if err := s.applyCreate(root, tNow, 1, true); err != nil {
				t.Fatal(err)
			}
			c := base
			mutate(&c)
			edit := createEv(t, seller.sk, "lot-x", c, tNow+10, [2]string{"e", root.ID})
			err := s.applyCreate(edit, tNow+10, 2, true)
			if err == nil || err.Error() != "immutable_field_changed "+field {
				t.Fatalf("want immutable_field_changed %s, got %v", field, err)
			}
		})
	}
}

func TestEditMustReferenceRoot(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	root := createEv(t, seller.sk, "lot-y", baseLot(), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatal(err)
	}
	c := baseLot()
	c.Title = "no root tag"
	edit := createEv(t, seller.sk, "lot-y", c, tNow+10) // no e tag
	if err := s.applyCreate(edit, tNow+10, 2, true); err == nil {
		t.Fatal("an update without e = auction_root_event_id must be refused")
	}
	wrong := createEv(t, seller.sk, "lot-y", c, tNow+10, [2]string{"e", hx(999)})
	if err := s.applyCreate(wrong, tNow+10, 2, true); err == nil {
		t.Fatal("an update pointing at a non-root event must be refused")
	}
	// a first create that claims a root it cannot know must be refused too
	orphan := createEv(t, seller.sk, "lot-z", baseLot(), tNow, [2]string{"e", hx(999)})
	if err := s.applyCreate(orphan, tNow, 3, true); err == nil {
		t.Fatal("the first create for a (seller, d) must not carry an e tag")
	}
}

func TestCanonicalResolvesLatestAcceptedVersion(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	root := createEv(t, seller.sk, "lot-4", baseLot(), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatal(err)
	}
	c := baseLot()
	c.Title = "v2 title"
	good := createEv(t, seller.sk, "lot-4", c, tNow+10, [2]string{"e", root.ID})
	if err := s.applyCreate(good, tNow+10, 2, true); err != nil {
		t.Fatalf("accepted edit: %v", err)
	}
	// a newer event that changes money is REJECTED and ignored
	bad := baseLot()
	bad.Title, bad.StartPrice = "v3 title", 500
	badEv := createEv(t, seller.sk, "lot-4", bad, tNow+20, [2]string{"e", root.ID})
	if err := s.applyCreate(badEv, tNow+20, 3, true); err == nil {
		t.Fatal("money edit must be refused")
	}
	// an edit older than the canonical version is ignored
	stale := baseLot()
	stale.Title = "stale title"
	staleEv := createEv(t, seller.sk, "lot-4", stale, tNow+5, [2]string{"e", root.ID})
	if err := s.applyCreate(staleEv, tNow+5, 4, true); err == nil {
		t.Fatal("a stale edit must be ignored")
	}
	au := s.canonicalAuction(seller.pub, "lot-4")
	if au.Title != "v2 title" || au.VersionID != good.ID {
		t.Fatalf("canonical must be the latest ACCEPTED version: title=%q ver=%s", au.Title, au.VersionID)
	}
}

// ---- bids bind to the root (spec §8) --------------------------------------

// auctionApp is liveApp through applyCreate, so the auction lives under its
// real (seller, d) coordinate with a real root id. It returns the coordinate
// and the root event id.
func auctionApp(t *testing.T, d string) (*App, *testMint, bidder, string, string) {
	t.Helper()
	m := newTestMint(t)
	group := hex.EncodeToString(mulG(new(btcec.ModNScalar).SetInt(7)).SerializeCompressed())
	a := NewApp()
	a.st.Params = Params{KeysetID: m.id, Keys: map[string]string{}, GroupKey: group, LockMarginSec: 30, MaxProofs: 64,
		MinWindowSec: 15, MaxWindowSec: 900, MinDurationSec: 20, MaxDurationSec: 7200}
	for _, amt := range []int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512} {
		a.st.Params.Keys[fmt.Sprint(amt)] = hex.EncodeToString(m.A.SerializeCompressed())
	}
	a.st.Height, a.st.Time = 10, tNow
	seller := newBidder(t)
	c := baseLot()
	c.DurationSec = 100
	root := createEv(t, seller.sk, d, c, tNow)
	if err := a.st.applyCreate(root, tNow, 10, true); err != nil {
		t.Fatal(err)
	}
	return a, m, seller, coordOf(seller.pub, d), root.ID
}

// TestBidWrongRootRefused checks the root binding IN THE TRANSITION: a bid that
// does not carry e = auction_root_event_id is refused by applyBid itself, not
// just at admission (a Byzantine proposer can skip CheckTx).
func TestBidWrongRootRefused(t *testing.T) {
	a, _, _, coord, rootID := auctionApp(t, "lot-5")
	mk := func(tags [][]string) *Event {
		return &Event{ID: hx(60), Pubkey: hx(61), Kind: KindBid, Tags: tags, Content: `{"auction":"` + coord + `","amount":1,"proofs":[]}`}
	}
	if err := a.st.applyBid(mk([][]string{{"e", hx(999)}}), tNow, 11, true, true); err == nil || !strings.Contains(err.Error(), "auction root") {
		t.Fatalf("a bid with the wrong e must be refused as a root mismatch, got %v", err)
	}
	if err := a.st.applyBid(mk(nil), tNow, 11, true, true); err == nil || !strings.Contains(err.Error(), "auction root") {
		t.Fatalf("a bid with no e must be refused, got %v", err)
	}
	// the correct root passes the root gate (then fails later, on the empty proof set)
	if err := a.st.applyBid(mk([][]string{{"e", rootID}}), tNow, 11, true, true); err == nil || strings.Contains(err.Error(), "auction root") {
		t.Fatalf("a bid with the correct root must pass the root gate, got %v", err)
	}
	// a bid naming the root and a mismatched coordinate is refused
	if err := a.st.applyBid(mk([][]string{{"e", rootID}, {"a", "1440:someone:else"}}), tNow, 11, true, true); err == nil || !strings.Contains(err.Error(), "coordinate") {
		t.Fatalf("a bid with a mismatched a coordinate must be refused, got %v", err)
	}
}

// TestBidWrongRootRefusedInBlock puts a bid with the wrong e straight into a
// block (bypassing CheckTx) and asserts the block rejects it: the transition,
// not the mempool, is what enforces the binding.
func TestBidWrongRootRefusedInBlock(t *testing.T) {
	a, m, _, coord, _ := auctionApp(t, "lot-6")
	alice := newBidder(t)
	_, tx := m.bidTx(t, a, alice, coord, 200, "aa")
	// rewrite the event's e tag to a bogus root and re-sign: a Byzantine
	// proposer cannot produce a valid signature over a different tag, so we
	// simulate the mempool-bypass by submitting a correctly signed bid whose e
	// is simply not this auction's root.
	var ev Event
	if err := json.Unmarshal(tx, &ev); err != nil {
		t.Fatal(err)
	}
	ev = *resignWithTags(t, alice.sk, &ev, [][]string{{"e", hx(1234)}, {"a", coord}})
	bogus, _ := json.Marshal(&ev)
	res := finalize(t, a, 11, tNow+1, bogus)
	if r := res.TxResults[0]; r.Code == 0 || !strings.Contains(r.Log, "auction root") {
		t.Fatalf("a bid with the wrong root must be rejected in the block, got code=%d log=%q", r.Code, r.Log)
	}
	if au := a.st.Auctions[coord]; au.HighBid != "" || len(au.Bids) != 0 {
		t.Fatal("the rejected bid must not have been applied")
	}
}

func TestBidSurvivesEdit(t *testing.T) {
	a, m, seller, coord, rootID := auctionApp(t, "lot-7")
	alice := newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, coord, 200, "aa")
	if res := finalize(t, a, 11, tNow+1, tx1); res.TxResults[0].Code != 0 {
		t.Fatalf("first bid refused: %s", res.TxResults[0].Log)
	}
	// the seller edits the title; the auction root must not change
	c := baseLot()
	c.DurationSec, c.Title = 100, "Retitled"
	edit := createEv(t, seller.sk, "lot-7", c, tNow+5, [2]string{"e", rootID})
	if res := finalize(t, a, 12, tNow+6, must(json.Marshal(edit))); res.TxResults[0].Code != 0 {
		t.Fatalf("edit after a bid refused: %s", res.TxResults[0].Log)
	}
	au := a.st.Auctions[coord]
	if au.Title != "Retitled" {
		t.Fatalf("edit not applied: %q", au.Title)
	}
	if au.RootID != rootID || au.HighBid != ev1.ID || len(au.Bids) != 1 {
		t.Fatalf("the bid must survive the edit (root=%s high=%s bids=%v)", au.RootID, au.HighBid, au.Bids)
	}
	if b := a.st.Bids[ev1.ID]; b == nil || b.Auction != coord {
		t.Fatal("the bid still points at the auction coordinate")
	}
	// a further bid, still bound to the root, is accepted and takes the lead
	bob := newBidder(t)
	ev2, tx2 := m.bidTx(t, a, bob, coord, 210, "bb")
	if res := finalize(t, a, 13, tNow+7, tx2); res.TxResults[0].Code != 0 {
		t.Fatalf("a bid after the edit must still be accepted: %s", res.TxResults[0].Log)
	}
	if a.st.Auctions[coord].HighBid != ev2.ID {
		t.Fatal("the post-edit bid must take the lead")
	}
}

// TestEditCannotChangeCoordinate is the structural immutability: changing the d
// (or the seller) makes a DIFFERENT auction, never an edit of this one.
func TestEditCannotChangeCoordinate(t *testing.T) {
	s := auctionState()
	seller := newBidder(t)
	root := createEv(t, seller.sk, "lot-a", baseLot(), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatal(err)
	}
	// the same seller, a new d, pointing at the old root: a different auction
	other := createEv(t, seller.sk, "lot-b", baseLot(), tNow+10, [2]string{"e", root.ID})
	if err := s.applyCreate(other, tNow+10, 2, true); err == nil {
		t.Fatal("a create for a new d must not be accepted as a supersession")
	}
	if s.canonicalAuction(seller.pub, "lot-a").Title != "Vintage camera" {
		t.Fatal("the original auction must be untouched")
	}
}
