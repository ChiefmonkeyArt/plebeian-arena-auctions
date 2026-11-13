package main

// Tests for V4V payout splits (spec §6): strict validation and named refusals at
// create, immutability of the committed split, the bidder's pre-signed SETTLE
// template having to reproduce the committed split exactly, bidder-only refunds,
// the floor/remainder rounding rule, and no regression on a split-less auction.
//
// These use the base's own test fixtures (liveApp, newBidder, newTestMint,
// signEvent, lockForSigAll, p2pkOut, must). No real mint is needed here: the
// chain's admission rule is what is under test. The 2-of-2 mint-level acceptance
// is covered separately by sigall_mint_test.go.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// splitRow builds a create-payload split row with a canonical integer bps.
func splitRow(role, pub string, bps int64) SplitRow {
	return SplitRow{Role: role, RecipientPubkey: pub, AllocationBps: json.Number(strconv.FormatInt(bps, 10))}
}


// createWithD signs a 1440 create carrying the `d` tag every create now needs:
// an auction's identity is (seller, d) and a create without a valid d is
// refused. These tests do not care which d it is.
func createWithD(t *testing.T, sk *btcec.PrivateKey, content string, createdAt int64) *Event {
	t.Helper()
	return createWithTags(t, sk, content, createdAt, nil)
}

// createWithTags adds extra tags to the `d` tag — used for a supersession,
// which must carry e = the auction root (spec §8).
func createWithTags(t *testing.T, sk *btcec.PrivateKey, content string, createdAt int64, extra [][]string) *Event {
	t.Helper()
	tags := [][]string{{"d", "v4v-lot"}}
	return signEventTags(t, sk, KindCreate, content, createdAt, append(tags, extra...))
}

// --- create-time validation -------------------------------------------------

// v4vCreateApp is liveApp plus a committed V4V split on the lot. The lot's
// auction id is the create event id in this base, so the split is attached
// directly to the fixture auction (exactly as applyCreate would).
func v4vCreateApp(t *testing.T, rows []SplitRow) (*App, *testMint, string, *Auction) {
	t.Helper()
	a, m, id := liveApp(t)
	split, err := validateV4VSplit(rows)
	if err != nil {
		t.Fatalf("fixture split invalid: %v", err)
	}
	a.st.Auctions[id].V4VSplit = split
	return a, m, id, a.st.Auctions[id]
}

func TestV4VSplitAcceptedAtCreate(t *testing.T) {
	s := newState()
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200, MinWindowSec: 60, MaxWindowSec: 900}
	seller := newBidder(t)
	validatorX, v4vY := realPub(t, 21), realPub(t, 22)
	// deliberately v4v before validator: the committed order is canonicalised.
	c := baseCreate()
	c.V4VSplit = []SplitRow{splitRow("v4v", v4vY, 2000), splitRow("validator", validatorX, 500)}
	ev := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
	if err := s.applyCreate(ev, tNow, 1, true); err != nil {
		t.Fatalf("a valid split create was refused: %v", err)
	}
	au := s.Auctions[coordOf(ev.Pubkey, "v4v-lot")] // auctions are keyed by their (seller, d) coordinate
	if au == nil || len(au.V4VSplit) != 2 {
		t.Fatalf("split not stored: %+v", au)
	}
	if au.V4VSplit[0].Role != "validator" || au.V4VSplit[1].Role != "v4v" {
		t.Fatalf("split not in canonical role order (validator < v4v): %+v", au.V4VSplit)
	}
	sum := au.V4VSplit[0].AllocationBps + au.V4VSplit[1].AllocationBps
	if rem := int64(10000) - sum; rem != 7500 {
		t.Fatalf("seller remainder %d bps, want 7500", rem)
	}
}

func TestV4VSplitTotalExceeds10000Refused(t *testing.T) {
	s := newState()
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200}
	seller := newBidder(t)
	c := baseCreate()
	c.V4VSplit = []SplitRow{splitRow("v4v", realPub(t, 21), 6000), splitRow("v4v", realPub(t, 22), 5000)}
	ev := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
	err := s.applyCreate(ev, tNow, 1, true)
	if err == nil || !strings.Contains(err.Error(), "v4v_split_total_exceeds_10000") {
		t.Fatalf("want v4v_split_total_exceeds_10000, got %v", err)
	}
}

func TestV4VSplitDuplicateRecipientRefused(t *testing.T) {
	s := newState()
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200}
	seller := newBidder(t)
	dup := realPub(t, 21)
	c := baseCreate()
	c.V4VSplit = []SplitRow{splitRow("validator", dup, 500), splitRow("v4v", dup, 2000)}
	ev := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
	err := s.applyCreate(ev, tNow, 1, true)
	if err == nil || !strings.Contains(err.Error(), "v4v_split_duplicate_recipient") {
		t.Fatalf("want v4v_split_duplicate_recipient, got %v", err)
	}
}

func TestV4VSplitUnknownRoleRefused(t *testing.T) {
	s := newState()
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200}
	seller := newBidder(t)
	c := baseCreate()
	c.V4VSplit = []SplitRow{splitRow("seller", realPub(t, 21), 500)}
	ev := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
	err := s.applyCreate(ev, tNow, 1, true)
	if err == nil || !strings.Contains(err.Error(), "v4v_split_role_unknown") {
		t.Fatalf("want v4v_split_role_unknown, got %v", err)
	}
}

func TestV4VSplitBpsNotIntegerOrNegativeRefused(t *testing.T) {
	cases := map[string]struct {
		bps  json.Number
		want string
	}{
		"non-integer": {json.Number("12.5"), "v4v_split_bps_not_integer"},
		"negative":    {json.Number("-5"), "v4v_split_bps_out_of_range"},
		"over 10000":  {json.Number("10001"), "v4v_split_bps_out_of_range"},
		"v4v zero":    {json.Number("0"), "v4v_split_bps_out_of_range"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newState()
			s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200}
			seller := newBidder(t)
			c := baseCreate()
			c.V4VSplit = []SplitRow{{Role: "v4v", RecipientPubkey: realPub(t, 21), AllocationBps: tc.bps}}
			ev := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
			err := s.applyCreate(ev, tNow, 1, true)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

// baseCreate is a valid create payload for the fixtures above.
func baseCreate() CreateContent {
	return CreateContent{Title: "lot", DurationSec: 100, StartPrice: 100, MinIncrement: 10,
		SellerWallet: sellerWalletKey(), Mode: "fixed"}
}

// sellerWalletKey is a fixed, valid compressed seller payout key.
func sellerWalletKey() string {
	sk, _ := btcec.PrivKeyFromBytes(append(make([]byte, 31), 9))
	return hex.EncodeToString(sk.PubKey().SerializeCompressed())
}

// The split is a money field (spec §8): once committed, a re-publish that
// changes it is refused BY NAME, and the stored split is left untouched.
//
// The auction's identity is (seller, d) and a supersession must point at the
// ROOT (spec §8), so this builds the root inline rather than reusing the
// liveApp fixture: it needs the seller's own key to sign the edit.
func TestV4VSplitEditRefusedByName(t *testing.T) {
	s := newState()
	s.Params = Params{MinDurationSec: 20, MaxDurationSec: 259200, MinWindowSec: 60, MaxWindowSec: 900}
	seller := newBidder(t)
	recipient := realPub(t, 21)

	c := baseCreate()
	c.V4VSplit = []SplitRow{splitRow("v4v", recipient, 500)}
	root := createWithD(t, seller.sk, string(must(json.Marshal(c))), tNow)
	if err := s.applyCreate(root, tNow, 1, true); err != nil {
		t.Fatalf("fixture root create refused: %v", err)
	}
	coord := coordOf(root.Pubkey, "v4v-lot")
	au := s.Auctions[coord]
	if au == nil || len(au.V4VSplit) != 1 || au.V4VSplit[0].AllocationBps != 500 {
		t.Fatalf("fixture split wrong: %+v", au)
	}

	// A supersession for the same (seller, d) that changes the split is refused
	// by name. Everything else is identical, so the split is the only thing
	// that can trigger it.
	c2 := baseCreate()
	c2.V4VSplit = []SplitRow{splitRow("v4v", recipient, 600)}
	ev := createWithTags(t, seller.sk, string(must(json.Marshal(c2))), tNow+20,
		[][]string{{"e", au.RootID}})
	err := s.applyCreate(ev, tNow+20, 3, true)
	if err == nil || err.Error() != "immutable_field_changed V4VSplit" {
		t.Fatalf("want immutable_field_changed V4VSplit, got %v", err)
	}
	if got := s.Auctions[coord].V4VSplit[0].AllocationBps; got != 500 {
		t.Fatalf("a refused edit must not change the committed split, got %d", got)
	}
}

// --- settle template enforcement -------------------------------------------

// mkOut builds one plain P2PK output locked to recipient with a fresh blinding
// factor. The secret must be a canonical plain P2PK lock with just a sigflag
// tag, which is what recipientMatches accepts as a settled destination.
func mkOut(recipient string, amount int64, idx int, keyset string) sigAllTemplateOutput {
	return sigAllTemplateOutput{
		Amount: amount, ID: keyset,
		Secret: p2pkOut(recipient, fmt.Sprintf("%064x", 0x3000+idx+1)),
		R:      fmt.Sprintf("%064x", 0x400000+idx+1),
	}
}

// signTemplate turns an output list into a signed template over the bid's proofs.
func signTemplate(t *testing.T, b bidder, proofs []Proof, outs []sigAllTemplateOutput) sigAllSignedTemplate {
	t.Helper()
	var inputs []sigAllTemplateInput
	for _, p := range proofs {
		inputs = append(inputs, sigAllTemplateInput{Amount: p.Amount, ID: p.ID, Secret: p.Secret, C: p.C})
	}
	tpl := sigAllSignedTemplate{Inputs: inputs, Outputs: outs}
	d, err := sigAllTemplateDigest(tpl)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(b.walletSk, mustHex(d))
	if err != nil {
		t.Fatal(err)
	}
	tpl.Digest, tpl.BidderSignature = d, hex.EncodeToString(sig.Serialize())
	return tpl
}

// v4vBid builds a bid for a split auction. The settle template reproduces the
// committed split exactly unless mutateSettle rewrites its outputs before
// signing; the refund template is bidder-only unless mutateRefund rewrites it.
// Either way the template is re-signed, so the ONLY fault is the output set.
func v4vBid(t *testing.T, a *App, m *testMint, b bidder, auction string, amount int64, nonce string,
	mutateSettle, mutateRefund func(*sigAllSignedTemplate)) (*Event, []byte) {
	t.Helper()
	au := a.st.Auctions[auction]
	lt := a.st.minLocktime(au, a.st.Time)
	var proofs []Proof
	left, i := amount, 0
	for d := int64(512); d >= 1; d /= 2 {
		for left >= d {
			proofs = append(proofs, m.sign(t, d, lockForSigAll(a.st.Params.GroupKey, b.wallet, lt, fmt.Sprintf("%s%02d", nonce, i))))
			left -= d
			i++
		}
	}
	var sout []sigAllTemplateOutput
	for j, so := range splitSats(au.SellerWallet, au.V4VSplit, amount) {
		sout = append(sout, mkOut(so.Recipient, so.Amount, j, m.id))
	}
	settle := sigAllSignedTemplate{Outputs: sout}
	if mutateSettle != nil {
		mutateSettle(&settle)
	}
	settle = signTemplate(t, b, proofs, settle.Outputs)

	var rout []sigAllTemplateOutput
	for j, p := range proofs {
		rout = append(rout, mkOut(b.wallet, p.Amount, 100+j, m.id))
	}
	refund := sigAllSignedTemplate{Outputs: rout}
	if mutateRefund != nil {
		mutateRefund(&refund)
	}
	refund = signTemplate(t, b, proofs, refund.Outputs)

	c := BidContent{Auction: auction, Amount: amount, Wallet: b.wallet, Name: "t", Proofs: proofs,
		OutcomeTemplates: &sigAllOutcomeTemplates{Settle: settle, Refund: refund}}
	ev := signEventTags(t, b.sk, KindBid, string(must(json.Marshal(c))), tNow,
		[][]string{{"e", a.st.Auctions[auction].RootID}})
	tx, _ := json.Marshal(ev)
	return ev, tx
}

func TestV4VSettleTemplateMatchesSplitAccepted(t *testing.T) {
	rows := []SplitRow{splitRow("validator", realPub(t, 21), 500), splitRow("v4v", realPub(t, 22), 2000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "aa", nil, nil) // 200 -> validator 10, v4v 40, seller 150
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("a bid whose settle template matches the committed split was refused: %v", err)
	}
	if b, ok := a.st.Bids[ev.ID]; !ok || b.OutcomeTemplates == nil {
		t.Fatal("the bid must be stored with its committed templates")
	}
}

func TestV4VSettleTemplateOmitsRowRefused(t *testing.T) {
	rows := []SplitRow{splitRow("validator", realPub(t, 21), 500), splitRow("v4v", realPub(t, 22), 3000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "ab", func(tpl *sigAllSignedTemplate) {
		tpl.Outputs = tpl.Outputs[:len(tpl.Outputs)-1] // drop a row
	}, nil)
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "omits a committed v4v split output") {
		t.Fatalf("want a refused template that omits a row, got %v", err)
	}
}

func TestV4VSettleTemplateAddsRecipientRefused(t *testing.T) {
	rows := []SplitRow{splitRow("validator", realPub(t, 21), 500), splitRow("v4v", realPub(t, 22), 3000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	attacker := realPub(t, 99)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "ac", func(tpl *sigAllSignedTemplate) {
		// keep the sum at 200 by taking a sat from the seller remainder output
		tpl.Outputs = append(tpl.Outputs, mkOut(attacker, 1, 50, m.id))
		tpl.Outputs[len(tpl.Outputs)-2].Amount -= 1
	}, nil)
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "adds an output that is not in the committed v4v split") {
		t.Fatalf("want a refused template that adds an uncommitted recipient, got %v", err)
	}
}

func TestV4VSettleTemplateReordersRowsRefused(t *testing.T) {
	rows := []SplitRow{splitRow("validator", realPub(t, 21), 5000), splitRow("v4v", realPub(t, 22), 3000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "ad", func(tpl *sigAllSignedTemplate) {
		tpl.Outputs[0], tpl.Outputs[1] = tpl.Outputs[1], tpl.Outputs[0]
	}, nil)
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "reordered") {
		t.Fatalf("want a refused template that reorders rows, got %v", err)
	}
}

func TestV4VSettleTemplateRepricesRowRefused(t *testing.T) {
	rows := []SplitRow{splitRow("validator", realPub(t, 21), 5000), splitRow("v4v", realPub(t, 22), 5000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "ae", func(tpl *sigAllSignedTemplate) {
		// keep the sum at 200 so the fault is purely the per-row price
		tpl.Outputs[0].Amount, tpl.Outputs[1].Amount = 101, 99
	}, nil)
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "reprices the committed split row") {
		t.Fatalf("want a refused template that reprices a row, got %v", err)
	}
}

func TestV4VRefundTemplateWithSplitRowRefused(t *testing.T) {
	recipient := realPub(t, 21)
	rows := []SplitRow{splitRow("v4v", recipient, 2000), splitRow("v4v", realPub(t, 22), 2000)}
	a, m, id, _ := v4vCreateApp(t, rows)
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "af", nil, func(tpl *sigAllSignedTemplate) {
		// pay the first committed V4V recipient from the refund branch
		tpl.Outputs[0].Secret = mkOut(recipient, tpl.Outputs[0].Amount, 0, m.id).Secret
	})
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "refund output 0 pays a committed v4v split recipient") {
		t.Fatalf("want a refund that pays a v4v row refused by name, got %v", err)
	}
}

// --- rounding ---------------------------------------------------------------

func TestV4VRoundingRemainderToSeller(t *testing.T) {
	rows := []SplitRow{splitRow("v4v", realPub(t, 21), 3333), splitRow("v4v", realPub(t, 22), 3333)}
	a, m, id, au := v4vCreateApp(t, rows)

	outs := splitSats(au.SellerWallet, au.V4VSplit, 100)
	if len(outs) != 3 {
		t.Fatalf("want 3 outputs (2 rows + seller), got %d: %+v", len(outs), outs)
	}
	if outs[0].Amount != 33 || outs[1].Amount != 33 {
		t.Fatalf("floored shares wrong: %+v", outs)
	}
	if !sameKey(outs[2].Recipient, au.SellerWallet) || outs[2].Amount != 34 {
		t.Fatalf("the rounding remainder must go to the seller (want 34), got %+v", outs[2])
	}
	var sum int64
	for _, o := range outs {
		sum += o.Amount
	}
	if sum != 100 {
		t.Fatalf("outputs must sum to the bid amount exactly: got %d", sum)
	}

	// the committed template matching this rule is admitted
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 100, "b0", nil, nil)
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("the floored template must be admitted: %v", err)
	}

	// a template that takes the dust from the seller (33/34/33) is refused
	a2, m2, id2, _ := v4vCreateApp(t, rows)
	bob2 := newBidder(t)
	ev2, _ := v4vBid(t, a2, m2, bob2, id2, 100, "b1", func(tpl *sigAllSignedTemplate) {
		tpl.Outputs[1].Amount, tpl.Outputs[2].Amount = 34, 33
	}, nil)
	err := a2.st.applyBid(ev2, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "reprices the committed split row") {
		t.Fatalf("a template that moves the seller's dust must be refused, got %v", err)
	}
}

// When the split allocates all 10000 bps and the floors sum to the whole bid,
// there is NO seller output: the remainder is zero. That is stated explicitly.
func TestV4VFullSplitLeavesNoSellerOutput(t *testing.T) {
	rows := []SplitRow{splitRow("v4v", realPub(t, 21), 5000), splitRow("v4v", realPub(t, 22), 5000)}
	a, m, id, au := v4vCreateApp(t, rows)
	outs := splitSats(au.SellerWallet, au.V4VSplit, 200)
	if len(outs) != 2 {
		t.Fatalf("a full 10000 bps split that divides evenly must have no seller output, got %+v", outs)
	}
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "c0", nil, nil)
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("a full-split bid with no seller output must be admitted: %v", err)
	}
}

// --- no regression ----------------------------------------------------------

func TestV4VNoSplitBidStillWorks(t *testing.T) {
	a, m, id := liveApp(t)
	if len(a.st.Auctions[id].V4VSplit) != 0 {
		t.Fatal("fixture must have no committed split")
	}
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "d0")
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("a bid on a split-less auction must still be accepted: %v", err)
	}
}

// verifySettle is split-aware: with a committed split, output i must be locked
// to the committed row i's recipient, not the seller. We tamper the committed
// template (post-admission) so an output pays the seller where a v4v row belongs
// and prove verifySettle refuses it per row.
func TestV4VSettleTxDestinationIsPerRow(t *testing.T) {
	rows := []SplitRow{splitRow("v4v", realPub(t, 21), 5000)}
	a, m, id, au := v4vCreateApp(t, rows)
	a.st.Params.Keys["100"] = hex.EncodeToString(m.A.SerializeCompressed())
	bob := newBidder(t)
	ev, _ := v4vBid(t, a, m, bob, id, 200, "e0", nil, nil)
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("split bid must be admitted: %v", err)
	}
	au.Status, au.Winner = "closed", ev.ID
	a.st.Bids[ev.ID].Status = "won"

	// Tamper row 0 (a v4v row) so the committed template pays the SELLER, and
	// build each outcome proof with the template's own blinding factor so the
	// proof blinds to the (tampered) template output and reaches the destination
	// check rather than failing earlier on the blind comparison.
	tpl := &a.st.Bids[ev.ID].OutcomeTemplates.Settle
	tpl.Outputs[0].Secret = p2pkOut(au.SellerWallet, fmt.Sprintf("%064x", 0x9001))
	sig := hex.EncodeToString(make([]byte, 64))

	var proofs []Proof
	for _, o := range tpl.Outputs {
		Y, err := hashToCurve([]byte(o.Secret))
		if err != nil {
			t.Fatal(err)
		}
		r, err := parseScalar(o.R)
		if err != nil {
			t.Fatal(err)
		}
		C := mul(&m.k, Y)
		Cb := add(C, mul(r, m.A))
		Bb := add(Y, mulG(r))
		var p btcec.ModNScalar
		p.SetByteSlice(randBytes(t))
		e32 := hashE(mulG(&p), mul(&p, Bb), m.A, Cb)
		var e, s btcec.ModNScalar
		e.SetBytes(&e32)
		s.Mul2(&e, &m.k).Add(&p)
		proofs = append(proofs, Proof{ID: m.id, Amount: o.Amount, Secret: o.Secret,
			C:    hex.EncodeToString(C.SerializeCompressed()),
			DLEQ: &DLEQ{E: scalarHex(&e), S: scalarHex(&s), R: o.R}})
	}
	if _, err := a.st.verifySettle(&settleTx{Bid: ev.ID, Outcome: "settle", Proofs: proofs, Sig: sig}, tNow); err == nil || !strings.Contains(err.Error(), "not locked to the committed destination") {
		t.Fatalf("a split settle that pays the seller where a v4v row belongs must be refused by the destination check, got %v", err)
	}
}
