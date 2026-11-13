package main

// v0.5.0 + 2-of-2 tests (ADR 0009, spec §4/§5): anti-snipe resets with no cap,
// fixed lots never move, push settlement through the bidder's COMMITTED
// outcome templates (the settler is an executor), the push signing policy
// over committed outputs, and the coordinator's majority pick.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	abci "github.com/cometbft/cometbft/abci/types"
)

// the liveApp group key is 7*G: a plain key stands in for the FROST group
// (the signature it makes is the same BIP-340 signature FROST produces)
func groupSign(t *testing.T, msg string) string {
	t.Helper()
	sk, _ := btcec.PrivKeyFromBytes(append(make([]byte, 31), 7))
	h := sha256Sum(msg)
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig.Serialize())
}

// blindSign is the mint's side of a swap: C_ = k*B_ with a NUT-12 DLEQ.
func (m *testMint) blindSign(t *testing.T, o SignOutput) blindSig {
	B, err := parsePub(o.B)
	if err != nil {
		t.Fatal(err)
	}
	var p btcec.ModNScalar
	p.SetByteSlice(randBytes(t))
	Cb := mul(&m.k, B)
	e32 := hashE(mulG(&p), mul(&p, B), m.A, Cb)
	var e, s btcec.ModNScalar
	e.SetBytes(&e32)
	s.Mul2(&e, &m.k).Add(&p)
	bs := blindSig{ID: o.ID, Amount: o.Amount, C_: hex.EncodeToString(Cb.SerializeCompressed())}
	bs.DLEQ = &struct {
		E string `json:"e"`
		S string `json:"s"`
	}{scalarHex(&e), scalarHex(&s)}
	return bs
}

func testSettler(t *testing.T, a *App) *settler {
	return &settler{p: a.st.Params, journal: filepath.Join(t.TempDir(), "j.jsonl"), done: map[string]*settleAttempt{}, tries: map[string][]*settleAttempt{}}
}

// mintMove submits one committed outcome the way the settler does: it derives
// the template's outputs from committed state, "swaps" them at the fake mint,
// unblinds, and builds the settle tx with the committee group signature over
// exactly the committed outputs.
func mintMove(t *testing.T, a *App, m *testMint, bidID, outcome, to string, now int64) *settleTx {
	t.Helper()
	st := testSettler(t, a)
	bid := a.st.Bids[bidID]
	outs, reveal, _, err := st.templateMaterial(bid, outcome)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([]blindSig, len(outs))
	for i, o := range outs {
		sigs[i] = m.blindSign(t, o)
	}
	at := &settleAttempt{Bid: bidID, Outcome: outcome, To: to, Outputs: outs, Reveal: reveal}
	if err := st.finish(at, sigs); err != nil {
		t.Fatal(err)
	}
	return &settleTx{Bid: bidID, Outcome: outcome, Proofs: at.Proofs, Sig: groupSign(t, sigAllMessage(bid.Proofs, outs))}
}

func outputsOf(proofs []Proof) []SignOutput {
	out := make([]SignOutput, len(proofs))
	for i, p := range proofs {
		b, _ := blinded(p.Secret, p.DLEQ.R)
		out[i] = SignOutput{Amount: p.Amount, ID: p.ID, B: b}
	}
	return out
}

func TestAntiSnipeResetsWithNoCap(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 20, tNow+30
	at, amount := tNow+15, int64(100)
	for h := int64(11); h < 31; h++ {
		a.st.Time = at
		_, tx := m.bidTx(t, a, newBidder(t), id, amount, hex.EncodeToString([]byte{byte(h)}))
		if r := finalize(t, a, h, at, tx); r.TxResults[0].Code != 0 {
			t.Fatalf("bid at %d: %s", h, r.TxResults[0].Log)
		}
		if au.EndAt != at+20 {
			t.Fatalf("bid %d with < window left must reset the clock to the window: end %d, now %d", h, au.EndAt, at)
		}
		at, amount = at+15, amount+10
	}
	if au.Status != "open" || au.Extensions != 20 || au.EndAt <= tNow+300 {
		t.Fatalf("anti-snipe must keep resetting with no cap: %+v", au)
	}
	// a bid with more than the window left does not move the end
	a.st.Time = au.EndAt - 25
	au.EndAt += 10
	end := au.EndAt
	_, tx := m.bidTx(t, a, newBidder(t), id, amount, "ff")
	finalize(t, a, 40, a.st.Time, tx)
	if au.EndAt != end {
		t.Fatal("a bid with more than the window left must not move the end")
	}
	finalize(t, a, 41, end)
	if au.Status != "closed" || au.Winner == "" {
		t.Fatalf("the lot closes when the bidding stops: %+v", au)
	}
}

func TestFixedLotNeverExtends(t *testing.T) {
	a, m, id := liveApp(t)
	_, tx := m.bidTx(t, a, newBidder(t), id, 100, "aa")
	finalize(t, a, 11, tNow+99, tx)
	if au := a.st.Auctions[id]; au.EndAt != tNow+100 || au.Extensions != 0 {
		t.Fatalf("a fixed lot must end on time: %+v", au)
	}
	finalize(t, a, 12, tNow+100)
	if a.st.Auctions[id].Status != "closed" {
		t.Fatal("fixed lot must close at its end")
	}
}

// An anti-snipe lot whose leading escrow is far from its locktime is not
// closed early any more: there is no expiry and no no-sale path (spec §11).
func TestAntiSnipeHasNoExpiryPath(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 20, tNow+1000
	ev, tx := m.bidTx(t, a, newBidder(t), id, 100, "aa")
	finalize(t, a, 11, tNow+1, tx)
	if c := a.checkClose(&closeTx{Auction: id, EndAt: au.EndAt}, tNow+24); c.Code == 0 {
		t.Fatal("no early close: a lot ends only when the bidding stops")
	}
	finalize(t, a, 12, tNow+24)
	if au.Status != "open" || a.st.Bids[ev.ID].Status != "leading" {
		t.Fatalf("an anti-snipe lot with a long lock must stay open: %+v", au)
	}
}

func TestPushRefundSettles(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	_, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	if a.st.Bids[ev1.ID].Status != "outbid" {
		t.Fatal("setup")
	}
	if items := a.st.dueMoves(tNow + 2); len(items) != 1 || items[0].Outcome != "refund" || items[0].To != alice.wallet {
		t.Fatalf("the outbid escrow must be due for a refund: %+v", items)
	}
	st := mintMove(t, a, m, ev1.ID, "refund", alice.wallet, tNow+2)
	tx := makeSettle(st)
	if ck, _ := a.CheckTx(context.Background(), &abci.CheckTxRequest{Tx: tx}); ck.Code != 0 {
		t.Fatalf("valid settle refused: %s", ck.Log)
	}
	if r := finalize(t, a, 12, tNow+2, tx); r.TxResults[0].Code != 0 {
		t.Fatalf("settle: %s", r.TxResults[0].Log)
	}
	b := a.st.Bids[ev1.ID]
	if b.Settled != "refund" || len(b.Out) != len(st.Proofs) {
		t.Fatalf("not settled: %+v", b)
	}
	if len(a.st.dueMoves(tNow+3)) != 0 {
		t.Fatal("a settled escrow is no longer due")
	}
	if r := finalize(t, a, 13, tNow+3, tx); r.TxResults[0].Code == 0 {
		t.Fatal("a settle tx must not apply twice")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "refund"}); code != 409 {
		t.Fatal("a settled escrow must not be released again")
	}
	// the client view shows it settled
	v := clientView(a.st, map[string]bool{alice.pub: true}, 5)
	if bv := v.Bids[ev1.ID]; bv != nil && bv.Settled != "refund" {
		t.Fatalf("view: %+v", bv)
	}
}

func TestPushSettleRefusesForgeries(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	good := mintMove(t, a, m, ev1.ID, "refund", alice.wallet, tNow+2)
	bad := map[string]*settleTx{}

	f := *good
	f.Sig = groupSign(t, "something else")
	bad["forged signature"] = &f

	// a different output set than the committed template (a redirected refund)
	short := *good
	short.Proofs = good.Proofs[1:]
	short.Sig = groupSign(t, sigAllMessage(a.st.Bids[ev1.ID].Proofs, outputsOf(short.Proofs)))
	bad["wrong amount"] = &short

	// a tampered DLEQ on one new proof
	dl := *good
	dl.Proofs = append([]Proof(nil), good.Proofs...)
	d0 := *dl.Proofs[0].DLEQ
	d0.S = strings.Repeat("01", 32)
	dl.Proofs[0].DLEQ = &d0
	bad["bad DLEQ"] = &dl

	// a new proof whose secret is not the committed template's output
	th := *good
	th.Proofs = append([]Proof(nil), good.Proofs...)
	th.Proofs[0] = a.st.Bids[ev1.ID].Proofs[0] // the OLD proof secret, re-used
	bad["foreign output"] = &th

	bad["leading bid"] = mintMove(t, a, m, ev2.ID, "refund", bob.wallet, tNow+2)
	bad["settle of an open lot"] = mintMove(t, a, m, ev2.ID, "settle", a.st.Auctions[id].SellerWallet, tNow+2)

	for name, st := range bad {
		if ck, _ := a.CheckTx(context.Background(), &abci.CheckTxRequest{Tx: makeSettle(st)}); ck.Code == 0 {
			t.Errorf("%s: settle accepted", name)
		}
	}
	// unknown fields are refused outright
	raw, _ := json.Marshal(good)
	if _, ok := parseSettle(append([]byte(settlePrefix), append(raw[:len(raw)-1], []byte(`,"x":1}`)...)...)); ok {
		t.Error("unknown settle field accepted")
	}
}

func TestPushSettleAndRefund(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 60, tNow+1000
	seller := newBidder(t)
	au.SellerWallet = seller.wallet
	alice := newBidder(t)
	ev, tx := m.bidTx(t, a, alice, id, 150, "aa")
	finalize(t, a, 11, tNow+1, tx)
	b := a.st.Bids[ev.ID]
	if len(a.st.dueMoves(tNow+5)) != 0 {
		t.Fatal("nothing is due while the lot is open and the bid leads")
	}
	// close and pay the seller via the committed settle template
	au.EndAt = tNow + 50
	finalize(t, a, 12, tNow+50)
	if au.Winner != ev.ID {
		t.Fatalf("winner: %+v", au)
	}
	items := a.st.dueMoves(tNow + 51)
	if len(items) != 1 || items[0].Outcome != "settle" || items[0].To != seller.wallet {
		t.Fatalf("settle must be due to the seller: %+v", items)
	}
	pay := mintMove(t, a, m, ev.ID, "settle", seller.wallet, tNow+51)
	if r := finalize(t, a, 13, tNow+51, makeSettle(pay)); r.TxResults[0].Code != 0 {
		t.Fatalf("settle: %s", r.TxResults[0].Log)
	}
	if b.Settled != "settle" {
		t.Fatal("settle not recorded")
	}
	// a settled escrow cannot also be refunded
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev.ID, Outcome: "refund"}); code != 409 {
		t.Fatal("a settled escrow must not be refundable")
	}
}

// The push signing policy signs the COMMITTED template's outputs and nothing
// else: a refund of a leading bid is refused, and an unknown outcome name is
// refused. There is no caller-supplied output any more (spec §4/§5).
func TestPushPolicySignsCommittedTemplate(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	_ = m

	if _, code, err := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "refund"}); code != 200 {
		t.Fatalf("valid refund refused: %d %v", code, err)
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev2.ID, Outcome: "refund"}); code == 200 {
		t.Fatal("refund of the leading bid accepted")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "payout"}); code == 200 {
		t.Fatal("an unknown outcome must be refused")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "nonsense"}); code == 200 {
		t.Fatal("a nonsense outcome must be refused")
	}
}

func TestPickSignersMajority(t *testing.T) {
	c := func(msg string) frostCommit { return frostCommit{Message: msg} }
	got, msg := pickSigners([]frostCommit{c("m"), c("x"), c("m"), c("m")})
	if msg != "m" || len(got) != 3 {
		t.Fatalf("majority: %q %d", msg, len(got))
	}
	if _, msg := pickSigners([]frostCommit{c("m"), c("m"), c("x"), c("y")}); msg != "" {
		t.Fatal("no three agree: nothing to sign")
	}
	e := frostCommit{Message: "m", Error: "down"}
	if got, msg := pickSigners([]frostCommit{e, c("m"), c("m"), c("m")}); msg != "m" || len(got) != 3 {
		t.Fatal("a refusing validator is skipped")
	}
}

func TestSplitAmount(t *testing.T) {
	keys := map[string]string{"1": "", "2": "", "4": "", "8": "", "16": "", "32": "", "64": "", "128": ""}
	got := splitAmount(150, keys)
	var sum int64
	for _, v := range got {
		sum += v
	}
	if sum != 150 || len(got) != 4 {
		t.Fatalf("split: %v", got)
	}
	if splitAmount(256, keys) != nil {
		t.Fatal("missing denomination must fail")
	}
}
