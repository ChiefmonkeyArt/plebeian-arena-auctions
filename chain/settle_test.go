package main

// v0.5.0 tests (ADR 0009): anti-snipe resets with no cap, fixed lots never
// move, expiry, push settlement (settle txs and the push signing policy),
// and the coordinator's majority pick.

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

// mintMove builds, "swaps" and unblinds one move the way the settler does.
func mintMove(t *testing.T, a *App, m *testMint, bidID, move, to string, now int64) *settleTx {
	t.Helper()
	st := testSettler(t, a)
	bid := a.st.Bids[bidID]
	at, err := st.build(dueMove{Bid: bid, Move: move, To: to}, now)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make([]blindSig, len(at.Outputs))
	for i, o := range at.Outputs {
		sigs[i] = m.blindSign(t, o)
	}
	if err := st.finish(at, sigs); err != nil {
		t.Fatal(err)
	}
	return &settleTx{Bid: bidID, Move: move, Proofs: at.Proofs, Sig: groupSign(t, sigAllMessage(bid.Proofs, at.Outputs))}
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
	if au.Status != "closed" || au.Winner == "" || au.Expired {
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

func TestAntiSnipeExpiresWithNoRelock(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 20, tNow+1000
	ev, tx := m.bidTx(t, a, newBidder(t), id, 100, "aa") // locktime tNow+30
	finalize(t, a, 11, tNow+1, tx)
	if c := a.checkClose(&closeTx{Auction: id, EndAt: au.EndAt}, tNow+10); c.Code == 0 {
		t.Fatal("no close while the escrow is far from its locktime")
	}
	finalize(t, a, 12, tNow+24) // 6 s left on a 30 s margin: below margin/4
	if au.Status != "closed" || !au.Expired || au.Winner != "" || a.st.Bids[ev.ID].Status != "lost" {
		t.Fatalf("an unrelocked anti-snipe lot must close with no sale: %+v", au)
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
	if items := a.st.dueMoves(tNow + 2); len(items) != 1 || items[0].Move != "refund" || items[0].To != alice.wallet {
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
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Purpose: "refund"}); code != 409 {
		t.Fatal("a settled escrow must not be released again")
	}
	// the client view: not "mine to claim" any more, but shows settled
	v := clientView(a.st, map[string]bool{alice.pub: true}, 5)
	if bv := v.Bids[ev1.ID]; bv != nil && bv.Settled != "refund" {
		t.Fatalf("view: %+v", bv)
	}
}

func TestPushSettleRefusesForgeries(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob, eve := newBidder(t), newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	good := mintMove(t, a, m, ev1.ID, "refund", alice.wallet, tNow+2)
	bad := map[string]*settleTx{}

	f := *good
	f.Sig = groupSign(t, "something else")
	bad["forged signature"] = &f

	// eve's key as the recipient, signed by the group: still refused,
	// because the chain says the refund goes to alice
	bad["wrong recipient"] = mintMove(t, a, m, ev1.ID, "refund", eve.wallet, tNow+2)

	short := *good
	short.Proofs = good.Proofs[1:]
	short.Sig = groupSign(t, sigAllMessage(a.st.Bids[ev1.ID].Proofs, outputsOf(short.Proofs)))
	bad["wrong amount"] = &short

	dl := *good
	dl.Proofs = append([]Proof(nil), good.Proofs...)
	d0 := *dl.Proofs[0].DLEQ
	d0.S = strings.Repeat("01", 32)
	dl.Proofs[0].DLEQ = &d0
	bad["bad DLEQ"] = &dl

	bad["leading bid"] = mintMove(t, a, m, ev2.ID, "refund", bob.wallet, tNow+2)
	bad["payout of an open lot"] = mintMove(t, a, m, ev2.ID, "payout", alice.wallet, tNow+2)

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

func TestPushPayoutAndRelock(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 20, tNow+1000
	seller := newBidder(t)
	au.SellerWallet = seller.wallet
	alice := newBidder(t)
	ev, tx := m.bidTx(t, a, alice, id, 150, "aa") // locktime tNow+30
	finalize(t, a, 11, tNow+1, tx)
	b := a.st.Bids[ev.ID]
	if len(a.st.dueMoves(tNow+5)) != 0 {
		t.Fatal("relock not due while the lock is far off")
	}
	items := a.st.dueMoves(tNow + 16) // 14 s left: below margin/2
	if len(items) != 1 || items[0].Move != "relock" {
		t.Fatalf("relock must be due: %+v", items)
	}
	old := b.Locktime
	st := mintMove(t, a, m, ev.ID, "relock", strings.ToLower(a.st.Params.GroupKey), tNow+16)
	if r := finalize(t, a, 12, tNow+16, makeSettle(st)); r.TxResults[0].Code != 0 {
		t.Fatalf("relock: %s", r.TxResults[0].Log)
	}
	if b.Settled != "" || b.Relocks != 1 || b.Locktime <= old || b.Status != "leading" {
		t.Fatalf("relock must keep the escrow with a later lock: %+v", b)
	}
	if _, err := a.st.checkLock(b.Proofs, alice.wallet, 0); err != nil {
		t.Fatalf("relocked escrow keeps the escrow lock: %v", err)
	}
	finalize(t, a, 13, tNow+24)
	if au.Status != "open" {
		t.Fatal("a relocked lot must not expire")
	}
	// relock to anyone but the group is refused
	if _, err := a.st.verifySettle(mintMove(t, a, m, ev.ID, "relock", alice.wallet, tNow+40), tNow+40); err == nil {
		t.Fatal("relock to a bidder key accepted")
	}
	// close and pay the seller
	au.EndAt = tNow + 50
	finalize(t, a, 14, tNow+50)
	if au.Winner != ev.ID {
		t.Fatalf("winner: %+v", au)
	}
	items = a.st.dueMoves(tNow + 51)
	if len(items) != 1 || items[0].Move != "payout" || items[0].To != seller.wallet {
		t.Fatalf("payout must be due to the seller: %+v", items)
	}
	pay := mintMove(t, a, m, ev.ID, "payout", seller.wallet, tNow+51)
	if r := finalize(t, a, 15, tNow+51, makeSettle(pay)); r.TxResults[0].Code != 0 {
		t.Fatalf("payout: %s", r.TxResults[0].Log)
	}
	if b.Settled != "payout" {
		t.Fatal("payout not recorded")
	}
}

func TestPushPolicyChecksRevealedOutputs(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	st := testSettler(t, a)
	at, _ := st.build(dueMove{Bid: a.st.Bids[ev1.ID], Move: "refund", To: alice.wallet}, tNow)
	req := SignReq{Bid: ev1.ID, Purpose: "push", Move: "refund", Outputs: at.Outputs, Reveal: at.Reveal}
	if _, code, err := releasePolicy(a, req); code != 200 {
		t.Fatalf("valid push refused: %d %v", code, err)
	}
	// hide the real recipient behind a different blinded message
	bad := req
	bad.Outputs = append([]SignOutput(nil), req.Outputs...)
	bad.Outputs[0].B = "02" + strings.Repeat("ab", 32)
	if _, code, _ := releasePolicy(a, bad); code == 200 {
		t.Fatal("output not matching its revealed secret accepted")
	}
	eveAt, _ := st.build(dueMove{Bid: a.st.Bids[ev1.ID], Move: "refund", To: bob.wallet}, tNow)
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Purpose: "push", Move: "refund", Outputs: eveAt.Outputs, Reveal: eveAt.Reveal}); code == 200 {
		t.Fatal("push to the wrong key accepted")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev2.ID, Purpose: "push", Move: "refund", Outputs: at.Outputs, Reveal: at.Reveal}); code == 200 {
		t.Fatal("push refund of the leading bid accepted")
	}
	noReveal := req
	noReveal.Reveal = nil
	if _, code, _ := releasePolicy(a, noReveal); code == 200 {
		t.Fatal("push without reveals accepted")
	}
	_ = m
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
