package main

// v0.4.0 tests (ADR 0007 and ADR 0003 §1, §4): late bids are recorded as
// void and refundable at once; the app hash ignores height and time; close
// txs; the ledger archive; pruning; the client view's voids.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	abci "github.com/cometbft/cometbft/abci/types"
)

type testMint struct {
	k  btcec.ModNScalar
	A  *btcec.PublicKey
	id string
}

func newTestMint(t *testing.T) *testMint {
	var m testMint
	m.k.SetByteSlice(randBytes(t))
	m.A = mulG(&m.k)
	m.id = "00testkeyset0001"
	return &m
}

func randBytes(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func scalarHex(s *btcec.ModNScalar) string { b := s.Bytes(); return hex.EncodeToString(b[:]) }

// sign issues one proof for secret with a NUT-12 DLEQ proof.
func (m *testMint) sign(t *testing.T, amount int64, secret string) Proof {
	Y, err := hashToCurve([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	var r, p btcec.ModNScalar
	r.SetByteSlice(randBytes(t))
	p.SetByteSlice(randBytes(t))
	C := mul(&m.k, Y)
	Bb := add(Y, mulG(&r))
	Cb := mul(&m.k, Bb)
	e32 := hashE(mulG(&p), mul(&p, Bb), m.A, Cb)
	var e, s btcec.ModNScalar
	e.SetBytes(&e32)
	s.Mul2(&e, &m.k).Add(&p)
	return Proof{ID: m.id, Amount: amount, Secret: secret, C: hex.EncodeToString(C.SerializeCompressed()),
		DLEQ: &DLEQ{E: scalarHex(&e), S: scalarHex(&s), R: scalarHex(&r)}}
}

func lockFor(group, wallet string, locktime int64, nonce string) string {
	return fmt.Sprintf(`["P2PK",{"nonce":"%s","data":"%s","tags":[["locktime","%d"],["refund","%s"],["sigflag","SIG_ALL"]]}]`, nonce, group, locktime, wallet)
}

type bidder struct {
	sk     *btcec.PrivateKey
	pub    string // x-only nostr key
	wallet string // compressed wallet key
}

func newBidder(t *testing.T) bidder {
	sk, _ := btcec.NewPrivateKey()
	w, _ := btcec.NewPrivateKey()
	return bidder{sk: sk, pub: hex.EncodeToString(schnorr.SerializePubKey(sk.PubKey())), wallet: hex.EncodeToString(w.PubKey().SerializeCompressed())}
}

func signEvent(t *testing.T, sk *btcec.PrivateKey, kind int, content string, at int64) *Event {
	ev := &Event{Pubkey: hex.EncodeToString(schnorr.SerializePubKey(sk.PubKey())), CreatedAt: at, Kind: kind, Tags: [][]string{}, Content: content}
	h := sha256.Sum256([]byte(ev.Serialize()))
	ev.ID = hex.EncodeToString(h[:])
	sig, err := schnorr.Sign(sk, h[:])
	if err != nil {
		t.Fatal(err)
	}
	ev.Sig = hex.EncodeToString(sig.Serialize())
	return ev
}

const tNow = int64(1_800_000_000)

// liveApp: one open lot (start 100, +10) ending at tNow+100, hard end +160.
func liveApp(t *testing.T) (*App, *testMint, string) {
	m := newTestMint(t)
	group := hex.EncodeToString(mulG(new(btcec.ModNScalar).SetInt(7)).SerializeCompressed())
	a := NewApp()
	a.st.Params = Params{KeysetID: m.id, Keys: map[string]string{}, GroupKey: group, LockMarginSec: 30, MaxProofs: 64,
		SoftCloseSec: 20, ExtendSec: 20, MaxExtendSec: 60}
	for _, amt := range []int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512} {
		a.st.Params.Keys[fmt.Sprint(amt)] = hex.EncodeToString(m.A.SerializeCompressed())
	}
	a.st.Height, a.st.Time = 10, tNow
	id := hx(42)
	a.st.Auctions[id] = &Auction{ID: id, Seller: hx(7), Status: "open", StartPrice: 100, MinIncrement: 10,
		EndAt: tNow + 100, HardEnd: tNow + 160}
	a.st.Order = []string{id}
	return a, m, id
}

func (m *testMint) bidTx(t *testing.T, a *App, b bidder, auction string, amount int64, nonce string) (*Event, []byte) {
	var proofs []Proof
	lt := a.st.Auctions[auction].HardEnd + a.st.Params.LockMarginSec
	left, i := amount, 0
	for d := int64(512); d >= 1; d /= 2 {
		for left >= d {
			proofs = append(proofs, m.sign(t, d, lockFor(a.st.Params.GroupKey, b.wallet, lt, fmt.Sprintf("%s%02d", nonce, i))))
			left -= d
			i++
		}
	}
	c, _ := json.Marshal(BidContent{Auction: auction, Amount: amount, Wallet: b.wallet, Name: "t", Proofs: proofs})
	ev := signEvent(t, b.sk, KindBid, string(c), tNow)
	tx, _ := json.Marshal(ev)
	return ev, tx
}

func finalize(t *testing.T, a *App, h, at int64, txs ...[]byte) *abci.FinalizeBlockResponse {
	t.Helper()
	res, err := a.FinalizeBlock(context.Background(), &abci.FinalizeBlockRequest{Height: h, Time: time.Unix(at, 0), Txs: txs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(context.Background(), &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	return res
}

func TestLateBidIsVoidAndRefundable(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 200, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 150, "bb") // below 200+10: lost the race

	// CheckTx: the late bid passes with a "late:" note, so the client knows at once
	ck, _ := a.CheckTx(context.Background(), &abci.CheckTxRequest{Tx: tx1})
	if ck.Code != 0 || ck.Log != "" {
		t.Fatalf("good bid: %d %q", ck.Code, ck.Log)
	}
	res := finalize(t, a, 11, tNow+1, tx1)
	if res.TxResults[0].Code != 0 {
		t.Fatalf("bid 1: %v", res.TxResults[0].Log)
	}
	ck, _ = a.CheckTx(context.Background(), &abci.CheckTxRequest{Tx: tx2})
	if ck.Code != 0 || !strings.HasPrefix(ck.Log, "late: bid must be at least 210") {
		t.Fatalf("late bid CheckTx: %d %q", ck.Code, ck.Log)
	}
	res = finalize(t, a, 12, tNow+2, tx2)
	if r := res.TxResults[0]; r.Code != 0 || !strings.HasPrefix(r.Log, "void: ") {
		t.Fatalf("late bid FinalizeBlock: %d %q", r.Code, r.Log)
	}
	au, b := a.st.Auctions[id], a.st.Bids[ev2.ID]
	if b == nil || b.Status != "void" || au.HighBid != ev1.ID || len(au.Bids) != 1 || len(au.Voids) != 1 {
		t.Fatalf("void not recorded right: %+v %+v", b, au)
	}
	for _, p := range b.Proofs {
		y, _ := proofY(p.Secret)
		if a.st.UsedY[y] != ev2.ID {
			t.Fatal("a void bid's proofs must be marked used")
		}
	}
	// the escrow can be refunded now: policy passes up to the wallet signature
	out := []SignOutput{{Amount: 128, ID: m.id, B: "02" + strings.Repeat("ab", 32)}, {Amount: 16, ID: m.id, B: "02" + strings.Repeat("ac", 32)},
		{Amount: 4, ID: m.id, B: "02" + strings.Repeat("ad", 32)}, {Amount: 2, ID: m.id, B: "02" + strings.Repeat("ae", 32)}}
	if _, code, err := releasePolicy(a, SignReq{Bid: ev2.ID, Purpose: "refund", Outputs: out, Auth: strings.Repeat("00", 64)}); code != 403 {
		t.Fatalf("void refund must reach the auth check, got %d %v", code, err)
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Purpose: "refund", Outputs: out}); code != 409 {
		t.Fatal("the leading bid must not be refundable")
	}
	// the same proofs cannot be bid again
	ck, _ = a.CheckTx(context.Background(), &abci.CheckTxRequest{Tx: tx2})
	if ck.Code == 0 {
		t.Fatal("a replayed void bid must be refused")
	}
	// the bidder's own view shows it; nobody else's does
	v := clientView(a.st, map[string]bool{bob.pub: true}, 5)
	if v.Bids[ev2.ID] == nil || v.Bids[ev2.ID].Status != "void" {
		t.Fatal("the bidder's view must include their void bid")
	}
	if clientView(a.st, map[string]bool{alice.pub: true}, 5).Bids[ev2.ID] != nil {
		t.Fatal("someone else's void bid must not be in the view")
	}
}

func TestBadEscrowIsRejectedNotVoid(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "cc")
	var c BidContent
	json.Unmarshal([]byte(ev.Content), &c)
	c.Proofs[0].DLEQ.E = strings.Repeat("11", 32) // forged
	c.Amount = 50                                 // and too low
	err := a.st.applyBid(&Event{ID: hx(99), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	var late *lateBid
	if err == nil || errors.As(err, &late) {
		t.Fatalf("a bad escrow must be refused outright, got %v", err)
	}
	if len(a.st.UsedY) != 0 || len(a.st.Bids) != 0 {
		t.Fatal("a refused bid must leave no trace")
	}
}

func TestLateAfterEndIsVoid(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	_, tx := m.bidTx(t, a, bob, id, 150, "dd")
	res := finalize(t, a, 11, tNow+101, tx) // the block closes the lot first
	if a.st.Auctions[id].Status != "closed" || !strings.HasPrefix(res.TxResults[0].Log, "void: auction closed") {
		t.Fatalf("bid after the end must be void: %q", res.TxResults[0].Log)
	}
}

func TestVoidCap(t *testing.T) {
	a, m, id := liveApp(t)
	a.st.Auctions[id].Voids = make([]string, maxVoids)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 50, "ee")
	err := a.st.applyBid(ev, tNow, 11, true, true)
	var late *lateBid
	if err == nil || errors.As(err, &late) {
		t.Fatalf("past the cap a late bid is refused: %v", err)
	}
}

func TestEmptyBlocksKeepAppHash(t *testing.T) {
	a, _, _ := liveApp(t)
	h1 := finalize(t, a, 11, tNow+1).AppHash
	h2 := finalize(t, a, 12, tNow+30).AppHash
	if !bytes.Equal(h1, h2) {
		t.Fatal("an empty block must not change the app hash (else CometBFT makes a proof block every time)")
	}
	var pub struct{ Height, Time int64 }
	json.Unmarshal(a.Snapshot(), &pub)
	if pub.Height != 12 || pub.Time != tNow+30 {
		t.Fatalf("published state must carry height/time: %+v", pub)
	}
	if !bytes.HasPrefix(a.committed, []byte(canonPrefix)) {
		t.Fatal("canonical bytes must start with zero height/time")
	}
	if got := sha256.Sum256(a.committed); !bytes.Equal(got[:], h2) {
		t.Fatal("app hash must be sha256 of the canonical bytes")
	}
}

func TestCloseTx(t *testing.T) {
	a, _, id := liveApp(t)
	au := a.st.Auctions[id]
	tx := makeClose(id, au.EndAt, tNow+100)
	c, ok := parseClose(tx)
	if !ok || c.Auction != id || c.EndAt != au.EndAt {
		t.Fatal("close tx round trip")
	}
	for name, bad := range map[string][]byte{
		"short id": []byte("close:abc:1:1"), "extra": append(append([]byte{}, tx...), ":1"...), "upper": []byte(strings.ToUpper(string(tx))),
		"not a number": []byte("close:" + id + ":x:1"),
	} {
		if _, ok := parseClose(bad); ok {
			t.Errorf("%s: parsed", name)
		}
	}
	if r := a.checkClose(c, au.EndAt-1); r.Code == 0 {
		t.Fatal("close before EndAt must be refused")
	}
	if r := a.checkClose(c, au.EndAt+60); r.Code == 0 {
		t.Fatal("a stale close must be refused")
	}
	if r := a.checkClose(&closeTx{id, au.EndAt + 5, tNow + 200}, tNow+200); r.Code == 0 {
		t.Fatal("a close for another EndAt must be refused")
	}
	if r := a.checkClose(c, au.EndAt); r.Code != 0 {
		t.Fatalf("a due close must pass: %s", r.Log)
	}
	res := finalize(t, a, 11, au.EndAt, tx)
	if res.TxResults[0].Code != 0 || au.Status != "closed" {
		t.Fatal("the block carrying a close tx closes the lot")
	}
	if r := a.checkClose(c, au.EndAt+1); r.Code == 0 {
		t.Fatal("close for a closed lot must be refused")
	}
	if a.st.TxCount != 0 {
		t.Fatal("close txs are not counted as bids/creates")
	}
}

func TestLedgerArchiveAndRetain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "ledger.jsonl")
	a, m, id := liveApp(t)
	var err error
	a.ledger, err = openLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.snap = &snapshotter{dir: filepath.Join(dir, "snap"), every: 0}
	a.retain = 5
	alice, bob := newBidder(t), newBidder(t)
	_, tx1 := m.bidTx(t, a, alice, id, 200, "f1")
	_, tx2 := m.bidTx(t, a, bob, id, 150, "f2")
	finalize(t, a, 11, tNow+1, tx1)
	finalize(t, a, 12, tNow+2) // empty: no line
	finalize(t, a, 13, tNow+3, tx2, []byte("junk"))
	a.ledger.close()

	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"result":"ok"`) || !strings.Contains(lines[1], `"result":"void"`) || !strings.Contains(lines[2], `"result":"rejected"`) {
		t.Fatalf("ledger:\n%s", b)
	}
	// a replay after restart does not duplicate; a torn tail is cut
	os.WriteFile(path, append(b, []byte(`{"height":14,"ti`)...), 0o600)
	l, err := openLedger(path)
	if err != nil || l.last != 13 {
		t.Fatalf("reopen: %v last %d", err, l.last)
	}
	l.append(13, []ledgerLine{{Height: 13, Result: "ok"}})
	l.append(14, []ledgerLine{{Height: 14, Result: "ok"}})
	l.close()
	b2, _ := os.ReadFile(path)
	if n := strings.Count(string(b2), "\n"); n != 4 || strings.Contains(string(b2), `"ti`+"\n") {
		t.Fatalf("after replay want 4 whole lines, got %d:\n%s", n, b2)
	}

	// pruning keeps retain blocks below the newest snapshot
	a.ledger = nil
	a.snap.last = 3
	if r, _ := a.Commit(context.Background(), &abci.CommitRequest{}); r.RetainHeight != 0 {
		t.Fatal("no pruning before the first snapshot clears the window")
	}
	a.snap.last = 20
	if r, _ := a.Commit(context.Background(), &abci.CommitRequest{}); r.RetainHeight != 15 {
		t.Fatalf("retain height %d, want 15", r.RetainHeight)
	}
	a.retain = 0
	if r, _ := a.Commit(context.Background(), &abci.CommitRequest{}); r.RetainHeight != 0 {
		t.Fatal("-retain-blocks 0 keeps everything")
	}
}

func TestSnapshotFormat2RestoresTime(t *testing.T) {
	dir := t.TempDir()
	a, _, _ := liveApp(t)
	a.snap = &snapshotter{dir: dir}
	finalize(t, a, 11, tNow+5)
	h, tt, hash, raw := a.committedSnapshot()
	if err := a.snap.write(h, tt, hash, raw); err != nil {
		t.Fatal(err)
	}
	s, err := loadSnapshot(dir, func(int64) ([]byte, bool, error) { return hash, true, nil })
	if err != nil || s.height != 11 || s.time != tNow+5 || s.state.Time != tNow+5 {
		t.Fatalf("restore: %v %+v", err, s)
	}
	b := NewApp()
	b.restore(s)
	if !bytes.Equal(b.Snapshot(), a.Snapshot()) {
		t.Fatal("restored published state differs")
	}
	if x, y := finalize(t, a, 12, tNow+9).AppHash, finalize(t, b, 12, tNow+9).AppHash; !bytes.Equal(x, y) {
		t.Fatal("restored app diverges")
	}
}
