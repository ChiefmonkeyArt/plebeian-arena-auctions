package main

// The verdict-publish end-to-end test, against a REAL `nak serve` relay.
//
// It proves the whole write path end to end and, above all, the property the
// increment exists for: a client that reads ONLY the relay reconstructs the
// auction outcome with NO call to a validator or a node.
//
// Sequence:
//  1. a `nak` relay is started on an OS-chosen high loopback port;
//  2. a relay-only READER subscribes BEFORE anything is published (an observer
//     is attached, so the relay is live);
//  3. a CLIENT publishes a create and a bid to the relay;
//  4. the same bytes are committed into a validator's chain (the observer's
//     ingest half is feat/relay-ingest's job; here we feed the relayed bytes to
//     the app so this test can focus on the WRITE path);
//  5. the block that closes the auction commits, then the validator PUBLISHES a
//     verdict (kind 1445) and a state commitment (kind 1447) to the relay,
//     anchored to that committed block's height and hash;
//  6. the reader, using only what it read from the relay, reconstructs the
//     outcome.
//
// The test skips (cleanly) when `nak` is absent rather than passing vacuously.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// hexGroupKey7 is the deterministic FROST group key liveApp uses (7*G), so the
// e2e lot's escrow lock matches what the app's checkLock expects.
func hexGroupKey7() string {
	return hex.EncodeToString(mulG(new(btcec.ModNScalar).SetInt(7)).SerializeCompressed())
}

// hexCompressedGroupKey is the test mint's public key A, as the keyset map wants.
func hexCompressedGroupKey(m *testMint) string { return hex.EncodeToString(m.A.SerializeCompressed()) }

// --- nak relay helpers ---


// startNakRelay launches `nak serve` on a free loopback port.  The port is
// chosen by the OS via net.Listen(":0"), so it can never collide with the
// demo's 7770/7777/8080/3338/13338.

type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}

func waitForRelay(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- the test ---

func TestVerdictPublishE2ERelayOnlyClientReconstructsOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping relay acceptance test in -short mode")
	}
	url, stopRelay := startNakRelay(t)
	defer stopRelay()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- build one lot, its create event and a committed bid. -------------
	m := newTestMint(t)
	group := hexGroupKey7()
	a := NewApp()
	vk, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a.st.Params = Params{KeysetID: m.id, Keys: map[string]string{}, GroupKey: group, LockMarginSec: 30, MaxProofs: 64,
		MinWindowSec: 15, MaxWindowSec: 900, MinDurationSec: 20, MaxDurationSec: 100000,
		Validators: []ValidatorKey{{Pubkey: NostrPubkeyHex(vk), Name: "Validator 1", Index: 1}}}
	for _, amt := range []int64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512} {
		a.st.Params.Keys[fmt.Sprint(amt)] = hexCompressedGroupKey(m)
	}
	a.st.Height, a.st.Time = 10, tNow

	seller := newBidder(t)
	c := CreateContent{Title: "e2e lot", StartPrice: 100, MinIncrement: 10, DurationSec: 100, SellerWallet: seller.wallet, Mode: "fixed"}
	createEv := createEv(t, seller.sk, "lot-e2e", c, tNow)
	createTx, _ := json.Marshal(createEv)
	coord := coordOf(seller.pub, "lot-e2e")
	if res := finalize(t, a, 1, tNow, createTx); res.TxResults[0].Code != 0 {
		t.Fatalf("create refused: %s", res.TxResults[0].Log)
	}
	bob := newBidder(t)
	bidEv, bidTx := m.bidTx(t, a, bob, coord, 200, "e2e")
	if res := finalize(t, a, 2, tNow+1, bidTx); res.TxResults[0].Code != 0 {
		t.Fatalf("bid refused: %s", res.TxResults[0].Log)
	}
	finalize(t, a, 3, tNow+101) // the block that decides the auction (winner)
	if au := a.st.Auctions[coord]; au == nil || au.Status != "closed" || au.Winner != bidEv.ID {
		t.Fatalf("lot must be closed with the bid as winner: %+v", au)
	}
	roster := a.st.Params.Roster()
	const decidedHeight = 3

	// --- the relay-only READER, attached before anything is published. ----
	reader, err := DialRelay(ctx, url)
	if err != nil {
		t.Fatalf("dial reader: %v", err)
	}
	defer reader.Close()
	events, cancelSub, err := reader.Subscribe(ctx, RelayFilter{Kinds: []int{KindCreate, KindBid, KindOutcome, KindStateCommit}})
	if err != nil {
		t.Fatalf("subscribe reader: %v", err)
	}
	defer cancelSub()

	var mu sync.Mutex
	var seen []*Event
	go func() {
		for ev := range events {
			mu.Lock()
			seen = append(seen, ev)
			mu.Unlock()
		}
	}()
	collected := func() []*Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*Event(nil), seen...)
	}

	// --- the CLIENT publishes a create and a bid to the relay. ------------
	client, err := DialRelay(ctx, url)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()
	if err := client.Publish(ctx, createEv); err != nil {
		t.Fatalf("publish create: %v", err)
	}
	if err := client.Publish(ctx, bidEv); err != nil {
		t.Fatalf("publish bid: %v", err)
	}

	// --- the validator publishes, anchored to committed height 3. ---------
	validator, err := DialRelay(ctx, url)
	if err != nil {
		t.Fatalf("dial validator: %v", err)
	}
	defer validator.Close()
	pub, err := NewPublisher(PublisherConfig{
		Key: vk, Relay: validator, App: a, Every: 1,
		BlockHash: func(height int64) (string, bool) { return testBlockHash(height), true },
	})
	if err != nil {
		t.Fatal(err)
	}
	pub.Step(ctx)

	wantHash := testBlockHash(decidedHeight)

	// The reader now waits for the verdict to arrive ON THE RELAY.
	verdictFor := func() *Event {
		for _, ev := range collected() {
			if ev.Kind == KindOutcome {
				if id, ok := tagValue(ev.Tags, "auction"); ok && id == coord {
					return ev
				}
			}
		}
		return nil
	}
	waitForRelay(t, 10*time.Second, func() bool { return verdictFor() != nil },
		"a verdict event to appear on the relay")

	ev := verdictFor()
	if err := ev.Verify(); err != nil {
		t.Fatalf("relayed verdict has an invalid signature/id: %v", err)
	}
	if _, ok := roster[ev.Pubkey]; !ok {
		t.Fatalf("verdict signed by %s, which is not on the roster", ev.Pubkey)
	}
	if ev.Pubkey != NostrPubkeyHex(vk) {
		t.Fatalf("verdict signed by %s, want the validator's roster key %s", ev.Pubkey, NostrPubkeyHex(vk))
	}
	if got := tagOf(t, ev, "height"); got != fmt.Sprint(decidedHeight) {
		t.Fatalf("relayed verdict height tag = %q, want the committed height %d", got, decidedHeight)
	}
	if got := tagOf(t, ev, "hash"); got != wantHash {
		t.Fatalf("relayed verdict hash tag = %q, want the committed block hash %s", got, wantHash)
	}

	// The state commitment (kind 1447) reaches the relay too.
	commitFor := func() *Event {
		for _, e := range collected() {
			if e.Kind == KindStateCommit {
				return e
			}
		}
		return nil
	}
	waitForRelay(t, 10*time.Second, func() bool { return commitFor() != nil }, "a state commitment on the relay")
	if _, err := ParseStateCommitment(commitFor(), roster); err != nil {
		t.Fatalf("relayed state commitment must parse and roster-check: %v", err)
	}

	// RECONSTRUCT THE OUTCOME FROM THE RELAY ALONE.  Everything fed to
	// ResolveOutcome came off the reader's subscription; there is no node call,
	// no /api/state, no validator RPC anywhere on this path.
	outcome, ok := ResolveOutcome(coord, collected(), roster)
	if !ok {
		t.Fatal("a relay-only client must reconstruct the outcome")
	}
	if outcome.Outcome != OutcomeWinner || outcome.BidID != bidEv.ID {
		t.Fatalf("relay-only reconstruction wrong: %+v (want winner %s)", outcome, bidEv.ID)
	}
	if outcome.Height != decidedHeight || outcome.BlockHash != wantHash {
		t.Fatalf("relay-only reconstruction anchor wrong: height=%d hash=%s (want %d/%s)",
			outcome.Height, outcome.BlockHash, decidedHeight, wantHash)
	}
	if len(outcome.Signers) != 1 || outcome.Signers[0] != NostrPubkeyHex(vk) {
		t.Fatalf("relay-only reconstruction signers = %v, want the one roster validator", outcome.Signers)
	}
}
