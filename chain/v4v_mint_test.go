package main

// Real-mint integration test for the V4V split settle (spec §6). It proves the
// one thing the unit tests cannot: that a real Nutshell mint ACCEPTS a 2-of-2
// [bidder, committee] SIG_ALL swap whose outputs are the committed split -- one
// output per recipient plus the seller remainder, each locked to its own key.
//
// It uses the same throwaway mint as sigall_mint_test.go (ARENA_TEST_MINT,
// default http://127.0.0.1:13438) and SKIPS cleanly when none is reachable, so
// `go test ./...` without a mint still passes.
//
// It also does NOT overclaim: the mint enforces only "two signatures over the
// recomputed transaction and the balance" (spec §1.3). It has no concept of a
// v4v recipient. What this test shows is that the multi-destination shape the
// chain requires is a shape the mint will actually spend -- the "must match the
// split" rule itself is the chain's, not the mint's.

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// A 2-of-2 escrow split into three payouts (two v4v recipients + the seller
// remainder) is accepted by a real mint, with both signatures over exactly those
// outputs.
func TestMintAcceptsV4VSplitSettle(t *testing.T) {
	url, id, keys := liveMint(t)
	bidderSk, committeeSk, bidder, committee := newKeys(t)

	plain := mintProof(t, url, id, keys, 64)
	locked, _ := lockProof(t, url, id, keys, plain, bidder, committee, time.Now().Unix()+3600)

	// the committed split, chosen so each row flushes to a mint denomination
	// (the mint keyset is powers of two): floor(64*2500/10000)=16, 16, seller
	// remainder 64-16-16 = 32. Three distinct recipients, three outputs.
	recA, recB := realPub(t, 41), realPub(t, 42)
	amounts := []int64{16, 16, 32}
	recipients := []string{recA, recB, bidder} // third output is the seller; any key works here
	var outs []mintOutput
	var signOuts []SignOutput
	for i := range amounts {
		secret := p2pkOut(recipients[i], hex.EncodeToString(randBytes(t)))
		o, _, err := blind(secret, amounts[i], id)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, o)
		signOuts = append(signOuts, SignOutput{Amount: amounts[i], ID: id, B: o.B})
	}

	digest := sigAllHash(locked, signOuts)
	sigs := []string{signDigest(t, bidderSk, digest), signDigest(t, committeeSk, digest)}
	code, body := sigAllSwap(t, url, locked, outs, sigs)
	if code != 200 || !strings.Contains(body, "signatures") {
		t.Fatalf("mint refused a valid multi-recipient V4V split settle: %d %s", code, body)
	}
}
