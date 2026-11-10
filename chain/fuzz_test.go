package main

// Fuzz targets for the consensus parsers: none may panic on any input.
// Run: go test -run XXX -fuzz FuzzParseP2PK -fuzztime 60s .

import (
	"encoding/json"
	"testing"
)

func FuzzParseP2PK(f *testing.F) {
	f.Add(`["P2PK",{"nonce":"aa","data":"02aa","tags":[["locktime","1"],["refund","02"],["sigflag","SIG_ALL"]]}]`)
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseP2PK(s); _, _ = proofY(s) })
}

func FuzzDecodeTx(f *testing.F) {
	f.Add([]byte(`{"id":"00","pubkey":"00","created_at":1,"kind":1441,"tags":[],"content":"{}","sig":"00"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decodeTx(b) })
}

func FuzzApplyContent(f *testing.F) {
	f.Add(`{"auction":"a","amount":5,"wallet":"02","proofs":[{"id":"00","amount":1,"secret":"x","C":"02","dleq":{"e":"00","s":"00","r":"00"}}]}`)
	f.Add(`{"title":"t","startPrice":1,"minIncrement":1,"durationSec":60,"sellerWallet":"02"}`)
	f.Fuzz(func(t *testing.T, c string) {
		s := newState()
		s.Params = Params{GroupKey: "02" + repeat("11", 32), KeysetID: "00", Keys: map[string]string{"1": "02" + repeat("11", 32)}, MaxProofs: 64, MinDurationSec: 20, MaxDurationSec: 7200}
		_ = s.applyCreate(&Event{ID: "a", Pubkey: "p", Kind: KindCreate, Content: c}, 100, 1, true)
		_ = s.applyBid(&Event{ID: "b", Pubkey: "q", Kind: KindBid, Content: c}, 101, 2, true, true)
		var p Proof
		if json.Unmarshal([]byte(c), &p) == nil {
			_ = verifyDLEQ(p, nil)
		}
	})
}

func repeat(s string, n int) string {
	o := ""
	for i := 0; i < n; i++ {
		o += s
	}
	return o
}
