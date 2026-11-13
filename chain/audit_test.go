package main

// Regression tests for the internal security audit (docs/SECURITY_AUDIT_2026-11-10.md).

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	// Real secp256k1 points: the strict 2-of-2 parser compares x-only keys, so
	// a fake hex string is not a key (spec §1.4). tG stands in for the
	// committee (FROST group) key, tW for a bidder's wallet key.
	tG = hex.EncodeToString(mulG(new(btcec.ModNScalar).SetInt(13)).SerializeCompressed())
	tW = hex.EncodeToString(mulG(new(btcec.ModNScalar).SetInt(17)).SerializeCompressed())
)

func auditState() *State {
	return &State{Params: Params{GroupKey: tG, SettlementSafetySec: 900, BidToConsensusLatencySec: 15}}
}

// goodLock is the canonical 2-of-2 [bidder, committee] SIG_ALL lock: data =
// the bidder (tW), pubkeys = [committee] (tG), n_sigs 2, refund = the bidder
// alone, SIG_ALL, five tags in canonical order (spec §1.1).
var goodLock = `["P2PK",{"nonce":"` + strings.Repeat("aa", 32) +
	`","data":"` + tW + `","tags":[["locktime","9999999999"],["pubkeys","` + tG +
	`"],["n_sigs","2"],["refund","` + tW + `"],["sigflag","SIG_ALL"]]}]`

func TestA1GoodLockAccepted(t *testing.T) {
	if _, err := auditState().checkLock([]Proof{{Secret: goodLock}}, tW, 1000); err != nil {
		t.Fatalf("valid lock rejected: %v", err)
	}
}

// A1: each of these was read one way by the validators and another way by
// the mint (Nutshell). All must now be refused by the strict 2-of-2 parser.
func TestA1ParserDifferentialsRejected(t *testing.T) {
	cases := map[string]string{
		"case-variant data key": `["P2PK",{"nonce":"` + repeat("aa", 32) + `","data":"` + tG + `","Data":"` + tW + `","tags":[["locktime","9999999999"],["pubkeys","` + tG + `"],["n_sigs","2"],["refund","` + tW + `"],["sigflag","SIG_ALL"]]}]`,
		"case-variant tags key": `["P2PK",{"nonce":"` + repeat("aa", 32) + `","data":"` + tW + `","tags":[["locktime","1"],["refund","` + tW + `"]],"Tags":[["locktime","9999999999"],["pubkeys","` + tG + `"],["n_sigs","2"],["refund","` + tW + `"],["sigflag","SIG_ALL"]]}]`,
		"duplicate locktime":    strings.Replace(goodLock, `["locktime","9999999999"]`, `["locktime","9999999999"],["locktime","1"]`, 1),
		"duplicate data key":    strings.Replace(goodLock, `"data":`, `"data":"`+tG+`","data":`, 1),
		"escaped string":        strings.Replace(goodLock, `"SIG_ALL"`, `"SIG\u005fALL"`, 1),
		"unknown key":           strings.Replace(goodLock, `"nonce":`, `"extra":1,"nonce":`, 1),
		"two-value locktime":    strings.Replace(goodLock, `["locktime","9999999999"]`, `["locktime","9999999999","1"]`, 1),
		"padded locktime":       strings.Replace(goodLock, `"9999999999"`, `"09999999999"`, 1),
		"uppercase data":        strings.Replace(goodLock, `"data":"`+tW+`"`, `"data":"`+strings.ToUpper(tW)+`"`, 1),
		"missing sigflag":       strings.Replace(goodLock, `,["sigflag","SIG_ALL"]`, ``, 1),
		"missing n_sigs":        strings.Replace(goodLock, `,["n_sigs","2"]`, ``, 1),
		"trailing data":         goodLock + ` []`,
		"invalid utf8":          strings.Replace(goodLock, `"nonce":"aaaa`, "\"nonce\":\"a\xffaa", 1),
	}
	for name, sec := range cases {
		if _, err := auditState().checkLock([]Proof{{Secret: sec}}, tW, 1000); err == nil {
			t.Errorf("%s: accepted, must be rejected", name)
		}
	}
}

// A4: the same event with upper-case hex must not verify.
func TestA4UppercaseHexRejected(t *testing.T) {
	ok := Event{ID: strings.Repeat("ab", 32), Pubkey: strings.Repeat("cd", 32), Sig: strings.Repeat("ef", 64)}
	for _, e := range []Event{
		{ID: strings.ToUpper(ok.ID), Pubkey: ok.Pubkey, Sig: ok.Sig},
		{ID: ok.ID, Pubkey: strings.ToUpper(ok.Pubkey), Sig: ok.Sig},
		{ID: ok.ID, Pubkey: ok.Pubkey, Sig: strings.ToUpper(ok.Sig)},
	} {
		if err := e.Verify(); err == nil || !strings.Contains(err.Error(), "lowercase") {
			t.Errorf("upper-case event not rejected for its case: %v", err)
		}
	}
}

// A5: listing images can only be same-site paths or plain https URLs.
func TestA5ImageValidation(t *testing.T) {
	for _, s := range []string{"", "./assets/lot1.webp", "/assets/x.png", "https://img.example/a.jpg?x=1"} {
		if !safeImage(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{`x" onerror="alert(1)`, "javascript:alert(1)", "//evil/x.png", "./a b.png", "./a'.png", "./<x>.png", "http://x/a.png", "data:image/png;base64,AA"} {
		if safeImage(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// A6: the SIG_ALL message covers each input's C and each output's amount.
func TestA6SigAllMessageCoversAmounts(t *testing.T) {
	m := sigAllMessage([]Proof{{Secret: "s1", C: "c1"}, {Secret: "s2", C: "c2"}}, []SignOutput{{Amount: 8, B: "b1"}, {Amount: 2, B: "b2"}})
	if m != "s1c1s2c2"+"8b1"+"2b2" {
		t.Fatalf("unexpected SIG_ALL message %q", m)
	}
	a := sigAllMessage(nil, []SignOutput{{Amount: 8, B: "b"}})
	b := sigAllMessage(nil, []SignOutput{{Amount: 4, B: "b"}})
	if a == b {
		t.Fatal("amounts not covered")
	}
}

// F8: one escrow cannot hold more than a few signing sessions open.
func TestF8SessionsPerEscrow(t *testing.T) {
	ss := &frostSessions{m: map[string]frostSession{}}
	for i := 0; i < maxSessionsPerRelease; i++ {
		if _, err := ss.put(json.RawMessage(`{}`), "h", "bid1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ss.put(json.RawMessage(`{}`), "h", "bid1"); err == nil {
		t.Fatal("extra session for the same escrow allowed")
	}
	if _, err := ss.put(json.RawMessage(`{}`), "h", "bid2"); err != nil {
		t.Fatalf("other escrow blocked: %v", err)
	}
}
