package main

// Regression tests for the internal security audit (docs/SECURITY_AUDIT_2026-11-10.md).

import (
	"encoding/json"
	"strings"
	"testing"
)

var (
	tG = "02" + strings.Repeat("11", 32)
	tW = "02" + strings.Repeat("33", 32)
)

func auditState() *State { return &State{Params: Params{GroupKey: tG, LockMarginSec: 30}} }

const goodLock = `["P2PK",{"nonce":"aa","data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"],["sigflag","SIG_ALL"]]}]`

func TestA1GoodLockAccepted(t *testing.T) {
	if _, err := auditState().checkLock([]Proof{{Secret: goodLock}}, tW, 1000); err != nil {
		t.Fatalf("valid lock rejected: %v", err)
	}
}

// A1: each of these was read one way by the validators and another way by
// the mint (Nutshell). All must now be refused.
func TestA1ParserDifferentialsRejected(t *testing.T) {
	cases := map[string]string{
		"case-variant data key": `["P2PK",{"nonce":"aa","data":"032222222222222222222222222222222222222222222222222222222222222222","Data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"],["sigflag","SIG_ALL"]]}]`,
		"case-variant tags key": `["P2PK",{"nonce":"aa","data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["locktime","1"],["refund","023333333333333333333333333333333333333333333333333333333333333333"]],"Tags":[["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"],["sigflag","SIG_ALL"]]}]`,
		"duplicate locktime":    `["P2PK",{"nonce":"aa","data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["locktime","1"],["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"],["sigflag","SIG_ALL"]]}]`,
		"duplicate sigflag":     `["P2PK",{"nonce":"aa","data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["sigflag","SIG_INPUTS"],["sigflag","SIG_ALL"],["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"]]}]`,
		"duplicate data key":    `["P2PK",{"nonce":"aa","data":"032222222222222222222222222222222222222222222222222222222222222222","data":"021111111111111111111111111111111111111111111111111111111111111111","tags":[["locktime","9999999999"],["refund","023333333333333333333333333333333333333333333333333333333333333333"],["sigflag","SIG_ALL"]]}]`,
		"escaped string":        strings.Replace(goodLock, `"SIG_ALL"`, `"SIG\u005fALL"`, 1),
		"unknown key":           strings.Replace(goodLock, `"nonce":"aa"`, `"nonce":"aa","extra":1`, 1),
		"two-value locktime":    strings.Replace(goodLock, `["locktime","9999999999"]`, `["locktime","9999999999","1"]`, 1),
		"padded locktime":       strings.Replace(goodLock, `"9999999999"`, `"09999999999"`, 1),
		"uppercase data":        strings.Replace(goodLock, `"data":"0211`, `"data":"02AA`, 1),
		"missing sigflag":       strings.Replace(goodLock, `,["sigflag","SIG_ALL"]`, ``, 1),
		"missing refund":        strings.Replace(goodLock, `,["refund","023333333333333333333333333333333333333333333333333333333333333333"]`, ``, 1),
		"pubkeys tag":           strings.Replace(goodLock, `["sigflag","SIG_ALL"]`, `["sigflag","SIG_ALL"],["pubkeys","023333333333333333333333333333333333333333333333333333333333333333"]`, 1),
		"trailing data":         goodLock + ` []`,
		"invalid utf8":          strings.Replace(goodLock, `"aa"`, "\"a\xff\"", 1),
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
