package main

// Tests for the 2-of-2 [bidder, committee] SIG_ALL escrow lock, the bidder's
// pre-signed outcome templates, the canonical tag set, and the locktime
// derivation -- including the check-order amendment (spec §2.2), which is
// load-bearing.

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// --- the frozen cross-language digest + the tag-set finding ----------------

// The golden SIG_ALL digest (layout B) must be byte-identical to what the
// browser client computes (web/src/lib/arena.js). A change here means the
// wallet and the validators disagree with the mint.
func TestSigAllGoldenDigestLayoutB(t *testing.T) {
	d := sigAllDigest(sigAllGoldenInputs, sigAllGoldenOutputs)
	if got := hex.EncodeToString(d[:]); got != sigAllGoldenDigest {
		t.Fatalf("golden digest %s, want %s", got, sigAllGoldenDigest)
	}
}

func TestSigAllGoldenOutputPoint(t *testing.T) {
	secret := `["P2PK",{"nonce":"` + strings.Repeat("00", 16) + `","data":"02` + strings.Repeat("aa", 32) + `","tags":[["sigflag","SIG_INPUTS"]]}]`
	got, err := sigAllOutputPoint(secret, strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	if got != sigAllGoldenOutputPoint {
		t.Fatalf("golden output point %s, want %s", got, sigAllGoldenOutputPoint)
	}
}

// The canonical tag set is EXACTLY five tags, in order, and a sixth
// (n_sigs_refund) is a divergence. cashu-ts emits n_sigs_refund only when
// requiredRefundSignatures > 1, which the wallet never sets.
func TestSigAllCanonicalTagSetIsFiveTags(t *testing.T) {
	tags := [][]string{
		{"locktime", "1800000000"},
		{"pubkeys", "02" + strings.Repeat("22", 32)},
		{"n_sigs", "2"},
		{"refund", "02" + strings.Repeat("11", 32)},
		{"sigflag", "SIG_ALL"},
	}
	b, _ := json.Marshal(tags)
	if string(b) != sigAllGoldenTagSet {
		t.Fatalf("canonical tag set changed:\n got %s\nwant %s", b, sigAllGoldenTagSet)
	}
	if len(tags) != 5 {
		t.Fatalf("canonical lock must carry exactly 5 tags, got %d", len(tags))
	}
	six := append(append([][]string{}, tags...), []string{"n_sigs_refund", "1"})
	b6, _ := json.Marshal(six)
	if string(b6) == sigAllGoldenTagSet {
		t.Fatal("six-tag set must differ from the frozen five-tag set")
	}
}

// --- the lock ---------------------------------------------------------------

func realPub(t *testing.T, scalar uint32) string {
	t.Helper()
	var s btcec.ModNScalar
	s.SetInt(scalar)
	return hex.EncodeToString(mulG(&s).SerializeCompressed())
}

// The canonical 2-of-2 lock is admitted.
func TestSigAllLockTwoOfTwoAdmitted(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	secret := lockForSigAll(committee, bidder, 9999999999, "aa")
	lt, err := checkSigAllLock([]Proof{{Secret: secret}}, bidder, committee, 1000)
	if err != nil {
		t.Fatalf("2-of-2 lock rejected: %v", err)
	}
	if lt != 9999999999 {
		t.Fatalf("locktime %d", lt)
	}
}

// Today's 1-of-1 lock (locked to the group key alone) is refused BY NAME --
// no migration, no fallback (spec §11/§12).
func TestSigAllLockOneOfOneRefusedByName(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	oneOfOne := `["P2PK",{"nonce":"` + strings.Repeat("aa", 32) + `","data":"` + committee + `","tags":[["locktime","9999999999"],["refund","` + bidder + `"],["sigflag","SIG_ALL"]]}]`
	_, err := checkSigAllLock([]Proof{{Secret: oneOfOne}}, bidder, committee, 1000)
	if err == nil || !strings.Contains(err.Error(), "lock data must be the bidder wallet key") {
		t.Fatalf("1-of-1 lock not refused by name: %v", err)
	}
}

// A lock whose n_sigs is 1 (a fake 2-of-2: the bidder alone could then spend)
// is refused by name.
func TestSigAllLockNSigsOneRefusedByName(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	secret := `["P2PK",{"nonce":"` + strings.Repeat("aa", 32) + `","data":"` + bidder + `","tags":[["locktime","9999999999"],["pubkeys","` + committee + `"],["n_sigs","1"],["refund","` + bidder + `"],["sigflag","SIG_ALL"]]}]`
	_, err := checkSigAllLock([]Proof{{Secret: secret}}, bidder, committee, 1000)
	if err == nil || !strings.Contains(err.Error(), "lock n_sigs must be 2") {
		t.Fatalf("n_sigs=1 not refused by name: %v", err)
	}
}

// A lock whose pubkeys is absent (the bidder alone) is refused.
func TestSigAllLockNoPubkeysRefusedByName(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	secret := `["P2PK",{"nonce":"` + strings.Repeat("aa", 32) + `","data":"` + bidder + `","tags":[["locktime","9999999999"],["n_sigs","2"],["refund","` + bidder + `"],["sigflag","SIG_ALL"]]}]`
	if _, err := checkSigAllLock([]Proof{{Secret: secret}}, bidder, committee, 1000); err == nil {
		t.Fatal("a lock without the committee pubkeys must be refused")
	}
}

// A lock whose locktime is under the auction floor is refused by name, because
// the refund branch must not open while the committee is still settling.
func TestSigAllLockLocktimeFloorRefusedByName(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	secret := lockForSigAll(committee, bidder, 1000, "aa") // below a floor of 1015
	_, err := checkSigAllLock([]Proof{{Secret: secret}}, bidder, committee, 1015)
	if err == nil || !strings.Contains(err.Error(), "locktime below the floor for this lot") {
		t.Fatalf("short locktime not refused by name: %v", err)
	}
}

// A sixth tag (n_sigs_refund) is refused by name.
func TestSigAllLockSixTagsRefusedByName(t *testing.T) {
	committee, bidder := realPub(t, 13), realPub(t, 17)
	secret := `["P2PK",{"nonce":"` + strings.Repeat("aa", 32) + `","data":"` + bidder + `","tags":[["locktime","9999999999"],["pubkeys","` + committee + `"],["n_sigs","2"],["refund","` + bidder + `"],["sigflag","SIG_ALL"],["n_sigs_refund","1"]]}]`
	_, err := checkSigAllLock([]Proof{{Secret: secret}}, bidder, committee, 1000)
	if err == nil || !strings.Contains(err.Error(), "6 tags, exactly 5 are required") {
		t.Fatalf("six-tag lock not refused by name: %v", err)
	}
}

// --- the locktime derivation, including the check-order amendment -----------

// The check-order amendment (spec §2.2): an anti-snipe bid that extends the
// end must clear the NEW end by the full settlement safety, not the old end.
// His old code checked BEFORE the extension, which collapsed the margin from
// 900 s to as little as 15 s.
func TestSigAllLocktimeFloorUsesEstablishedEnd(t *testing.T) {
	a, _, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 300, tNow+10
	now := tNow // the bid arrives with 10 s left: it extends the end to now+300
	got := a.st.minLocktime(au, now)
	want := (now + 300) + a.st.Params.SettlementSafetySec + a.st.Params.BidToConsensusLatencySec // = now+1215
	if got != want {
		t.Fatalf("minLocktime %d, want %d (the NEW end + 900 + 15)", got, want)
	}
	// A lock that only clears the OLD end (tNow+10) plus the safety is below
	// the floor: an extending bid that carried it would leave the sale ~300 s
	// short of the safety window.
	shortLock := (au.EndAt) + a.st.Params.SettlementSafetySec + a.st.Params.BidToConsensusLatencySec // now+925
	if shortLock >= got {
		t.Fatalf("the check-order amendment must make the old-end lock insufficient: old-end lock %d, floor %d", shortLock, got)
	}
}

// And the parser refuses such an extending bid by name.
func TestSigAllExtendingBidUnderNewFloorRefused(t *testing.T) {
	a, m, id := liveApp(t)
	au := a.st.Auctions[id]
	au.Mode, au.WindowSec, au.EndAt = "antisnipe", 300, tNow+10
	// Build the bid's lock against the OLD end only, as his pre-amendment code
	// would have accepted.
	alice := newBidder(t)
	oldFloor := au.EndAt + a.st.Params.SettlementSafetySec + a.st.Params.BidToConsensusLatencySec
	var proofs []Proof
	left, i := int64(150), 0
	for d := int64(128); d >= 1; d /= 2 {
		for left >= d {
			proofs = append(proofs, m.sign(t, d, lockForSigAll(a.st.Params.GroupKey, alice.wallet, oldFloor, hex.EncodeToString(append(make([]byte, 30), byte(i), byte(i))))))
			left -= d
			i++
		}
	}
	c, _ := json.Marshal(BidContent{Auction: id, Amount: 150, Wallet: alice.wallet, Name: "t", Proofs: proofs,
		OutcomeTemplates: m.templates(t, alice, au.SellerWallet, proofs)})
	ev := signEvent(t, alice.sk, KindBid, string(c), tNow)
	err := a.st.applyBid(ev, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "locktime below the floor for this lot") {
		t.Fatalf("an extending bid below the new floor was not refused by name: %v", err)
	}
}

// A fixed lot's floor is its own end + safety + latency, irrespective of a
// late block: the end never moves, so the floor is stable.
func TestSigAllFixedLotFloorIsStable(t *testing.T) {
	a, _, id := liveApp(t)
	au := a.st.Auctions[id]
	base := au.EndAt + a.st.Params.SettlementSafetySec + a.st.Params.BidToConsensusLatencySec
	if got := a.st.minLocktime(au, tNow); got != base {
		t.Fatalf("fixed floor at tNow: %d, want %d", got, base)
	}
	if got := a.st.minLocktime(au, tNow+50); got != base {
		t.Fatalf("fixed floor must not grow with the clock: %d, want %d", got, base)
	}
}

// --- the templates ----------------------------------------------------------

// A committed template that names a different destination is refused BY NAME
// at admission -- after its digest and signature are made valid, so the ONLY
// fault is the destination.
func TestSigAllTemplateWrongDestinationRefusedByName(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "ab")
	var c BidContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		t.Fatal(err)
	}
	attacker := realPub(t, 21)
	for i := range c.OutcomeTemplates.Settle.Outputs {
		c.OutcomeTemplates.Settle.Outputs[i].Secret = p2pkOut(attacker, strings.Repeat("ab", 32)[:64])
	}
	d, _ := sigAllTemplateDigest(c.OutcomeTemplates.Settle)
	sig, _ := schnorr.Sign(bob.walletSk, mustHex(d))
	c.OutcomeTemplates.Settle.Digest, c.OutcomeTemplates.Settle.BidderSignature = d, hex.EncodeToString(sig.Serialize())

	err := a.st.applyBid(&Event{ID: hx(88), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "is not locked to the auction's committed seller payout key") {
		t.Fatalf("wrong destination not refused by name: %v", err)
	}
}

// A committed template that RE-LOCKS the escrow to the committee key is
// refused BY NAME: it is forbidden outright (spec §4), because it would hand
// the committee a spendable output and so make the 2-of-2 useless.
func TestSigAllRelockTemplateRefusedByName(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "ba")
	var c BidContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		t.Fatal(err)
	}
	// Point every settle output at the committee group key, then re-sign so
	// the digest and signature are valid: the ONLY fault is the re-lock.
	for i := range c.OutcomeTemplates.Settle.Outputs {
		c.OutcomeTemplates.Settle.Outputs[i].Secret = p2pkOut(a.st.Params.GroupKey, strings.Repeat("cd", 32)[:64])
	}
	d, _ := sigAllTemplateDigest(c.OutcomeTemplates.Settle)
	sig, _ := schnorr.Sign(bob.walletSk, mustHex(d))
	c.OutcomeTemplates.Settle.Digest, c.OutcomeTemplates.Settle.BidderSignature = d, hex.EncodeToString(sig.Serialize())

	err := a.st.applyBid(&Event{ID: hx(92), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "re-locks the escrow to the committee key, which is forbidden") {
		t.Fatalf("group-key re-lock template not refused by name: %v", err)
	}
}

// A committed template that the bidder did not sign is refused.
func TestSigAllTemplateUnsignedRefused(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "ac")
	var c BidContent
	json.Unmarshal([]byte(ev.Content), &c)
	c.OutcomeTemplates.Refund.BidderSignature = strings.Repeat("00", 64)

	err := a.st.applyBid(&Event{ID: hx(89), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "bidder signature does not verify") {
		t.Fatalf("unsigned template not refused by name: %v", err)
	}
}

// A committed template whose inputs are not the bid's committed proofs is
// refused (the SIG_ALL inputs ARE the committed proofs).
func TestSigAllTemplateInputsMustBeCommittedProofs(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "ad")
	var c BidContent
	json.Unmarshal([]byte(ev.Content), &c)
	c.OutcomeTemplates.Settle.Inputs[0].Secret = `["P2PK",{"nonce":"` + strings.Repeat("bb", 32) + `","data":"` + bob.wallet + `","tags":[["sigflag","SIG_ALL"]]}]`

	err := a.st.applyBid(&Event{ID: hx(90), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "is not the committed proof's secret") {
		t.Fatalf("foreign template input not refused by name: %v", err)
	}
}

// A committed template whose digest was tampered with is refused.
func TestSigAllTemplateDigestMismatchRefused(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "bb")
	var c BidContent
	json.Unmarshal([]byte(ev.Content), &c)
	c.OutcomeTemplates.Refund.Digest = strings.Repeat("00", 32)

	err := a.st.applyBid(&Event{ID: hx(93), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "digest does not match its inputs and outputs") {
		t.Fatalf("tampered digest not refused by name: %v", err)
	}
}

// A bid with no templates at all is refused.
func TestSigAllBidWithoutTemplatesRefused(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "ae")
	var c BidContent
	json.Unmarshal([]byte(ev.Content), &c)
	c.OutcomeTemplates = nil
	err := a.st.applyBid(&Event{ID: hx(91), Pubkey: bob.pub, Content: string(must(json.Marshal(c)))}, tNow, 11, true, true)
	if err == nil || !strings.Contains(err.Error(), "must publish outcome_templates") {
		t.Fatalf("template-less bid not refused by name: %v", err)
	}
}

// A good 2-of-2 bid with valid templates is admitted and the templates are
// committed on the Bid.
func TestSigAllBidWithTemplatesAdmitted(t *testing.T) {
	a, m, id := liveApp(t)
	bob := newBidder(t)
	ev, _ := m.bidTx(t, a, bob, id, 150, "af")
	if err := a.st.applyBid(ev, tNow, 11, true, true); err != nil {
		t.Fatalf("valid 2-of-2 bid rejected: %v", err)
	}
	b, ok := a.st.Bids[ev.ID]
	if !ok || b.OutcomeTemplates == nil {
		t.Fatal("the committed bid must carry its outcome templates")
	}
}
