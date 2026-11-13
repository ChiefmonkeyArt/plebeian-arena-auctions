package main

// The NUT-11 2-of-2 [bidder, committee] SIG_ALL escrow lock, the bidder's
// pre-signed outcome templates, and the strict parser for both.
//
// Why this file exists. Before this change a bid locked its proofs to the
// validators' FROST group key alone (one key, n_sigs=1) and the settlement
// DESTINATION was enforced only by releasePolicy in each validator -- code,
// not cryptography. The escrow's destination therefore lived in a validator's
// runtime behaviour, so a colluding majority could redirect it.
//
// This moves the constraint into the mint's spending condition:
//
//	["P2PK",{"nonce":<32B hex>,"data":<bidder compressed>,"tags":[
//	    ["locktime",<n>],["pubkeys",<committee compressed>],["n_sigs","2"],
//	    ["refund",<bidder compressed>],["sigflag","SIG_ALL"]]}]
//
// Exactly two signatures may move it: the bidder's and the committee's (the
// FROST group key, a single point). The bidder additionally publishes, inside
// the committed bid content, the two exact transactions it PRE-SIGNS -- settle
// to the auction's committed seller payout key, refund to its own wallet key.
// Every validator re-derives each template's digest and re-checks the
// bidder's signature at admission, so the chain verifies at admission the
// only two spends the money may ever make.
//
// What the lock guarantees, and what it does not (stated accurately; the
// independent evaluation is summarised in the spec's section 1.3). The mint
// has no concept of "seller" or "bidder": a SIG_ALL signature commits only to
// concat(input secret||C) then concat(str(amount)||B_). The "exactly two
// destinations" property is delivered by (a) the bidder honestly pre-signing
// exactly these two templates and (b) this consensus admission rule refusing
// any template not locked to the committed seller/bidder keys -- NOT by the
// mint. What the lock DOES guarantee is that the committee ALONE cannot move
// the money: it cannot forge the bidder's half (Schnorr is message-bound; no
// combine, no reuse). Honest residual: a colluding bidder+committee can send
// the escrow anywhere, and the chain cannot stop it because the spend happens
// at the mint. That is acceptable here: the seller never had custody, and the
// templates are PUBLIC, so a seller can verify the committed destinations
// before shipping (verify-then-ship). Not preventable; provable.
//
// The digest convention is unchanged: layout B, the current Cashu spec form
// (NUT-11 "Message aggregation for SIG_ALL", pinned by cashubtc/nuts PR #302
// on 2025-11-15) and what Nutshell >= 0.20.3 signs. It is implemented once
// here, and the browser client mirrors it (web/src/lib/arena.js).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

// sigAllMessageInput is one proof's bound fields for the SIG_ALL message.
type sigAllMessageInput struct {
	Secret string
	C      string
}

// sigAllMessageOutput is one blinded output's bound fields for the SIG_ALL
// message: its amount (decimal string) and the blinded point B_ it will sign.
type sigAllMessageOutput struct {
	Amount  int64
	Blinded string
}

// sigAllDigest is the CURRENT Cashu NUT-11 SIG_ALL message (layout B, spec
// PR #302): for every input, its secret then its C; then for every output, its
// amount as a decimal string then its blinded point B_. Hashed once with
// sha256, exactly as Nutshell 0.21's sigall_message_to_sign does.
func sigAllDigest(inputs []sigAllMessageInput, outputs []sigAllMessageOutput) [32]byte {
	h := sha256.New()
	for _, in := range inputs {
		h.Write([]byte(in.Secret))
		h.Write([]byte(in.C))
	}
	for _, out := range outputs {
		h.Write([]byte(strconv.FormatInt(out.Amount, 10)))
		h.Write([]byte(out.Blinded))
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// The frozen cross-language golden vector. It pins LAYOUT B. Keep byte-for-byte
// aligned with web/src/lib/arena.js (SIGALL golden constants) and with the
// Go<->TS test; a change to this digest means the wallet and the validators
// disagree with the mint, and the mint stops accepting the bids -- so the
// vector must be recomputed only deliberately, never incidentally.
var sigAllGoldenInputs = []sigAllMessageInput{
	{Secret: "sigall-golden-secret-0001", C: "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
	{Secret: "sigall-golden-secret-0002", C: "03dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
}

var sigAllGoldenOutputs = []sigAllMessageOutput{
	{Amount: 1, Blinded: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{Amount: 2, Blinded: "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
}

const sigAllGoldenDigest = "d3403843d4f3ead4a341f02476b14f140699d346054435fd38d27c294130bec3"

// sigAllGoldenOutputPoint pins the B_ = hash_to_curve(secret) + r*G derivation
// for the shared vector (secret with tags [[sigflag,SIG_INPUTS]], r = 11*32),
// so the Go coordinator recomputes the exact point the browser wallet signed.
const sigAllGoldenOutputPoint = "0336bf38b85ee80f36950f9a05f22c0f36576118dcb30b5300b5a9f73bd41af17e"

// sigAllGoldenTagSet pins, as BYTES, the exact tag set the browser wallet's
// cashu-ts (5.0.0-rc.4, and the wallet's pinned 4.13.0) emits for the 2-of-2
// lock. This settles the "five tags or six" question empirically: cashu-ts
// emits ["n_sigs_refund", ...] ONLY when requiredRefundSignatures > 1, and the
// wallet sets exactly 1, so the canonical form is FIVE tags, in this order.
// A regression here is a lock that the mint admits and the validators refuse
// (or vice versa), so it is pinned as a literal byte string.
const sigAllGoldenTagSet = `[["locktime","1800000000"],["pubkeys","` +
	"022222222222222222222222222222222222222222222222222222222222222222" +
	`"],["n_sigs","2"],["refund","` +
	"021111111111111111111111111111111111111111111111111111111111111111" +
	`"],["sigflag","SIG_ALL"]]`

// sigAllOutputPoint computes B_ = hash_to_curve(secret) + r*G for one output,
// exactly the point the mint signs and the committee submits.
func sigAllOutputPoint(secret, rHex string) (string, error) {
	if !validLowerHex(rHex, 32) {
		return "", errors.New("template output blinding factor is not 32 bytes of lowercase hex")
	}
	Y, err := hashToCurve([]byte(secret))
	if err != nil {
		return "", err
	}
	var r btcec.ModNScalar
	if overflow := r.SetByteSlice(mustHex(rHex)); overflow {
		return "", errors.New("template output blinding factor is not a valid scalar")
	}
	B := add(Y, mulG(&r))
	return hex.EncodeToString(B.SerializeCompressed()), nil
}

// sigAllTemplateInput is one locked proof offered for an outcome. It carries
// the proof secret and C, which are the committed bid's own proofs.
type sigAllTemplateInput struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	Secret string `json:"secret"`
	C      string `json:"C"`
}

// sigAllTemplateOutput is one fresh proof the outcome creates. It carries the
// opening (secret + blinding r) so the committee can submit the exact output
// the bidder authorized without ever choosing a destination itself.
type sigAllTemplateOutput struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	Secret string `json:"secret"`
	R      string `json:"r"`
}

// sigAllSignedTemplate is a template plus the bidder's signature over its
// SIG_ALL digest.
type sigAllSignedTemplate struct {
	Inputs          []sigAllTemplateInput  `json:"inputs"`
	Outputs         []sigAllTemplateOutput `json:"outputs"`
	Digest          string                 `json:"digest"`
	BidderSignature string                 `json:"bidder_signature"`
}

// sigAllOutcomeTemplates is the two outcome templates the bidder pre-signs:
// settle (pay the auction's committed seller key) and refund (return to the
// bidder's own wallet spend key).
type sigAllOutcomeTemplates struct {
	Settle sigAllSignedTemplate `json:"settle"`
	Refund sigAllSignedTemplate `json:"refund"`
}

// sigAllTemplateNamed returns the committed template for an outcome name, or
// an error for any other name. There are exactly two outcomes, and only the
// two the bidder pre-signed.
func sigAllTemplateNamed(t *sigAllOutcomeTemplates, outcome string) (sigAllSignedTemplate, error) {
	if t == nil {
		return sigAllSignedTemplate{}, errors.New("bid publishes no outcome templates")
	}
	switch outcome {
	case "settle":
		return t.Settle, nil
	case "refund":
		return t.Refund, nil
	}
	return sigAllSignedTemplate{}, errors.New("outcome must be settle or refund")
}

// sigAllTemplateDigest computes the (layout B) digest of one exact template.
func sigAllTemplateDigest(template sigAllSignedTemplate) (string, error) {
	inputs := make([]sigAllMessageInput, 0, len(template.Inputs))
	for index, in := range template.Inputs {
		if in.Secret == "" || len(in.Secret) > 4096 {
			return "", fmt.Errorf("template input %d has an invalid secret", index)
		}
		if in.C == "" {
			return "", fmt.Errorf("template input %d has no C point", index)
		}
		inputs = append(inputs, sigAllMessageInput{Secret: in.Secret, C: in.C})
	}
	outputs := make([]sigAllMessageOutput, 0, len(template.Outputs))
	for index, out := range template.Outputs {
		if out.Secret == "" || len(out.Secret) > 4096 {
			return "", fmt.Errorf("template output %d has an invalid secret", index)
		}
		point, err := sigAllOutputPoint(out.Secret, out.R)
		if err != nil {
			return "", fmt.Errorf("template output %d: %w", index, err)
		}
		outputs = append(outputs, sigAllMessageOutput{Amount: out.Amount, Blinded: point})
	}
	d := sigAllDigest(inputs, outputs)
	return hex.EncodeToString(d[:]), nil
}

// sigAllTemplateSignOutputs turns a committed template into the SignOutput
// list the FROST message is built from, recomputing each output's B_ from the
// committed secret and opening. The committee never supplies an output: it
// signs exactly what the bidder committed.
func sigAllTemplateSignOutputs(template sigAllSignedTemplate) ([]SignOutput, error) {
	outs := make([]SignOutput, 0, len(template.Outputs))
	for index, out := range template.Outputs {
		point, err := sigAllOutputPoint(out.Secret, out.R)
		if err != nil {
			return nil, fmt.Errorf("template output %d: %w", index, err)
		}
		outs = append(outs, SignOutput{Amount: out.Amount, ID: out.ID, B: point})
	}
	return outs, nil
}

// sigAllP2PKCondition is the NUT-10 P2PK body of an output secret.
type sigAllP2PKCondition struct {
	Nonce string     `json:"nonce"`
	Data  string     `json:"data"`
	Tags  [][]string `json:"tags"`
}

// sigAllOutputRecipient reads the destination key a template output is locked
// to. The committee never chooses this; the bidder built it.
func sigAllOutputRecipient(secret string) (string, error) {
	var decoded []json.RawMessage
	if err := json.Unmarshal([]byte(secret), &decoded); err != nil || len(decoded) != 2 {
		return "", errors.New("template output secret is not a NUT-10 P2PK condition")
	}
	var kind string
	if err := json.Unmarshal(decoded[0], &kind); err != nil || kind != "P2PK" {
		return "", errors.New("template output secret is not a NUT-10 P2PK condition")
	}
	var condition sigAllP2PKCondition
	if err := json.Unmarshal(decoded[1], &condition); err != nil {
		return "", errors.New("template output secret is not a NUT-10 P2PK condition")
	}
	if !isCompressedPub(condition.Data) {
		return "", errors.New("template output is not locked to a compressed secp256k1 key")
	}
	return condition.Data, nil
}

// sigAllOutputIsEscrowRelock reports whether a template output re-locks the
// escrow to the committee key. Such an output is FORBIDDEN: it hands the
// committee a spendable output, so the committee would then need no bidder
// signature at all -- worse than not having the 2-of-2 lock (spec section 4).
// It is refused by name, not merely as "a wrong destination", so the reason is
// unambiguous in a validator's rejection log.
func sigAllOutputIsEscrowRelock(secret, committeeKey string) bool {
	var decoded []json.RawMessage
	if err := json.Unmarshal([]byte(secret), &decoded); err != nil || len(decoded) != 2 {
		return false
	}
	var kind string
	if err := json.Unmarshal(decoded[0], &kind); err != nil || kind != "P2PK" {
		return false
	}
	var condition sigAllP2PKCondition
	if err := json.Unmarshal(decoded[1], &condition); err != nil {
		return false
	}
	dataX, err1 := xOnlyOf(condition.Data)
	committeeX, err2 := xOnlyOf(committeeKey)
	return err1 == nil && err2 == nil && dataX == committeeX
}

// verifySigAllBidderSignature checks a bidder's BIP-340 signature over a
// template digest against the wallet spend key that owns the lock.
func verifySigAllBidderSignature(spendPublicKey, digestHex, signatureHex string) error {
	if !isCompressedPub(spendPublicKey) {
		return errors.New("template wallet spend key is not a valid compressed secp256k1 point")
	}
	if !validLowerHex(digestHex, 32) {
		return errors.New("template digest is not a 32-byte hex string")
	}
	if !validLowerHex(signatureHex, 64) {
		return errors.New("template signature is not a 64-byte hex Schnorr signature")
	}
	if !schnorrVerifyHash(mustHex(digestHex), spendPublicKey, signatureHex) {
		return errors.New("bidder signature does not verify over the template digest")
	}
	return nil
}

// verifySigAllBidTemplates is the CONSENSUS admission rule for a bid's
// committed outcome templates, run inside applyBid so every validator agrees.
// It refuses, naming the rule, when:
//
//	(a) the bid publishes no outcome_templates at all;
//	(b) either template's inputs are not exactly the bid's committed proof
//	    secrets, in the same order (the SIG_ALL inputs ARE the committed proofs);
//	(c) either template's outputs do not sum to the bid's amount, or name a
//	    keyset other than the pinned keyset_id;
//	(d) the settle outputs are not all locked to the auction's committed seller
//	    payout key;
//	(e) the refund outputs are not all locked to the bidder's wallet spend key;
//	(f) either template's stored digest is not the one its inputs and outputs
//	    derive;
//	(g) either bidder signature does not verify over that digest.
//
// An output that re-locks the escrow to the committee key is refused FIRST and
// by name: it is forbidden outright (spec section 4), not merely a wrong
// destination, because it would leave the committee able to spend alone.
func verifySigAllBidTemplates(au *Auction, content *BidContent, params Params) error {
	if content.OutcomeTemplates == nil {
		return errors.New("sigall bid must publish outcome_templates carrying the bidder's pre-signed settle and refund templates")
	}
	if len(content.Proofs) == 0 {
		return errors.New("sigall bid publishes outcome_templates but carries no proofs for them to spend")
	}
	if params.KeysetID == "" {
		return errors.New("sigall bid: the network pinned no mint keyset for the templates' outputs")
	}
	if !isCompressedPub(au.SellerWallet) {
		return errors.New("sigall bid: the auction committed no seller payout key for the settle template")
	}
	if !isCompressedPub(content.Wallet) {
		return errors.New("sigall bid: the bid committed no wallet spend key for the refund template")
	}
	entries := []struct {
		name     string
		template sigAllSignedTemplate
		dest     string
	}{
		{"settle", content.OutcomeTemplates.Settle, au.SellerWallet},
		{"refund", content.OutcomeTemplates.Refund, content.Wallet},
	}
	for _, e := range entries {
		template := e.template
		// (b) The inputs are the committed proofs, same secrets, same order.
		if len(template.Inputs) != len(content.Proofs) {
			return fmt.Errorf("sigall %s template has %d inputs but the bid carries %d proofs", e.name, len(template.Inputs), len(content.Proofs))
		}
		for index, in := range template.Inputs {
			if in.Secret != content.Proofs[index].Secret {
				return fmt.Errorf("sigall %s template input %d is not the committed proof's secret", e.name, index)
			}
		}
		if len(template.Outputs) == 0 {
			return fmt.Errorf("sigall %s template has no outputs", e.name)
		}
		// (c) conserve the bid's amount and name the pinned keyset.
		var total int64
		for index, out := range template.Outputs {
			if out.Amount <= 0 {
				return fmt.Errorf("sigall %s output %d has no positive amount", e.name, index)
			}
			if out.Amount > (1<<62)-total {
				return fmt.Errorf("sigall %s output amounts overflow", e.name)
			}
			total += out.Amount
			if out.ID != params.KeysetID {
				return fmt.Errorf("sigall %s output %d names keyset %q, not the pinned %q", e.name, index, out.ID, params.KeysetID)
			}
		}
		if total != content.Amount {
			return fmt.Errorf("sigall %s outputs sum to %d, not the bid's amount %d", e.name, total, content.Amount)
		}
		// (d) settle and (e) refund: every output locked to the one committed
		// destination, and never to the committee key (a forbidden re-lock).
		for index, out := range template.Outputs {
			if sigAllOutputIsEscrowRelock(out.Secret, params.GroupKey) {
				return fmt.Errorf("sigall %s output %d re-locks the escrow to the committee key, which is forbidden", e.name, index)
			}
			recipient, err := sigAllOutputRecipient(out.Secret)
			if err != nil {
				return fmt.Errorf("sigall %s output %d: %w", e.name, index, err)
			}
			if strings.ToLower(recipient) != strings.ToLower(e.dest) {
				if e.name == "settle" {
					return fmt.Errorf("sigall settle output %d is not locked to the auction's committed seller payout key", index)
				}
				return fmt.Errorf("sigall refund output %d is not locked to the bid's wallet spend key", index)
			}
		}
		// (f) stored digest must be the one the inputs and outputs derive.
		digest, err := sigAllTemplateDigest(template)
		if err != nil {
			return fmt.Errorf("sigall %s template: %w", e.name, err)
		}
		if template.Digest != digest {
			return fmt.Errorf("sigall %s template digest does not match its inputs and outputs", e.name)
		}
		// (g) the bidder's signature must verify over that digest.
		if err := verifySigAllBidderSignature(content.Wallet, digest, template.BidderSignature); err != nil {
			return fmt.Errorf("sigall %s template: %w", e.name, err)
		}
	}
	return nil
}

// sigAllLockCondition is the NUT-10 P2PK condition body a 2-of-2 SIG_ALL lock
// secret carries.
type sigAllLockCondition struct {
	Nonce string     `json:"nonce"`
	Data  string     `json:"data"`
	Tags  [][]string `json:"tags"`
}

// checkSigAllLock is the strict, differential 2-of-2 SIG_ALL lock parser. It
// accepts EXACTLY the one shape the wallet builds and the mint enforces, and
// refuses every near-miss by name, because a validator and the mint reading
// the same secret differently is the bug class this exists to catch (crafted
// secrets, uppercase hex, duplicated key tags, reordered tags, an extra
// pubkey, n_sigs=1 all read differently to the mint).
//
// The accepted shape, byte for byte:
//
//	["P2PK",{"nonce":<32B hex>,"data":<bidder compressed>,"tags":[
//	    ["locktime","<n>"],["pubkeys",<committee compressed>],["n_sigs","2"],
//	    ["refund",<bidder compressed>],["sigflag","SIG_ALL"]]}]
//
// bidderWallet is the bid's committed wallet key; committeeKey is the
// validators' FROST group key (a single point); minLock already includes the
// settlement safety and the bid-to-consensus latency, and is derived from the
// end THIS bid establishes (spec section 2.1): the caller must resolve the end
// first, so an extending bid is checked against its new end. Keys are compared
// in x-only form, so a compressed value that lifts to the same point is the
// same key regardless of the 0x02 prefix -- that is intentional and matches
// cashu-ts. The tag set is pinned to EXACTLY five tags in canonical order:
// cashu-ts emits ["n_sigs_refund", ...] only when requiredRefundSignatures > 1,
// which the wallet never sets, so a sixth tag is a divergence and is refused.
func checkSigAllLock(proofs []Proof, bidderWallet, committeeKey string, minLock int64) (int64, error) {
	bidderX, err := xOnlyOf(bidderWallet)
	if err != nil {
		return 0, errors.New("lock data must be the bidder wallet key")
	}
	committeeX, err := xOnlyOf(committeeKey)
	if err != nil {
		return 0, errors.New("lock pubkeys must be exactly the committee key")
	}
	var firstTags string
	var lt int64
	for i, pr := range proofs {
		locktime, tags, err := parseOneSigAllLock(pr.Secret, bidderX, committeeX, minLock)
		if err != nil {
			return 0, err
		}
		if i == 0 {
			firstTags, lt = tags, locktime
		} else if tags != firstTags {
			return 0, errors.New("all proofs must share one lock")
		}
	}
	return lt, nil
}

// parseOneSigAllLock validates one proof's secret against the 2-of-2 shape and
// returns its locktime plus a canonical rendering of its tag set (used to
// require all proofs in a bid to share one identical lock).
func parseOneSigAllLock(secret, bidderX, committeeX string, minLock int64) (int64, string, error) {
	var outer []json.RawMessage
	if err := json.Unmarshal([]byte(secret), &outer); err != nil || len(outer) != 2 {
		return 0, "", errors.New("the secret is not a NUT-10 P2PK condition")
	}
	var kind string
	if err := json.Unmarshal(outer[0], &kind); err != nil || kind != "P2PK" {
		return 0, "", errors.New("the secret is not a P2PK condition")
	}
	var condition sigAllLockCondition
	if err := json.Unmarshal(outer[1], &condition); err != nil {
		return 0, "", errors.New("the condition body is malformed")
	}
	// Canonical form: re-marshalling the parsed structure must reproduce the
	// secret byte for byte, so escaped, reordered or whitespace-padded secrets
	// and extra fields can never read differently to the mint.
	canonical, err := json.Marshal([]any{"P2PK", condition})
	if err != nil || string(canonical) != secret {
		return 0, "", errors.New("the secret is not canonical (an escaped or reordered secret reads differently to the mint)")
	}
	if !validLowerHex(condition.Nonce, 32) {
		return 0, "", errors.New("the condition nonce is not 32 bytes of lowercase hex")
	}
	dataX, err := xOnlyOf(condition.Data)
	if err != nil {
		return 0, "", errors.New("lock data must be the bidder wallet key")
	}
	if dataX != bidderX {
		return 0, "", errors.New("lock data must be the bidder wallet key")
	}
	tags := condition.Tags
	if len(tags) != 5 {
		return 0, "", fmt.Errorf("lock carries %d tags, exactly 5 are required", len(tags))
	}
	for _, tag := range tags {
		if len(tag) != 2 {
			return 0, "", errors.New("every tag must have exactly one value")
		}
	}
	if tags[0][0] != "locktime" {
		return 0, "", errors.New("the first tag must be locktime")
	}
	locktime, err := strconv.ParseInt(tags[0][1], 10, 64)
	if err != nil || strconv.FormatInt(locktime, 10) != tags[0][1] {
		return 0, "", errors.New("the locktime tag is not a decimal integer")
	}
	if locktime < minLock {
		return 0, "", fmt.Errorf("locktime below the floor for this lot: %d is under %d", locktime, minLock)
	}
	pubX, err := xOnlyOf(tags[1][1])
	if tags[1][0] != "pubkeys" || err != nil || pubX != committeeX {
		return 0, "", errors.New("lock pubkeys must be exactly the committee key")
	}
	if tags[2][0] != "n_sigs" || tags[2][1] != "2" {
		return 0, "", errors.New("lock n_sigs must be 2")
	}
	refX, err := xOnlyOf(tags[3][1])
	if tags[3][0] != "refund" || err != nil || refX != bidderX {
		return 0, "", errors.New("lock refund must be the bidder wallet key only")
	}
	if tags[4][0] != "sigflag" || tags[4][1] != "SIG_ALL" {
		return 0, "", errors.New("lock must use SIG_ALL")
	}
	tb, _ := json.Marshal(tags)
	return locktime, string(tb), nil
}

// validLowerHex reports whether s is n bytes of lowercase hex.
func validLowerHex(s string, n int) bool { return lowerHex(s, 2*n) }

// xOnlyOf validates a compressed key and returns its x-only (BIP-340) form,
// exactly as cashu-ts's xOnly does: drop the 0x02/0x03 prefix.
func xOnlyOf(compressed string) (string, error) {
	if !isCompressedPub(compressed) {
		return "", errors.New("not a compressed secp256k1 point")
	}
	return compressed[2:], nil
}

// isCompressedPub reports whether s is a 33-byte compressed pubkey with a
// 02/03 prefix that lifts to a point on secp256k1.
func isCompressedPub(s string) bool {
	if len(s) != 66 || !(strings.HasPrefix(s, "02") || strings.HasPrefix(s, "03")) {
		return false
	}
	_, err := parsePub(s)
	return err == nil
}

// mustHex decodes lowercase/uppercase hex, panicking only on programmer error
// (callers validate the hex first).
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustHex: " + err.Error())
	}
	return b
}
