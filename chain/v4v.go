package main

// Value-for-value (V4V) payout splits for the auctions protocol (spec §6).
//
// WHAT THIS IS. V4V in the market repo is a seller-configured list of payout
// recipients, each with a share, that a buyer's payment also pays (a NIP-57
// zap-split heritage; see notes/12-v4v-in-market.md). On the market's master it
// is Lightning-only and absent from auctions. The multiparty auction wire
// profile (docs/protocol/auction-multiparty-v1.md) proposes an escrow-committed
// payout schedule with integer basis points and a seller remainder; that
// profile is Proposed and implementation-prohibited as a production wire format,
// but the owner has authorised implementing the SPLIT CONCEPT here (spec §6).
//
// WHAT THIS FILE DOES. It gives an auction create payload an OPTIONAL `v4vSplit`:
// rows {role, recipientPubkey, allocationBps} where role is exactly "validator"
// or "v4v". The split is validated strictly, stored IMMUTABLY on the auction (a
// money field, spec §8), and reproduced EXACTLY by the bidder's pre-signed
// SETTLE template. The chain verifies the template's outputs against the
// committed split at admission (verifySigAllBidTemplates, sigall.go). A REFUND
// template stays bidder-only and MUST NOT pay a V4V row (spec §6).
//
// WHAT THE MINT DOES AND DOES NOT ENFORCE (spec §1.3 — do not overclaim). The
// mint knows NOTHING about V4V. SIG_ALL makes it commit to concat(input
// secret||C) then concat(str(amount)||B_); there is no recipient in the signed
// message and the mint has no concept of seller, validator or v4v recipient. So
// "the money can only reach the committed rows" is delivered by (a) the bidder
// honestly pre-signing a settle template whose outputs ARE the split, and (b)
// this consensus admission rule refusing any template that is not exactly the
// committed split. It is a PROTOCOL rule, not a mint rule. The templates are
// public, so a seller can verify the committed destinations before shipping.
// Not preventable by the mint; provable against the chain's own record.
//
// WHAT IT DELIBERATELY IS NOT. No Lightning zap fan-out, no seller wallet
// automation, no mutable split, no per-product shares, no validator payout
// machinery beyond a plain row. The split is a committed escrow payout schedule.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// v4vTotalBps is the whole. A split allocates at most this much; the seller
// keeps v4vTotalBps - sum(allocationBps). 10000 bps = the entire bid. The
// seller remainder is DERIVED, never stored: seller_remainder_bps =
// 10000 - sum(allocationBps) (spec §6).
const v4vTotalBps = 10000

const (
	roleValidator = "validator" // paid row for a contracted validator (may be 0 bps)
	roleV4V       = "v4v"       // value-for-value recipient (must be > 0 bps)
)

// SplitRow is one row of the optional V4V payout schedule in a create payload.
//
// AllocationBps is a json.Number rather than an int64 so that a NON-INTEGER
// ("12.5") can be refused BY NAME (v4v_split_bps_not_integer) instead of
// collapsing into a generic "bad create content". The value must already be a
// whole number; no normalisation is performed beyond trimming the role and
// lower-casing the recipient.
type SplitRow struct {
	Role            string      `json:"role"`
	RecipientPubkey string      `json:"recipientPubkey"`
	AllocationBps   json.Number `json:"allocationBps"`
}

// CommittedSplitRow is a validated split row as stored immutably on the auction.
// AllocationBps is an integer basis-point share.
type CommittedSplitRow struct {
	Role            string `json:"role"`
	RecipientPubkey string `json:"recipientPubkey"`
	AllocationBps   int64  `json:"allocationBps"`
}

// roleRank fixes the canonical order: every validator row before every v4v row
// (the multiparty profile's "order validator < v4v"). This is what "same order"
// means when the settle template is checked against the committed split.
func roleRank(role string) int {
	if role == roleValidator {
		return 0
	}
	return 1
}

// parseBps reads an integer basis-point count from a JSON number literal. It
// returns an error for anything that is not a whole non-negative integer
// (fractions, exponent notation, empty). A leading minus is accepted here so a
// negative value is reported as OUT OF RANGE (v4v_split_bps_out_of_range), not
// as a malformed integer -- the two are different mistakes and are named
// differently so a rejection is diagnosable.
func parseBps(n json.Number) (int64, error) {
	s := n.String()
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	if s == "" {
		return 0, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a whole number")
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if neg {
		v = -v
	}
	return v, nil
}

// validateV4VSplit strictly validates a create payload's split and returns its
// canonical (normalised, ordered) form, or a NAMED error. Rules, each with its
// own error name so a refusal is diagnosable (spec §6):
//
//   - role set is exactly {validator, v4v}                   v4v_split_role_unknown
//   - recipient is a compressed secp256k1 payout key         v4v_split_recipient_invalid
//   - allocationBps is a whole number                        v4v_split_bps_not_integer
//   - validator bps in 0..10000, v4v bps in 1..10000         v4v_split_bps_out_of_range
//   - recipient pubkeys are globally unique across rows      v4v_split_duplicate_recipient
//   - sum(allocationBps) <= 10000                            v4v_split_total_exceeds_10000
//
// An empty (or absent) split is allowed and means "no split": the auction is a
// plain seller-only escrow. The seller remainder is derived; it is 0 exactly
// when sum == 10000.
func validateV4VSplit(rows []SplitRow) ([]CommittedSplitRow, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	out := make([]CommittedSplitRow, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	var total int64
	for i, r := range rows {
		role := strings.TrimSpace(r.Role)
		if role != roleValidator && role != roleV4V {
			return nil, fmt.Errorf("v4v_split_role_unknown: row %d role %q is not %q or %q", i, r.Role, roleValidator, roleV4V)
		}
		pk := strings.ToLower(strings.TrimSpace(r.RecipientPubkey))
		if !isCompressedPub(pk) {
			return nil, fmt.Errorf("v4v_split_recipient_invalid: row %d recipient is not a compressed secp256k1 key", i)
		}
		if seen[pk] {
			return nil, fmt.Errorf("v4v_split_duplicate_recipient: %s appears in more than one row (recipient pubkeys are globally unique)", pk)
		}
		seen[pk] = true
		bps, err := parseBps(r.AllocationBps)
		if err != nil {
			return nil, fmt.Errorf("v4v_split_bps_not_integer: row %d allocationBps %q is not a whole number", i, r.AllocationBps.String())
		}
		if bps < 0 || bps > v4vTotalBps || (role == roleV4V && bps == 0) {
			return nil, fmt.Errorf("v4v_split_bps_out_of_range: row %d allocationBps %d (validator 0..10000, v4v 1..10000)", i, bps)
		}
		total += bps
		out = append(out, CommittedSplitRow{Role: role, RecipientPubkey: pk, AllocationBps: bps})
	}
	if total > v4vTotalBps {
		return nil, fmt.Errorf("v4v_split_total_exceeds_10000: %d basis points allocated", total)
	}
	// Canonical order: role (validator < v4v), then recipient pubkey bytes. The
	// committed order is what the settle template must reproduce.
	sort.SliceStable(out, func(i, j int) bool {
		if roleRank(out[i].Role) != roleRank(out[j].Role) {
			return roleRank(out[i].Role) < roleRank(out[j].Role)
		}
		return out[i].RecipientPubkey < out[j].RecipientPubkey
	})
	return out, nil
}

// splitOut is one payout the committed split requires for a given bid amount.
type splitOut struct {
	Recipient string
	Amount    int64
}

// splitSats is the ROUNDING RULE, in one place (spec §6).
//
// Each auxiliary row gets floor(amount * allocationBps / 10000). The seller
// remainder is amount - sum(auxiliary rows): the rounding dust, always >= 0,
// always paid to the seller. The outputs therefore sum to the bid amount
// EXACTLY -- no sat is created or lost.
//
// When the split allocates all 10000 bps and the floors happen to sum to the
// whole bid, the remainder is 0 and NO seller output exists; otherwise a seller
// output exists. A row whose floor is 0 sats cannot be a positive escrow output,
// so the settle check refuses such a bid by name rather than paying the
// recipient nothing.
func splitSats(sellerWallet string, split []CommittedSplitRow, amount int64) []splitOut {
	seller := strings.ToLower(sellerWallet)
	if len(split) == 0 {
		return []splitOut{{Recipient: seller, Amount: amount}}
	}
	out := make([]splitOut, 0, len(split)+1)
	var allocated int64
	for _, row := range split {
		share := amount * row.AllocationBps / v4vTotalBps
		allocated += share
		out = append(out, splitOut{Recipient: row.RecipientPubkey, Amount: share})
	}
	if rem := amount - allocated; rem > 0 {
		out = append(out, splitOut{Recipient: seller, Amount: rem})
	}
	return out
}

// isSplitRecipient reports whether pubkey is one of the committed split rows.
// Used to refuse a REFUND template that pays a V4V/validator row (spec §6).
func isSplitRecipient(au *Auction, pubkey string) bool {
	for _, row := range au.V4VSplit {
		if sameKey(row.RecipientPubkey, pubkey) {
			return true
		}
	}
	return false
}

// settleMatchesSplit is the CONSENSUS check that a bid's pre-signed SETTLE
// template pays EXACTLY the committed split, in order: one output per committed
// row (same recipient, same amount) plus the seller remainder output when the
// remainder is positive. It refuses, naming the rule, a template that omits a
// row, adds an uncommitted output, reorders rows, reprices a row, names a
// different keyset, or cannot represent a row without loss.
func settleMatchesSplit(au *Auction, amount int64, template sigAllSignedTemplate, keysetID string) error {
	for _, row := range au.V4VSplit {
		if amount*row.AllocationBps/v4vTotalBps == 0 {
			return fmt.Errorf("sigall settle template cannot represent the committed v4v split without loss: the %s row rounds to 0 sats at a %d sat bid", row.Role, amount)
		}
	}
	expected := splitSats(au.SellerWallet, au.V4VSplit, amount)
	switch {
	case len(template.Outputs) < len(expected):
		return errors.New("sigall settle template omits a committed v4v split output")
	case len(template.Outputs) > len(expected):
		return errors.New("sigall settle template adds an output that is not in the committed v4v split")
	}
	for i, out := range template.Outputs {
		if out.Amount <= 0 {
			return fmt.Errorf("sigall settle output %d has no positive amount", i)
		}
		if out.ID != keysetID {
			return fmt.Errorf("sigall settle output %d names keyset %q, not the pinned %q", i, out.ID, keysetID)
		}
		recipient, err := sigAllOutputRecipient(out.Secret)
		if err != nil {
			return fmt.Errorf("sigall settle output %d: %w", i, err)
		}
		if !sameKey(recipient, expected[i].Recipient) {
			return fmt.Errorf("sigall settle template output %d is not the committed split row at that index (reordered or the wrong recipient)", i)
		}
		if out.Amount != expected[i].Amount {
			return fmt.Errorf("sigall settle template output %d reprices the committed split row to %d sats (committed %d)", i, out.Amount, expected[i].Amount)
		}
	}
	return nil
}

// splitEqual reports whether two committed splits are identical row for row,
// in canonical order, including roles, recipient pubkeys and integer bps. It is
// what makes "the split is immutable" (spec §8) a testable statement rather than
// a claim.
func splitEqual(a, b []CommittedSplitRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// splitImmutableChanged names the immutable field a re-publish tried to change,
// or "" if the split is unchanged. It is the seam the editable-allow-list work
// will extend into the generic immutable-field check over the (seller, d)
// coordinate: an edit that changes the V4V split is refused as
// immutable_field_changed V4VSplit, because the split is part of the money
// promise (spec §8). It compares on the canonical form, so a cosmetic reorder
// is not a change.
func splitImmutableChanged(cur *Auction, next []SplitRow) string {
	nw, err := validateV4VSplit(next)
	if err != nil || !splitEqual(cur.V4VSplit, nw) {
		return "V4VSplit"
	}
	return ""
}

// sameKey compares two compressed secp256k1 keys case-insensitively.
func sameKey(a, b string) bool { return strings.EqualFold(a, b) }
