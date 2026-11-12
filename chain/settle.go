package main

// Push settlement (ADR 0009, v0.5.0). The validators move escrows
// themselves the moment a block makes a move due, instead of waiting for the
// bidder's or seller's browser to ask:
//
//   refund  an outbid, lost or late (void) bid goes back to the bidder's
//           wallet key;
//   payout  the winning bid of a closed lot goes to the seller's wallet key;
//   relock  an anti-snipe lot's leading escrow gets a later locktime before
//           it comes near the point where its bidder could take it back.
//
// The gateway's settler builds the new outputs, reveals each output's secret
// and blinding factor to the validators, and asks them for one FROST
// signature. Every validator recomputes B_ = hash_to_curve(secret) + r*G for
// each output and checks it is locked to the right key for a move its own
// copy of the chain says is due. The mint swap then makes the new ecash, and
// a settle tx records it on chain. The tx is only valid with the group
// signature over the old proofs and those exact outputs, so nobody can
// forge one: the gateway can delay a settlement, never redirect it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const settlePrefix = "settle:"

type settleTx struct {
	Bid    string  `json:"bid"`
	Move   string  `json:"move"`   // refund | payout | relock
	Proofs []Proof `json:"proofs"` // the new ecash, with DLEQ (e, s, r)
	Sig    string  `json:"sig"`    // FROST group signature on the swap (SIG_ALL)
}

func parseSettle(tx []byte) (*settleTx, bool) {
	if !bytes.HasPrefix(tx, []byte(settlePrefix)) || len(tx) > 256<<10 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(tx[len(settlePrefix):]))
	dec.DisallowUnknownFields()
	var st settleTx
	if dec.Decode(&st) != nil || dec.More() || !lowerHex(st.Bid, 64) || !lowerHex(st.Sig, 128) {
		return nil, false
	}
	return &st, true
}

func makeSettle(st *settleTx) []byte {
	b, _ := json.Marshal(st)
	return append([]byte(settlePrefix), b...)
}

// moveDue says whether bid may be moved this way, and to which key.
// signing is true for the validators' signing policy (wall clock now), false
// for recording a settle tx that already carries the group signature: then a
// relock is accepted whatever the bid's status became meanwhile, because the
// escrow has really moved and the chain must follow it.
func (s *State) moveDue(bid *Bid, move string, now int64, signing bool) (string, error) {
	if bid.Settled != "" {
		return "", errors.New("escrow already settled")
	}
	au := s.Auctions[bid.Auction]
	if au == nil {
		return "", errors.New("unknown auction")
	}
	switch move {
	case "refund":
		if bid.Status != "outbid" && bid.Status != "lost" && bid.Status != "void" {
			return "", fmt.Errorf("bid is %s, not refundable", bid.Status)
		}
		return bid.Wallet, nil
	case "payout":
		if au.Status != "closed" || au.Winner != bid.ID {
			return "", errors.New("only the winning bid of a closed auction pays out")
		}
		return au.SellerWallet, nil
	case "relock":
		if au.Mode != "antisnipe" {
			return "", errors.New("only anti-snipe escrows are re-locked")
		}
		if signing && (au.Status != "open" || bid.Status != "leading" || bid.Locktime-now >= s.Params.LockMarginSec/2) {
			return "", errors.New("relock not due")
		}
		return strings.ToLower(s.Params.GroupKey), nil
	}
	return "", errors.New("move must be refund, payout or relock")
}

// checkOutLock checks one new output's secret carries the lock the move
// needs: a plain P2PK lock to the recipient's wallet key for a refund or a
// payout; the escrow lock again (group key, SIG_ALL, refund to the bidder,
// a later locktime) for a relock.
func (s *State) checkOutLock(secret, move string, bid *Bid, to string, minLock int64) (int64, error) {
	l, err := parseP2PK(secret)
	if err != nil {
		return 0, err
	}
	if l.Data != to || len(l.Pubkeys) != 0 || l.NSigs != 1 {
		return 0, errors.New("output not locked to the recipient's key")
	}
	if move == "relock" {
		if l.SigFlag != "SIG_ALL" || len(l.Refund) != 1 || l.Refund[0] != bid.Wallet {
			return 0, errors.New("relock must keep SIG_ALL and the bidder's refund path")
		}
		if l.Locktime < minLock {
			return 0, errors.New("relock locktime too early")
		}
		return l.Locktime, nil
	}
	if l.Locktime != 0 || len(l.Refund) != 0 || (l.SigFlag != "" && l.SigFlag != "SIG_INPUTS") {
		return 0, errors.New("pushed ecash must be a plain lock to the recipient")
	}
	return 0, nil
}

// checkOutputs checks the new outputs as a whole: pinned keyset, real
// denominations, the escrow's exact total, one lock each, no repeats.
func (s *State) checkOutputs(bid *Bid, move, to string, outs []SignOutput, secrets []string, minLock int64) (int64, error) {
	if len(outs) == 0 || len(outs) > 64 || len(secrets) != len(outs) {
		return 0, errors.New("bad output count")
	}
	var sum, lt int64
	seen := map[string]bool{}
	for i, o := range outs {
		if o.ID != s.Params.KeysetID || o.Amount <= 0 || !lowerHex(o.B, 66) {
			return 0, errors.New("bad output")
		}
		if _, ok := s.Params.Keys[fmt.Sprint(o.Amount)]; !ok {
			return 0, errors.New("bad output amount")
		}
		if sum > math.MaxInt64-o.Amount {
			return 0, errors.New("output total overflows")
		}
		sum += o.Amount
		if seen[secrets[i]] {
			return 0, errors.New("duplicate output secret")
		}
		seen[secrets[i]] = true
		l, err := s.checkOutLock(secrets[i], move, bid, to, minLock)
		if err != nil {
			return 0, err
		}
		if i > 0 && l != lt {
			return 0, errors.New("all relocked outputs must share one locktime")
		}
		lt = l
	}
	if sum != bid.Amount {
		return 0, fmt.Errorf("outputs total %d, escrow is %d", sum, bid.Amount)
	}
	return lt, nil
}

// blinded is B_ = Y + r*G for a revealed secret and blinding factor.
func blinded(secret, rHex string) (string, error) {
	Y, err := hashToCurve([]byte(secret))
	if err != nil {
		return "", err
	}
	r, err := parseScalar(rHex)
	if err != nil {
		return "", errors.New("bad blinding factor")
	}
	return hex.EncodeToString(add(Y, mulG(r)).SerializeCompressed()), nil
}

type settleCheck struct {
	ys       []string
	locktime int64
}

// verifySettle checks a settle tx at block time now: the move is due, every
// new proof is a real mint signature (DLEQ) on an output the validators
// would have agreed to, and the group signature covers the old escrow and
// exactly these outputs.
func (s *State) verifySettle(st *settleTx, now int64) (*settleCheck, error) {
	bid := s.Bids[st.Bid]
	if bid == nil {
		return nil, errors.New("unknown bid")
	}
	to, err := s.moveDue(bid, st.Move, now, false)
	if err != nil {
		return nil, err
	}
	if len(st.Proofs) == 0 || len(st.Proofs) > 64 {
		return nil, errors.New("bad proof count")
	}
	outs := make([]SignOutput, len(st.Proofs))
	secrets := make([]string, len(st.Proofs))
	ys := make([]string, len(st.Proofs))
	for i, pr := range st.Proofs {
		kh, ok := s.Params.Keys[fmt.Sprint(pr.Amount)]
		if !ok || pr.ID != s.Params.KeysetID {
			return nil, errors.New("proof from unpinned keyset or bad amount")
		}
		A, err := parsePub(kh)
		if err != nil {
			return nil, errors.New("bad keyset key")
		}
		if err := verifyDLEQ(pr, A); err != nil {
			return nil, err
		}
		b, err := blinded(pr.Secret, pr.DLEQ.R)
		if err != nil {
			return nil, err
		}
		y, err := proofY(pr.Secret)
		if err != nil {
			return nil, err
		}
		if _, used := s.UsedY[y]; used {
			return nil, errors.New("proof already used")
		}
		outs[i] = SignOutput{Amount: pr.Amount, ID: pr.ID, B: b}
		secrets[i], ys[i] = pr.Secret, y
	}
	lt, err := s.checkOutputs(bid, st.Move, to, outs, secrets, now+s.Params.LockMarginSec/4)
	if err != nil {
		return nil, err
	}
	h := sha256Sum(sigAllMessage(bid.Proofs, outs))
	if !schnorrVerifyHash(h[:], s.Params.GroupKey, st.Sig) {
		return nil, errors.New("group signature does not cover this settlement")
	}
	return &settleCheck{ys: ys, locktime: lt}, nil
}

func (s *State) applySettle(st *settleTx, v *settleCheck) {
	bid := s.Bids[st.Bid]
	if st.Move == "relock" {
		bid.Proofs, bid.Locktime = st.Proofs, v.locktime
		bid.Relocks++
		for _, y := range v.ys {
			s.UsedY[y] = bid.ID
		}
		return
	}
	bid.Settled, bid.Out = st.Move, st.Proofs
}

// dueMove is one escrow the settler should move now.
type dueMove struct {
	Bid  *Bid   `json:"bid"`
	Move string `json:"move"`
	To   string `json:"to"`
}

// settleWindowSec: escrows of lots closed longer ago than this are left to
// their owners (pull release or locktime), so the due list stays short.
const settleWindowSec = 7 * 24 * 3600

// dueMoves lists every escrow that should move at wall time now, oldest
// first.
func (s *State) dueMoves(now int64) []dueMove {
	var out []dueMove
	for _, b := range s.Bids {
		if b.Settled != "" {
			continue
		}
		au := s.Auctions[b.Auction]
		if au == nil || (au.Status == "closed" && now-au.ClosedAt > settleWindowSec) {
			continue
		}
		for _, mv := range []string{"refund", "payout", "relock"} {
			if to, err := s.moveDue(b, mv, now, true); err == nil {
				out = append(out, dueMove{Bid: b, Move: mv, To: to})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bid.Height != out[j].Bid.Height {
			return out[i].Bid.Height < out[j].Bid.Height
		}
		return out[i].Bid.ID < out[j].Bid.ID
	})
	return out
}

func sha256Sum(s string) [32]byte { return sha256.Sum256([]byte(s)) }
