package main

// Client view of the committed state (v0.3.1).
//
// The browser used to download the full state every second: every bid with
// all of its Cashu proofs, every finished auction and the whole used-token
// list. That grows with every bid, and by v0.3.0 it was over 1 MB a poll.
// The client view keeps what the page draws and settles:
//   - every open auction, plus the most recent finished ones (closed=N);
//   - any finished auction in which one of the caller's identities
//     (bidders=pk,pk…) still has something to settle (a refund or a payout),
//     for up to a week after it closed;
//   - all bids of those auctions, without proofs (proofCount instead);
//   - the used-token count, not the list.
// Proofs for one bid come from /bid?id= when the browser releases it.
// The ETag ignores height and time, so an unchanged view answers 304.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

const (
	viewDefaultClosed = 12
	viewMaxClosed     = 50
	viewMaxBidders    = 16
	viewOwnWindowSec  = 7 * 24 * 3600
)

type BidView struct {
	ID         string `json:"id"`
	Auction    string `json:"auction"`
	Bidder     string `json:"bidder"`
	Name       string `json:"name"`
	Wallet     string `json:"wallet"`
	Amount     int64  `json:"amount"`
	ProofCount int    `json:"proofCount"`
	Locktime   int64  `json:"locktime"`
	Height     int64  `json:"height"`
	Time       int64  `json:"time"`
	Status     string `json:"status"`
	Extended   bool   `json:"extended"`
	Settled    string `json:"settled,omitempty"` // settle | refund: pushed by the validators (ADR 0009)
}

type ClientView struct {
	View       string              `json:"view"`
	Height     int64               `json:"height"`
	Time       int64               `json:"time"`
	Now        int64               `json:"now"` // the validator's wall clock, ms (for the client's clock offset)
	Params     Params              `json:"params"`
	Auctions   map[string]*Auction `json:"auctions"`
	Order      []string            `json:"order"`
	Bids       map[string]*BidView `json:"bids"`
	UsedCount  int                 `json:"usedCount"`
	Rejections []Rejection         `json:"rejections"`
	TxCount    int64               `json:"txCount"`
}

// committedCache holds the parsed form of the last committed snapshot so a
// poll does not re-parse it; it refreshes at most once per committed block.
type committedCache struct {
	mu sync.Mutex
	h  int64
	st *State
}

func (c *committedCache) get(a *App) *State {
	a.mu.RLock()
	b, h, t := a.committed, a.committedH, a.committedT
	a.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil || c.h != h {
		st := newState()
		if json.Unmarshal(b, st) != nil {
			return newState()
		}
		st.Height, st.Time = h, t
		c.st, c.h = st, h
	}
	return c.st
}

func parseBidders(q string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(q, ",") {
		if len(out) >= viewMaxBidders {
			break
		}
		if lowerHex(p, 64) {
			out[p] = true
		}
	}
	return out
}

func parseClosed(q string) int {
	n, err := strconv.Atoi(q)
	if err != nil || n < 0 {
		return viewDefaultClosed
	}
	if n > viewMaxClosed {
		return viewMaxClosed
	}
	return n
}

// clientView builds the view from a committed state. It does not modify s.
func clientView(s *State, bidders map[string]bool, closed int) *ClientView {
	keep := map[string]bool{}
	recent := 0
	for i := len(s.Order) - 1; i >= 0; i-- {
		au := s.Auctions[s.Order[i]]
		if au == nil {
			continue
		}
		if au.Status == "open" {
			keep[au.ID] = true
		} else if recent < closed {
			keep[au.ID] = true
			recent++
		}
	}
	// finished auctions where a caller still has a refund or a payout to collect
	if len(bidders) > 0 {
		for _, b := range s.Bids {
			au := s.Auctions[b.Auction]
			if au == nil || keep[au.ID] || au.Status != "closed" || s.Time-au.ClosedAt > viewOwnWindowSec {
				continue
			}
			mine := bidders[b.Bidder] && (b.Status == "outbid" || b.Status == "lost" || b.Status == "void")
			sale := bidders[au.Seller] && b.Status == "won"
			if mine || sale {
				keep[au.ID] = true
			}
		}
	}
	v := &ClientView{View: "client", Height: s.Height, Time: s.Time, Params: s.Params,
		Auctions: map[string]*Auction{}, Order: []string{}, Bids: map[string]*BidView{},
		UsedCount: len(s.UsedY), Rejections: s.Rejections, TxCount: s.TxCount}
	for _, id := range s.Order {
		if !keep[id] {
			continue
		}
		au := s.Auctions[id]
		v.Auctions[id] = au
		v.Order = append(v.Order, id)
		ids := au.Bids
		for _, vid := range au.Voids { // only the caller's own late bids
			if b := s.Bids[vid]; b != nil && bidders[b.Bidder] {
				ids = append(ids[:len(ids):len(ids)], vid)
			}
		}
		for _, bid := range ids {
			if b := s.Bids[bid]; b != nil {
				v.Bids[bid] = &BidView{ID: b.ID, Auction: b.Auction, Bidder: b.Bidder, Name: b.Name, Wallet: b.Wallet,
					Amount: b.Amount, ProofCount: len(b.Proofs), Locktime: b.Locktime, Height: b.Height, Time: b.Time,
					Status: b.Status, Extended: b.Extended, Settled: b.Settled}
			}
		}
	}
	if v.Rejections == nil {
		v.Rejections = []Rejection{}
	}
	return v
}

// encodeView returns the JSON body and an ETag that ignores height and time,
// so the tag only moves when something the page shows has changed.
func encodeView(v *ClientView) ([]byte, string) {
	h, t, n := v.Height, v.Time, v.Now
	v.Height, v.Time, v.Now = 0, 0, 0
	stable, _ := json.Marshal(v)
	v.Height, v.Time, v.Now = h, t, n
	sum := sha256.Sum256(stable)
	body, _ := json.Marshal(v)
	return body, `"` + hex.EncodeToString(sum[:12]) + `"`
}

// etagMatch reports whether an If-None-Match header names tag.
func etagMatch(header, tag string) bool {
	for _, p := range strings.Split(header, ",") {
		p = strings.TrimPrefix(strings.TrimSpace(p), "W/")
		if p == tag || p == "*" {
			return true
		}
	}
	return false
}
