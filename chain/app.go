package main

// The auction state machine. Every validator runs this identically; the
// AppHash (sha256 of the canonical JSON state) proves they agree.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

type Params struct {
	MintURL        string            `json:"mintUrl"`
	KeysetID       string            `json:"keysetId"`
	Keys           map[string]string `json:"keys"`
	GroupKey       string            `json:"groupKey"`    // FROST 3-of-4 escrow key (compressed hex); no single validator holds it
	FrostPublic    json.RawMessage   `json:"frostPublic"` // FROST public key package: group key + each validator's verifying share
	ValidatorNames []string          `json:"validatorNames"`
	SoftCloseSec   int64             `json:"softCloseSec"`
	ExtendSec      int64             `json:"extendSec"`
	MaxExtendSec   int64             `json:"maxExtendSec"`
	LockMarginSec  int64             `json:"lockMarginSec"`
	MinDurationSec int64             `json:"minDurationSec"`
	MaxDurationSec int64             `json:"maxDurationSec"`
	MaxProofs      int               `json:"maxProofs"`
	Threshold      int               `json:"threshold"`
}

type Auction struct {
	ID           string   `json:"id"`
	Seller       string   `json:"seller"`
	SellerWallet string   `json:"sellerWallet"`
	SellerName   string   `json:"sellerName"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Image        string   `json:"image"`
	Category     string   `json:"category"`
	StartPrice   int64    `json:"startPrice"`
	MinIncrement int64    `json:"minIncrement"`
	CreatedAt    int64    `json:"createdAt"`
	CreatedH     int64    `json:"createdHeight"`
	EndAt        int64    `json:"endAt"`
	HardEnd      int64    `json:"hardEnd"`
	Status       string   `json:"status"` // open | closed
	HighBid      string   `json:"highBid"`
	HighAmount   int64    `json:"highAmount"`
	Bids         []string `json:"bids"`
	Extensions   int      `json:"extensions"`
	Winner       string   `json:"winner"` // bid id
	ClosedAt     int64    `json:"closedAt"`
	ClosedH      int64    `json:"closedHeight"`
}

type Bid struct {
	ID       string  `json:"id"`
	Auction  string  `json:"auction"`
	Bidder   string  `json:"bidder"`
	Name     string  `json:"name"`
	Wallet   string  `json:"wallet"`
	Amount   int64   `json:"amount"`
	Proofs   []Proof `json:"proofs"`
	Locktime int64   `json:"locktime"`
	Height   int64   `json:"height"`
	Time     int64   `json:"time"`
	Status   string  `json:"status"` // leading | outbid | won | lost
	Extended bool    `json:"extended"`
}

type Rejection struct {
	Height int64  `json:"height"`
	Time   int64  `json:"time"`
	Kind   int    `json:"kind"`
	Pubkey string `json:"pubkey"`
	Event  string `json:"event"`
	Reason string `json:"reason"`
}

type State struct {
	Height     int64               `json:"height"`
	Time       int64               `json:"time"`
	Params     Params              `json:"params"`
	Auctions   map[string]*Auction `json:"auctions"`
	Order      []string            `json:"order"`
	Bids       map[string]*Bid     `json:"bids"`
	UsedY      map[string]string   `json:"usedY"`
	Rejections []Rejection         `json:"rejections"`
	TxCount    int64               `json:"txCount"`
}

func newState() *State {
	return &State{Auctions: map[string]*Auction{}, Bids: map[string]*Bid{}, UsedY: map[string]string{}, Rejections: []Rejection{}, Order: []string{}}
}

func (s *State) hash() []byte {
	b, _ := json.Marshal(s) // Go sorts map keys: canonical
	h := sha256.Sum256(b)
	return h[:]
}

type App struct {
	abci.BaseApplication
	mu         sync.RWMutex
	st         *State
	committed  []byte // JSON snapshot of last committed state
	committedH int64  // height of that snapshot
	pending    []byte // snapshot made in FinalizeBlock, published at Commit
	appHash    []byte
}

func NewApp() *App { return &App{st: newState()} }

func (a *App) Snapshot() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.committed
}

func (a *App) Read(f func(s *State)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	f(a.st)
}

func (a *App) Info(context.Context, *abci.InfoRequest) (*abci.InfoResponse, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// In-memory app: report height 0 so CometBFT replays the chain from genesis on restart.
	return &abci.InfoResponse{Data: "arena-auctions", Version: "0.3.2", AppVersion: 1, LastBlockHeight: 0}, nil
}

func (a *App) InitChain(_ context.Context, req *abci.InitChainRequest) (*abci.InitChainResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st = newState()
	if err := json.Unmarshal(req.AppStateBytes, &a.st.Params); err != nil {
		return nil, fmt.Errorf("bad app_state: %w", err)
	}
	a.committed, _ = json.Marshal(a.st)
	return &abci.InitChainResponse{}, nil
}

type CreateContent struct {
	Title        string `json:"title"`
	Description  string `json:"description"`
	Image        string `json:"image"`
	Category     string `json:"category"`
	StartPrice   int64  `json:"startPrice"`
	MinIncrement int64  `json:"minIncrement"`
	DurationSec  int64  `json:"durationSec"`
	SellerWallet string `json:"sellerWallet"`
	Name         string `json:"name"`
}

type BidContent struct {
	Auction string  `json:"auction"`
	Amount  int64   `json:"amount"`
	Wallet  string  `json:"wallet"`
	Name    string  `json:"name"`
	Proofs  []Proof `json:"proofs"`
}

func decodeTx(tx []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(tx, &ev); err != nil {
		return nil, errors.New("tx is not a Nostr event")
	}
	if ev.Kind != KindCreate && ev.Kind != KindBid {
		return nil, fmt.Errorf("unsupported kind %d", ev.Kind)
	}
	if err := ev.Verify(); err != nil {
		return nil, err
	}
	return &ev, nil
}

// safeImage allows an empty image, a same-site path or an https URL made of
// URL-safe characters only, so it can never break out of an HTML attribute
// (internal audit A5).
func safeImage(s string) bool {
	if s == "" {
		return true
	}
	if !(strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//")) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~:/?#[]@!$&()*+,;=%", c) >= 0) {
			return false
		}
	}
	return true
}

func isPubHex(s string) bool {
	if len(s) != 66 || !(strings.HasPrefix(s, "02") || strings.HasPrefix(s, "03")) {
		return false
	}
	_, err := parsePub(s)
	return err == nil
}

// applyCreate validates and (if apply) executes an auction create event at block time now.
func (s *State) applyCreate(ev *Event, now, height int64, apply bool) error {
	if _, ok := s.Auctions[ev.ID]; ok {
		return errors.New("auction already exists")
	}
	var c CreateContent
	if err := json.Unmarshal([]byte(ev.Content), &c); err != nil {
		return errors.New("bad create content")
	}
	p := s.Params
	switch {
	case len(strings.TrimSpace(c.Title)) == 0 || len(c.Title) > 120:
		return errors.New("title required (max 120 chars)")
	case len(c.Description) > 2000 || len(c.Image) > 500 || len(c.Category) > 40 || len(c.Name) > 40:
		return errors.New("field too long")
	case !safeImage(c.Image):
		return errors.New("image must be a same-site path or an https URL")
	case c.StartPrice < 1 || c.StartPrice > 10_000_000:
		return errors.New("start price out of range")
	case c.MinIncrement < 1 || c.MinIncrement > 1_000_000:
		return errors.New("increment out of range")
	case c.DurationSec < p.MinDurationSec || c.DurationSec > p.MaxDurationSec:
		return fmt.Errorf("duration must be %d-%d seconds", p.MinDurationSec, p.MaxDurationSec)
	case !isPubHex(strings.ToLower(c.SellerWallet)):
		return errors.New("seller wallet pubkey invalid")
	}
	if !apply {
		return nil
	}
	end := now + c.DurationSec
	s.Auctions[ev.ID] = &Auction{
		ID: ev.ID, Seller: ev.Pubkey, SellerWallet: strings.ToLower(c.SellerWallet), SellerName: c.Name,
		Title: c.Title, Description: c.Description, Image: c.Image, Category: c.Category,
		StartPrice: c.StartPrice, MinIncrement: c.MinIncrement, CreatedAt: now, CreatedH: height,
		EndAt: end, HardEnd: end + p.MaxExtendSec, Status: "open", Bids: []string{},
	}
	s.Order = append(s.Order, ev.ID)
	return nil
}

// checkLock enforces the 3-of-4 validator lock with the bidder's refund path.
func (s *State) checkLock(proofs []Proof, wallet string, hardEnd int64) (int64, error) {
	p := s.Params
	var firstTags string
	var lt int64
	for i, pr := range proofs {
		l, err := parseP2PK(pr.Secret)
		if err != nil {
			return 0, err
		}
		if l.Data != strings.ToLower(p.GroupKey) || len(l.Pubkeys) != 0 || l.NSigs != 1 {
			return 0, errors.New("proofs not locked to the validators' FROST group key")
		}
		if l.SigFlag != "SIG_ALL" {
			return 0, errors.New("lock must use SIG_ALL")
		}
		if len(l.Refund) != 1 || l.Refund[0] != wallet {
			return 0, errors.New("refund path must be the bidder's wallet key only")
		}
		if l.Locktime < hardEnd+p.LockMarginSec {
			return 0, errors.New("locktime too early: validators need time to settle")
		}
		if i == 0 {
			firstTags = l.TagsJSON
			lt = l.Locktime
		} else if l.TagsJSON != firstTags {
			return 0, errors.New("all proofs must share one lock")
		}
	}
	return lt, nil
}

func lower(a []string) []string {
	out := make([]string, len(a))
	for i, v := range a {
		out[i] = strings.ToLower(v)
	}
	return out
}

func (s *State) applyBid(ev *Event, now, height int64, apply, timed bool) error {
	if _, ok := s.Bids[ev.ID]; ok {
		return errors.New("bid already recorded")
	}
	var b BidContent
	if err := json.Unmarshal([]byte(ev.Content), &b); err != nil {
		return errors.New("bad bid content")
	}
	au, ok := s.Auctions[b.Auction]
	if !ok {
		return errors.New("unknown auction")
	}
	if au.Status != "open" || (timed && now >= au.EndAt) {
		return errors.New("auction closed")
	}
	if ev.Pubkey == au.Seller {
		return errors.New("seller cannot bid on own lot")
	}
	min := au.StartPrice
	if au.HighBid != "" {
		min = au.HighAmount + au.MinIncrement
		if s.Bids[au.HighBid].Bidder == ev.Pubkey {
			return errors.New("you are already the highest bidder")
		}
	}
	if b.Amount < min {
		return fmt.Errorf("bid must be at least %d sats", min)
	}
	wallet := strings.ToLower(b.Wallet)
	if !isPubHex(wallet) {
		return errors.New("wallet pubkey invalid")
	}
	if len(b.Proofs) == 0 || len(b.Proofs) > s.Params.MaxProofs {
		return errors.New("bad proof count")
	}
	var sum int64
	seen := map[string]bool{}
	ys := make([]string, 0, len(b.Proofs))
	for _, pr := range b.Proofs {
		if pr.ID != s.Params.KeysetID {
			return errors.New("proof from unpinned keyset")
		}
		kh, ok := s.Params.Keys[fmt.Sprint(pr.Amount)]
		if !ok || pr.Amount <= 0 {
			return errors.New("bad proof amount")
		}
		A, err := parsePub(kh)
		if err != nil {
			return errors.New("bad keyset key")
		}
		if err := verifyDLEQ(pr, A); err != nil {
			return err
		}
		y, err := proofY(pr.Secret)
		if err != nil {
			return err
		}
		if seen[y] {
			return errors.New("duplicate proof")
		}
		if _, used := s.UsedY[y]; used {
			return errors.New("proof already used in another bid")
		}
		seen[y] = true
		ys = append(ys, y)
		if sum > math.MaxInt64-pr.Amount {
			return errors.New("proof total overflows")
		}
		sum += pr.Amount
	}
	if sum != b.Amount {
		return fmt.Errorf("proofs total %d but bid is %d", sum, b.Amount)
	}
	lt, err := s.checkLock(b.Proofs, wallet, au.HardEnd)
	if err != nil {
		return err
	}
	if !apply {
		return nil
	}
	if au.HighBid != "" {
		s.Bids[au.HighBid].Status = "outbid"
	}
	bid := &Bid{ID: ev.ID, Auction: au.ID, Bidder: ev.Pubkey, Name: b.Name, Wallet: wallet, Amount: b.Amount,
		Proofs: b.Proofs, Locktime: lt, Height: height, Time: now, Status: "leading"}
	if au.EndAt-now < s.Params.SoftCloseSec {
		ne := now + s.Params.ExtendSec
		if ne > au.HardEnd {
			ne = au.HardEnd
		}
		if ne > au.EndAt {
			au.EndAt = ne
			au.Extensions++
			bid.Extended = true
		}
	}
	s.Bids[ev.ID] = bid
	for _, y := range ys {
		s.UsedY[y] = ev.ID
	}
	au.HighBid, au.HighAmount = ev.ID, b.Amount
	au.Bids = append(au.Bids, ev.ID)
	return nil
}

func (s *State) closeDue(now, height int64) {
	ids := append([]string{}, s.Order...)
	sort.Strings(ids)
	for _, id := range ids {
		au := s.Auctions[id]
		if au.Status == "open" && now >= au.EndAt {
			au.Status, au.ClosedAt, au.ClosedH = "closed", now, height
			if au.HighBid != "" {
				au.Winner = au.HighBid
				s.Bids[au.HighBid].Status = "won"
			}
			for _, bid := range au.Bids {
				if bid != au.Winner {
					s.Bids[bid].Status = "lost"
				}
			}
		}
	}
}

func (a *App) CheckTx(_ context.Context, req *abci.CheckTxRequest) (*abci.CheckTxResponse, error) {
	ev, err := decodeTx(req.Tx)
	if err != nil {
		return &abci.CheckTxResponse{Code: 1, Log: err.Error()}, nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch ev.Kind {
	case KindCreate:
		err = a.st.applyCreate(ev, a.st.Time, a.st.Height, false)
	case KindBid:
		err = a.st.applyBid(ev, a.st.Time, a.st.Height, false, false)
	}
	if err != nil {
		return &abci.CheckTxResponse{Code: 2, Log: err.Error()}, nil
	}
	return &abci.CheckTxResponse{Code: 0}, nil
}

func (a *App) FinalizeBlock(_ context.Context, req *abci.FinalizeBlockRequest) (*abci.FinalizeBlockResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.st
	now := req.Time.Unix()
	s.Height, s.Time = req.Height, now
	s.closeDue(now, req.Height)
	res := make([]*abci.ExecTxResult, len(req.Txs))
	for i, tx := range req.Txs {
		ev, err := decodeTx(tx)
		if err == nil {
			switch ev.Kind {
			case KindCreate:
				err = s.applyCreate(ev, now, req.Height, true)
			case KindBid:
				err = s.applyBid(ev, now, req.Height, true, true)
			}
		}
		if err != nil {
			r := Rejection{Height: req.Height, Time: now, Reason: err.Error()}
			if ev != nil {
				r.Kind, r.Pubkey, r.Event = ev.Kind, ev.Pubkey, ev.ID
			}
			s.Rejections = append(s.Rejections, r)
			if len(s.Rejections) > 50 {
				s.Rejections = s.Rejections[len(s.Rejections)-50:]
			}
			res[i] = &abci.ExecTxResult{Code: 2, Log: err.Error()}
			continue
		}
		s.TxCount++
		res[i] = &abci.ExecTxResult{Code: 0}
	}
	// One serialisation per block: the app hash is the SHA-256 of the same
	// canonical JSON that Commit publishes (identical to s.hash()).
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	a.appHash, a.pending = h[:], b
	return &abci.FinalizeBlockResponse{TxResults: res, AppHash: a.appHash}, nil
}

func (a *App) Commit(context.Context, *abci.CommitRequest) (*abci.CommitResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != nil {
		a.committed, a.pending = a.pending, nil
	} else {
		a.committed, _ = json.Marshal(a.st)
	}
	a.committedH = a.st.Height
	return &abci.CommitResponse{}, nil
}
