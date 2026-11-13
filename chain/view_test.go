package main

// Tests for the v0.3.1 client view, ETag, gzip and single-serialisation commit.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

func hx(n int) string { return fmt.Sprintf("%064x", n) }

// viewState: 20 closed auctions (oldest first), then 2 open ones; 3 bids each,
// every bid carrying 4 proofs. Bidder hx(9000) lost in the oldest auction.
func viewState(now int64) *State {
	s := newState()
	s.Height, s.Time = 500, now
	s.UsedY = map[string]string{"y1": "a", "y2": "b"}
	for i := 0; i < 22; i++ {
		id := hx(i + 1)
		au := &Auction{ID: id, Seller: hx(7000), Title: fmt.Sprint("lot ", i), Status: "closed", ClosedAt: now - int64(22-i)*60}
		if i >= 20 {
			au.Status, au.ClosedAt = "open", 0
		}
		for j := 0; j < 3; j++ {
			bid := hx(1000 + i*10 + j)
			bidder := hx(8000 + j)
			if i == 0 && j == 0 {
				bidder = hx(9000)
			}
			st := "outbid"
			if j == 2 {
				st = map[bool]string{true: "leading", false: "won"}[au.Status == "open"]
			} else if au.Status == "closed" {
				st = "lost"
			}
			s.Bids[bid] = &Bid{ID: bid, Auction: id, Bidder: bidder, Amount: int64(100 + j), Status: st,
				Proofs: []Proof{{Secret: strings.Repeat("s", 400), C: "c"}, {Secret: "x"}, {Secret: "y"}, {Secret: "z"}}}
			au.Bids = append(au.Bids, bid)
		}
		s.Auctions[id] = au
		s.Order = append(s.Order, id)
	}
	return s
}

func TestClientViewTrimsAndStripsProofs(t *testing.T) {
	now := int64(1_800_000_000)
	s := viewState(now)
	full, _ := json.Marshal(s)
	v := clientView(s, nil, 12)
	if len(v.Order) != 14 {
		t.Fatalf("want 2 open + 12 closed auctions, got %d", len(v.Order))
	}
	if v.Auctions[hx(1)] != nil {
		t.Fatal("oldest closed auction should be trimmed")
	}
	if len(v.Bids) != 14*3 {
		t.Fatalf("want all bids of kept auctions, got %d", len(v.Bids))
	}
	for _, b := range v.Bids {
		if b.ProofCount != 4 {
			t.Fatalf("proofCount %d", b.ProofCount)
		}
	}
	body, _ := encodeView(v)
	if bytes.Contains(body, []byte(`"proofs"`)) || bytes.Contains(body, []byte(`"usedY"`)) {
		t.Fatal("client view must not carry proofs or the used-token list")
	}
	if v.UsedCount != 2 {
		t.Fatalf("usedCount %d", v.UsedCount)
	}
	if len(body)*2 > len(full) {
		t.Fatalf("view %d bytes is not much smaller than full %d", len(body), len(full))
	}
	// order preserved
	for i := 1; i < len(v.Order); i++ {
		if v.Order[i] < v.Order[i-1] {
			t.Fatal("order not preserved")
		}
	}
	// the source state is untouched
	if len(s.Bids[hx(1000)].Proofs) != 4 || len(s.Order) != 22 {
		t.Fatal("clientView modified the state")
	}
}

func TestClientViewKeepsCallersUnsettledAuction(t *testing.T) {
	now := int64(1_800_000_000)
	s := viewState(now)
	v := clientView(s, parseBidders(hx(9000)), 12)
	if v.Auctions[hx(1)] == nil || v.Bids[hx(1000)] == nil {
		t.Fatal("the caller's lost bid (refund due) must stay in view")
	}
	if len(v.Order) != 15 {
		t.Fatalf("want 15 auctions, got %d", len(v.Order))
	}
	// seller sees auctions with a won bid (payout due), all of them here
	v = clientView(s, parseBidders(hx(7000)), 0)
	if len(v.Order) != 22 {
		t.Fatalf("seller view: want 22, got %d", len(v.Order))
	}
	// after the window the old auction drops out
	s.Time = now + viewOwnWindowSec + 3600
	v = clientView(s, parseBidders(hx(9000)), 12)
	if v.Auctions[hx(1)] != nil {
		t.Fatal("auction older than the window should drop out")
	}
}

func TestParseBiddersAndClosed(t *testing.T) {
	var parts []string
	for i := 0; i < 30; i++ {
		parts = append(parts, hx(i))
	}
	parts = append(parts, "ZZ", strings.ToUpper(hx(5)), "")
	if n := len(parseBidders(strings.Join(parts, ","))); n != viewMaxBidders {
		t.Fatalf("bidders capped at %d, got %d", viewMaxBidders, n)
	}
	if len(parseBidders("not-hex,"+strings.ToUpper(hx(0xabc)))) != 0 {
		t.Fatal("non-lowercase-hex bidders must be ignored")
	}
	for in, want := range map[string]int{"": 12, "x": 12, "-3": 12, "0": 0, "5": 5, "999": viewMaxClosed} {
		if got := parseClosed(in); got != want {
			t.Fatalf("parseClosed(%q)=%d want %d", in, got, want)
		}
	}
}

func TestViewETagIgnoresHeightButNotChanges(t *testing.T) {
	s := viewState(1_800_000_000)
	_, t1 := encodeView(clientView(s, nil, 12))
	s.Height, s.Time = s.Height+5, s.Time+5
	b2, t2 := encodeView(clientView(s, nil, 12))
	if t1 != t2 {
		t.Fatal("ETag must not change with height/time alone")
	}
	if !bytes.Contains(b2, []byte(`"height":505`)) {
		t.Fatal("body must still carry the real height")
	}
	s.Bids[hx(1200)].Status = "lost"
	if _, t3 := encodeView(clientView(s, nil, 12)); t3 == t2 {
		t.Fatal("ETag must change when a shown bid changes")
	}
	if !etagMatch(`W/"zz", `+t1, t1) || etagMatch(`"other"`, t1) || etagMatch("", t1) {
		t.Fatal("etagMatch")
	}
}

func TestCommitSerialisesOnceAndHashMatches(t *testing.T) {
	a := NewApp()
	p, _ := json.Marshal(Params{GroupKey: tG, SettlementSafetySec: 900, BidToConsensusLatencySec: 15})
	if _, err := a.InitChain(context.Background(), &abci.InitChainRequest{AppStateBytes: p}); err != nil {
		t.Fatal(err)
	}
	res, err := a.FinalizeBlock(context.Background(), &abci.FinalizeBlockRequest{Height: 7, Time: time.Unix(1_800_000_000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.AppHash, a.st.hash()) {
		t.Fatal("app hash must equal sha256 of the canonical state JSON (consensus-compatible with v0.3.0)")
	}
	a.Commit(context.Background(), &abci.CommitRequest{})
	want, _ := json.Marshal(a.st)
	if !bytes.Equal(a.Snapshot(), want) || a.committedH != 7 || a.pending != nil {
		t.Fatal("commit must publish the FinalizeBlock snapshot")
	}
	c := &committedCache{}
	if c.get(a).Height != 7 {
		t.Fatal("cache height")
	}
}

func TestGzipMiddleware(t *testing.T) {
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/same":
			w.Header().Set("ETag", `"t"`)
			w.WriteHeader(http.StatusNotModified)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(strings.Repeat(`{"a":1}`, 500)))
		}
	}))
	get := func(path string, gz bool) *http.Response {
		r := httptest.NewRequest("GET", path, nil)
		if gz {
			r.Header.Set("Accept-Encoding", "gzip, br")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result()
	}
	r := get("/api/state", true)
	if r.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("api JSON should be gzipped")
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if len(b) != 3500 {
		t.Fatalf("decompressed %d bytes", len(b))
	}
	if r := get("/api/state", false); r.Header.Get("Content-Encoding") != "" {
		t.Fatal("no gzip without Accept-Encoding")
	}
	if r := get("/api/same", true); r.StatusCode != 304 || r.Header.Get("Content-Encoding") != "" {
		t.Fatal("304 must pass through uncompressed")
	}
	if r := get("/mint/v1/keys", true); r.Header.Get("Content-Encoding") != "" {
		t.Fatal("mint proxy must not be gzipped by the gateway")
	}
	if r := get("/assets/x.jpg", true); r.Header.Get("Content-Encoding") != "" {
		t.Fatal("images must not be gzipped")
	}
	if r := get("/assets/index-abc.js", true); r.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("JS should be gzipped")
	}
}
