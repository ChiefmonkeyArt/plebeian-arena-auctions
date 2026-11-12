package main

// Push updates (ADR 0007, v0.4.0). GET /api/events is a Server-Sent Events
// stream that says "the committed height is now h" the moment a validator
// commits a block; the page then fetches /api/state (usually one small
// conditional request). With blocks on demand there is nothing to push while
// the chain is idle, so the stream costs almost nothing. Polling stays as
// the fallback.

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	sseMaxSubs   = 512
	ssePoll      = 100 * time.Millisecond
	ssePing      = 15 * time.Second
	sseLifetime  = 15 * time.Minute // then the browser reconnects (spreads load, refreshes limits)
	sseWriteWait = 10 * time.Second
)

type eventHub struct {
	mu     sync.Mutex
	subs   map[chan int64]chan []byte // height channel -> message channel
	height int64
	wake   chan struct{}
	// committed height from the first running validator; after is the
	// height already seen, so a source may long-poll until it moves (v0.5.0)
	src     func(after int64) (int64, bool)
	onBlock func(int64) // the settler: told about every new height, listeners or not
}

func newEventHub(src func(after int64) (int64, bool)) *eventHub {
	h := &eventHub{subs: map[chan int64]chan []byte{}, wake: make(chan struct{}, 1), src: src}
	go h.run()
	return h
}

// watch makes the hub follow the chain even with no listeners and call f on
// every new height.
func (h *eventHub) watch(f func(int64)) {
	h.mu.Lock()
	h.onBlock = f
	h.mu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// broadcast sends one message (a JSON object) to every listener; a listener
// too slow to take it misses it and falls back to polling.
func (h *eventHub) broadcast(msg []byte) {
	b := []byte("data: " + string(msg) + "\n\n")
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.subs {
		select {
		case m <- b:
		default:
		}
	}
}

// run follows the validators only while someone is listening (or the
// settler watches). The source long-polls, so this is one waiting request,
// not ten a second; a source that answers at once is paced at ssePoll.
func (h *eventHub) run() {
	for {
		h.mu.Lock()
		n := len(h.subs)
		watched := h.onBlock != nil
		last := h.height
		h.mu.Unlock()
		if n == 0 && !watched {
			<-h.wake
			continue
		}
		t0 := time.Now()
		ht, ok := h.src(last)
		if !ok || ht == last {
			if d := ssePoll - time.Since(t0); d > 0 {
				time.Sleep(d)
			}
			if !ok {
				continue
			}
		}
		h.mu.Lock()
		f := h.onBlock
		if ht != h.height {
			if f != nil && ht > h.height {
				go f(ht)
			}
			h.height = ht
			for c := range h.subs {
				select { // latest wins: drop a stale value a slow reader has not taken
				case <-c:
				default:
				}
				c <- ht
			}
		}
		h.mu.Unlock()
	}
}

func (h *eventHub) subscribe() (chan int64, int64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= sseMaxSubs {
		return nil, 0, false
	}
	if len(h.subs) == 0 && h.onBlock == nil {
		// The hub stops polling while nobody listens, so the height it kept is
		// stale: the first listener waits for the next poll (100 ms) instead.
		h.height = 0
	}
	c := make(chan int64, 1)
	h.subs[c] = make(chan []byte, 32)
	select {
	case h.wake <- struct{}{}:
	default:
	}
	return c, h.height, true
}

func (h *eventHub) unsubscribe(c chan int64) {
	h.mu.Lock()
	delete(h.subs, c)
	h.mu.Unlock()
}

func sseMessage(height int64) []byte {
	b, _ := json.Marshal(map[string]int64{"h": height, "now": time.Now().UnixMilli()})
	return []byte("data: " + string(b) + "\n\n")
}

func (h *eventHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET only"})
		return
	}
	c, cur, ok := h.subscribe()
	if !ok {
		w.Header().Set("Retry-After", "30")
		writeJSON(w, 503, map[string]string{"error": "too many listeners; polling still works"})
		return
	}
	defer h.unsubscribe(c)
	h.mu.Lock()
	msgs := h.subs[c]
	h.mu.Unlock()
	rc := http.NewResponseController(w)
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-cache, no-transform")
	hd.Set("X-Accel-Buffering", "no") // nginx: do not buffer the stream
	w.WriteHeader(200)
	send := func(b []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteWait))
		if _, err := w.Write(b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send([]byte("retry: 2000\n\n")) || (cur > 0 && !send(sseMessage(cur))) {
		return
	}
	ping := time.NewTicker(ssePing)
	defer ping.Stop()
	end := time.NewTimer(sseLifetime)
	defer end.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case <-ping.C:
			if !send([]byte(": ping\n\n")) {
				return
			}
		case ht := <-c:
			if !send(sseMessage(ht)) {
				return
			}
		case m := <-msgs:
			if !send(m) {
				return
			}
		}
	}
}

// heightFrom reads a validator's /height (its app's committed height).
func heightFrom(cl *http.Client, url string) (int64, bool) {
	resp, err := cl.Get(url)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var out struct {
		Height int64 `json:"height"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&out) != nil {
		return 0, false
	}
	return out.Height, true
}
