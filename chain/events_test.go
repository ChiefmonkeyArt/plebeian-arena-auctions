package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEventStreamPushesHeights(t *testing.T) {
	var h atomic.Int64
	h.Store(5)
	hub := newEventHub(func() (int64, bool) { return h.Load(), true })
	srv := httptest.NewServer(gzipMiddleware(hub))
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/events", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %v", resp.Header)
	}
	rd := bufio.NewReader(resp.Body)
	next := func() string {
		done := make(chan string, 1)
		go func() {
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					done <- "ERR " + err.Error()
					return
				}
				if strings.HasPrefix(l, "data: ") {
					done <- l
					return
				}
			}
		}()
		select {
		case l := <-done:
			return l
		case <-time.After(3 * time.Second):
			return "TIMEOUT"
		}
	}
	if l := next(); !strings.Contains(l, `"h":5`) || !strings.Contains(l, `"now":`) {
		t.Fatalf("first event: %q", l)
	}
	h.Store(6)
	if l := next(); !strings.Contains(l, `"h":6`) {
		t.Fatalf("pushed event: %q", l)
	}
	if r, _ := http.Post(srv.URL+"/api/events", "text/plain", nil); r.StatusCode != 405 {
		t.Fatal("POST must be refused")
	}
}

func TestEventStreamCap(t *testing.T) {
	hub := newEventHub(func() (int64, bool) { return 1, true })
	for i := 0; i < sseMaxSubs; i++ {
		if _, _, ok := hub.subscribe(); !ok {
			t.Fatal("under the cap")
		}
	}
	rec := httptest.NewRecorder()
	hub.ServeHTTP(rec, httptest.NewRequest("GET", "/api/events", nil))
	if rec.Code != 503 {
		t.Fatalf("over the cap want 503, got %d", rec.Code)
	}
}
