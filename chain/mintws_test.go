package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMintHandlerUpgradeOnlyOnWS(t *testing.T) {
	hit := 0
	h := mintHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	up := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Connection", "keep-alive, Upgrade")
		r.Header.Set("Upgrade", "WebSocket")
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		code int
		hit  bool
	}{
		{httptest.NewRequest("GET", "/v1/info", nil), 200, true},
		{up("GET", "/v1/info"), 400, false},
		{up("POST", "/v1/ws"), 400, false},
		{up("GET", "/v1/ws"), 200, true},
	} {
		before := hit
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.r)
		if w.Code != c.code || (hit > before) != c.hit {
			t.Fatalf("%s %s: code %d hit %v", c.r.Method, c.r.URL.Path, w.Code, hit > before)
		}
	}
}
