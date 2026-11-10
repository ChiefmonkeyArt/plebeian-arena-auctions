package main

// The mint's NUT-17 WebSocket (/mint/v1/ws), v0.3.2. Coco subscribes there
// for quote and proof-state updates. httputil.ReverseProxy upgrades the
// connection itself, but a hijacked connection keeps the server's read and
// write deadlines, so it would be cut after ReadTimeout (15 s). Only the
// exact ws path may upgrade; it gets a 10-minute session cap instead (Coco
// reconnects on its own).

import (
	"net/http"
	"strings"
	"time"
)

const mintWSIdle = 10 * time.Minute

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func mintHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/v1/ws" || r.Method != http.MethodGet {
			http.Error(w, "upgrade only on /v1/ws", http.StatusBadRequest)
			return
		}
		rc := http.NewResponseController(w)
		// replaces the 15 s / 60 s server deadlines for this connection only
		_ = rc.SetReadDeadline(time.Now().Add(mintWSIdle))
		_ = rc.SetWriteDeadline(time.Now().Add(mintWSIdle))
		next.ServeHTTP(w, r)
	})
}
