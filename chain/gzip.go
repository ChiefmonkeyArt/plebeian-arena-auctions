package main

// Gzip for the gateway's JSON and text assets (v0.3.1). The state, network
// and chat responses are polled every 1-2.5 s and the JS bundle is ~1 MB, so
// compressing them is the cheapest speed win. The mint proxy, images, fonts,
// range requests and 304s pass through untouched.

import (
	"compress/gzip"
	"net/http"
	"strings"
	"sync"
)

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed); return w }}

func gzippable(r *http.Request) bool {
	if r.Header.Get("Range") != "" || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}
	p := r.URL.Path
	if p == "/api/events" {
		return false // a stream: gzip would hold it in a buffer
	}
	if strings.HasPrefix(p, "/api/") {
		return true
	}
	if strings.HasPrefix(p, "/mint/") {
		return false
	}
	for _, ext := range []string{".js", ".css", ".html", ".svg", ".json", ".txt"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return p == "/" || !strings.Contains(p[strings.LastIndex(p, "/")+1:], ".") // SPA fallback serves index.html
}

type gzipWriter struct {
	http.ResponseWriter
	gz    *gzip.Writer
	wrote bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if g.wrote {
		return
	}
	g.wrote = true
	h := g.Header()
	h.Add("Vary", "Accept-Encoding")
	if code == http.StatusOK && h.Get("Content-Encoding") == "" {
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		g.gz = gzPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.wrote {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipWriter) close() {
	if g.gz != nil {
		_ = g.gz.Close()
		gzPool.Put(g.gz)
		g.gz = nil
	}
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !gzippable(r) {
			next.ServeHTTP(w, r)
			return
		}
		g := &gzipWriter{ResponseWriter: w}
		defer g.close()
		next.ServeHTTP(g, r)
	})
}
