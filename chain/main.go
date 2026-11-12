package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: arena init|node|gateway [flags]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "node":
		cmdNode(os.Args[2:])
	case "gateway":
		cmdGateway(os.Args[2:])
	default:
		log.Fatal("unknown command")
	}
}

type supervisor struct {
	mu    sync.Mutex
	root  string
	bin   string
	logs  string
	procs [4]*exec.Cmd
	want  [4]bool
}

func (s *supervisor) start(i int) error {
	return s.startWith(i, []string{"node", "-root", s.root, "-i", fmt.Sprint(i + 1)})
}

// startWith starts validator i with explicit arguments, so the gateway can pass
// relay flags through to each node's ingest.
func (s *supervisor) startWith(i int, args []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.procs[i] != nil {
		return nil
	}
	lf, err := os.OpenFile(filepath.Join(s.logs, fmt.Sprintf("v%d.log", i+1)), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(s.bin, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.procs[i], s.want[i] = cmd, true
	go func() {
		cmd.Wait()
		lf.Close()
		s.mu.Lock()
		if s.procs[i] == cmd {
			s.procs[i] = nil
		}
		s.mu.Unlock()
	}()
	return nil
}

func (s *supervisor) stop(i int) {
	s.mu.Lock()
	cmd := s.procs[i]
	s.want[i] = false
	s.mu.Unlock()
	if cmd == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			s.mu.Lock()
			gone := s.procs[i] != cmd
			s.mu.Unlock()
			if gone {
				close(done)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		cmd.Process.Kill()
	}
}

func (s *supervisor) running(i int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.procs[i] != nil
}

var client = &http.Client{Timeout: 4 * time.Second}

type chatMsg struct {
	Event
	Received int64 `json:"received"`
}

func cmdGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	root := fs.String("root", "run/chain", "chain root")
	static := fs.String("static", "web/dist", "front end dir")
	addr := fs.String("addr", "127.0.0.1:8080", "listen addr")
	mint := fs.String("mint", "http://127.0.0.1:3338", "mint")
	demo := fs.Bool("demo-controls", false, "expose the unauthenticated validator stop/start route (demo only, never on a real-sats deployment)")
	var relays relayURLs
	fs.Var(&relays, "relay", "relay websocket URL clients publish to (repeatable); the relay is the primary transport")
	fs.Parse(args)
	bin, _ := os.Executable()
	sup := &supervisor{root: *root, bin: bin, logs: filepath.Dir(*root)}
	for i := 0; i < 4; i++ {
		args := []string{"node", "-root", *root, "-i", fmt.Sprint(i+1)}
		for _, relay := range relays {
			args = append(args, "-relay", relay)
		}
		check(sup.startWith(i, args))
	}
	publisher := newRelayPublisher(relays)

	var chatMu sync.Mutex
	chat := []chatMsg{}

	mu := http.NewServeMux()
	mintURL, _ := url.Parse(*mint)
	mp := httputil.NewSingleHostReverseProxy(mintURL)
	mu.Handle("/mint/", http.StripPrefix("/mint", mintHandler(mp)))

	// state from the first healthy validator. ?view=client is the slim view
	// the page polls (see view.go); it answers 304 when nothing changed.
	mu.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		q := url.Values{}
		for _, k := range []string{"view", "bidders", "closed"} {
			if v := r.URL.Query().Get(k); v != "" && len(v) <= 2048 {
				q.Set(k, v)
			}
		}
		for i := 0; i < 4; i++ {
			if !sup.running(i) {
				continue
			}
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/state?%s", httpPort(i), q.Encode()), nil)
			if inm := r.Header.Get("If-None-Match"); inm != "" && len(inm) <= 256 {
				req.Header.Set("If-None-Match", inm)
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if tag := resp.Header.Get("ETag"); tag != "" {
				w.Header().Set("ETag", tag)
				w.Header().Set("Cache-Control", "no-cache")
			}
			w.Header().Set("X-Served-By", names[i])
			if resp.StatusCode == http.StatusNotModified {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			if resp.StatusCode == 200 && len(b) > 2 {
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}
		}
		writeJSON(w, 503, map[string]string{"error": "no validator reachable"})
	})

	// push: "a block was committed" as Server-Sent Events (events.go)
	evCl := &http.Client{Timeout: 500 * time.Millisecond}
	mu.Handle("/api/events", newEventHub(func() (int64, bool) {
		for i := 0; i < 4; i++ {
			if sup.running(i) {
				if h, ok := heightFrom(evCl, fmt.Sprintf("http://127.0.0.1:%d/height", httpPort(i))); ok {
					return h, true
				}
			}
		}
		return 0, false
	}))

	// one bid with its proofs, for releasing it
	mu.HandleFunc("/api/bid", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if !lowerHex(id, 64) {
			writeJSON(w, 400, map[string]string{"error": "id must be 64 lowercase hex"})
			return
		}
		for i := 0; i < 4; i++ {
			if !sup.running(i) {
				continue
			}
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/bid?id=%s", httpPort(i), id))
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 404 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(resp.StatusCode)
				w.Write(b)
				return
			}
		}
		writeJSON(w, 503, map[string]string{"error": "no validator reachable"})
	})

	mu.HandleFunc("/api/network", func(w http.ResponseWriter, r *http.Request) {
		out := make([]map[string]any, 4)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				m := map[string]any{"name": names[i], "index": i + 1, "up": false, "process": sup.running(i)}
				if sup.running(i) {
					resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/status", httpPort(i)))
					if err == nil {
						json.NewDecoder(resp.Body).Decode(&m)
						resp.Body.Close()
						m["up"] = true
						m["process"] = true
					}
				}
				out[i] = m
			}(i)
		}
		wg.Wait()
		writeJSON(w, 200, out)
	})

	// Publish a signed Nostr event.  When the gateway is configured with a
	// relay, the relay is the primary transport: the event goes there, every
	// validator's observer ingests it into that validator's own mempool, and
	// the gateway does not need to know which validator leads.  The direct
	// submit below is kept as a fallback for a deployment with no relay.
	mu.HandleFunc("/api/tx", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || r.Method != http.MethodPost {
			writeJSON(w, 400, map[string]string{"error": "POST a signed event"})
			return
		}
		var compact bytes.Buffer
		if json.Compact(&compact, body) != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
		tx := "0x" + hex.EncodeToString(compact.Bytes())

		if publisher != nil {
			var event Event
			if json.Unmarshal(compact.Bytes(), &event) != nil || event.Verify() != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid signed event"})
				return
			}
			if pubErr := publisher.Publish(r.Context(), event); pubErr == nil {
				writeJSON(w, 200, map[string]any{"ok": true, "via": "relay"})
				return
			} else {
				log.Printf("relay publish failed, falling back to direct submit: %v", pubErr)
			}
		}

		for i := 0; i < 4; i++ {
			if !sup.running(i) {
				continue
			}
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/broadcast_tx_sync?tx=%s", rpcPort(i), tx))
			if err != nil {
				continue
			}
			var rr struct {
				Result *struct {
					Code uint32 `json:"code"`
					Log  string `json:"log"`
					Hash string `json:"hash"`
				} `json:"result"`
				Error *struct {
					Message string `json:"message"`
					Data    string `json:"data"`
				} `json:"error"`
			}
			json.NewDecoder(resp.Body).Decode(&rr)
			resp.Body.Close()
			if rr.Error != nil {
				msg := rr.Error.Data
				if msg == "" {
					msg = rr.Error.Message
				}
				if strings.Contains(msg, "already exists in cache") {
					writeJSON(w, 200, map[string]any{"ok": true, "via": names[i], "note": "already submitted"})
					return
				}
				writeJSON(w, 400, map[string]any{"ok": false, "error": msg, "via": names[i]})
				return
			}
			if rr.Result == nil {
				continue
			}
			if rr.Result.Code != 0 {
				writeJSON(w, 400, map[string]any{"ok": false, "error": rr.Result.Log, "via": names[i]})
				return
			}
			out := map[string]any{"ok": true, "hash": rr.Result.Hash, "via": names[i]}
			if strings.HasPrefix(rr.Result.Log, "late: ") {
				// a late bid: on chain as void, refundable as soon as it lands (ADR 0007)
				out["late"] = strings.TrimPrefix(rr.Result.Log, "late: ")
			}
			writeJSON(w, 200, out)
			return
		}
		writeJSON(w, 503, map[string]string{"error": "no validator reachable"})
	})

	// relay a release request to every validator's signer; the browser assembles 3 of 4
	// escrow release: one FROST signing round across the validators
	rc, err := loadCoordinator(*root, func(i int, path string, body any, out any) (int, error) {
		b, _ := json.Marshal(body)
		resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d%s", httpPort(i), path), "application/json", bytes.NewReader(b))
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
		return resp.StatusCode, nil
	})
	check(err)
	mu.HandleFunc("/api/release", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if !json.Valid(body) {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		code, res := rc.release(body)
		writeJSON(w, code, res)
	})

	mu.HandleFunc("/api/admin/validator/", func(w http.ResponseWriter, r *http.Request) {
		if !*demo {
			writeJSON(w, 404, map[string]string{"error": "demo controls are off on this deployment"})
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		var n int
		var action string
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/admin/validator/"), "%d/%s", &n, &action)
		if n < 1 || n > 4 {
			writeJSON(w, 400, map[string]string{"error": "validator 1-4"})
			return
		}
		switch action {
		case "stop":
			sup.stop(n - 1)
		case "start":
			if err := sup.start(n - 1); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
		default:
			writeJSON(w, 400, map[string]string{"error": "stop or start"})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "validator": n, "action": action})
	})

	// lot chat: signed Nostr events, kept in memory (not consensus data)
	mu.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var ev Event
			if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&ev) != nil || ev.Kind != KindChat || ev.Verify() != nil || len(ev.Content) > 280 {
				writeJSON(w, 400, map[string]string{"error": "invalid chat event"})
				return
			}
			chatMu.Lock()
			chat = append(chat, chatMsg{ev, time.Now().Unix()})
			if len(chat) > 300 {
				chat = chat[len(chat)-300:]
			}
			chatMu.Unlock()
			writeJSON(w, 200, map[string]bool{"ok": true})
			return
		}
		chatMu.Lock()
		defer chatMu.Unlock()
		writeJSON(w, 200, chat)
	})

	// static front end with SPA fallback
	fsrv := http.FileServer(http.Dir(*static))
	mu.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(*static, filepath.Clean(r.URL.Path))
		if st, err := os.Stat(p); err != nil || st.IsDir() && r.URL.Path != "/" {
			r.URL.Path = "/"
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fsrv.ServeHTTP(w, r)
	})

	srv := &http.Server{Addr: *addr, Handler: gzipMiddleware(mu),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	log.Printf("gateway on %s", *addr)
	go func() {
		sigc := make(chan os.Signal, 1)
		signalNotify(sigc)
		<-sigc
		// stop all four at once: each may take a few seconds to write its
		// shutdown snapshot, and systemd's TimeoutStopSec is 20 s
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); sup.stop(i) }(i)
		}
		wg.Wait()
		os.Exit(0)
	}()
	log.Fatal(srv.ListenAndServe())
}
