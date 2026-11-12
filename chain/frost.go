package main

// FROST 3-of-4 escrow key. The four validators hold one share each of a key
// made by distributed key generation (no complete private key ever exists).
// Bids are locked to the group key; a release needs a signature that only
// three cooperating validators can produce. The maths is done by the
// arena-frost tool (Zcash Foundation frost-secp256k1-tr), called over stdin.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const frostMax, frostMin = 4, 3

func frostBin() string {
	if b := os.Getenv("ARENA_FROST"); b != "" {
		return b
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "arena-frost")
}

// frostCall runs one arena-frost command: JSON in, JSON out. Signing
// commands go to a long-lived "arena-frost serve" process (v0.5.0: no exec
// per call); key generation and any serve failure use a one-shot exec.
func frostCall(cmd string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(cmd, "dkg") && os.Getenv("ARENA_FROST_SERVE") != "0" {
		if raw, err, served := frostServed(cmd, b); served {
			if err != nil {
				return err
			}
			return json.Unmarshal(raw, out)
		}
	}
	return frostExec(cmd, b, out)
}

func frostExec(cmd string, b []byte, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, frostBin(), cmd)
	c.Stdin = bytes.NewReader(b)
	var so, se bytes.Buffer
	c.Stdout, c.Stderr = &so, &se
	runErr := c.Run()
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(so.Bytes(), &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	if runErr != nil {
		return fmt.Errorf("arena-frost %s: %v %s", cmd, runErr, strings.TrimSpace(se.String()))
	}
	return json.Unmarshal(so.Bytes(), out)
}

// frostServer is one "arena-frost serve" process. It is stateless: every
// request carries its own key package and nonces, and nonces live only in the
// validator's memory (frostSessions), never on disk.
type frostServer struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

const frostServers = 4

var (
	frostIdle  = make(chan *frostServer, frostServers)
	frostSlots = make(chan struct{}, frostServers)
)

func startFrostServer() (*frostServer, error) {
	c := exec.Command(frostBin(), "serve")
	in, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	o, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	return &frostServer{cmd: c, in: in, out: bufio.NewReaderSize(o, 64<<10)}, nil
}

func (f *frostServer) kill() {
	f.in.Close()
	f.cmd.Process.Kill()
	go f.cmd.Wait()
}

// frostServed sends one request to a pooled server. served=false means the
// pool could not be used and the caller should exec instead.
func frostServed(cmd string, in []byte) (raw json.RawMessage, err error, served bool) {
	var f *frostServer
	select {
	case f = <-frostIdle:
	default:
		select {
		case f = <-frostIdle:
		case frostSlots <- struct{}{}:
			if f, err = startFrostServer(); err != nil {
				<-frostSlots
				return nil, nil, false
			}
		}
	}
	line, _ := json.Marshal(map[string]any{"cmd": cmd, "input": json.RawMessage(in)})
	type reply struct {
		b   []byte
		err error
	}
	ch := make(chan reply, 1)
	go func() {
		if _, err := f.in.Write(append(line, '\n')); err != nil {
			ch <- reply{nil, err}
			return
		}
		b, err := f.out.ReadBytes('\n')
		ch <- reply{b, err}
	}()
	var r reply
	select {
	case r = <-ch:
	case <-time.After(10 * time.Second):
		r.err = errors.New("timeout")
	}
	if r.err != nil {
		f.kill()
		<-frostSlots
		return nil, nil, false
	}
	frostIdle <- f
	var res struct {
		OK    json.RawMessage `json:"ok"`
		Error string          `json:"error"`
	}
	if json.Unmarshal(r.b, &res) != nil {
		return nil, errors.New("arena-frost serve: bad reply"), true
	}
	if res.Error != "" {
		return nil, errors.New(res.Error), true
	}
	return res.OK, nil, true
}

type frostKeyFile struct {
	Participant int             `json:"participant"`
	KeyPackage  json.RawMessage `json:"key_package"`
	GroupKey    string          `json:"group_key"`
}

// frostDKG runs the three-round key ceremony for four participants. Each
// participant's secret packages stay with that participant's step; round-2
// packages go only to their recipient.
func frostDKG() (keys []json.RawMessage, pkp json.RawMessage, groupKey string, err error) {
	type r1out struct {
		Secret  json.RawMessage `json:"secret"`
		Package json.RawMessage `json:"package"`
	}
	secrets1 := make([]json.RawMessage, frostMax)
	round1 := map[string]json.RawMessage{}
	for i := 1; i <= frostMax; i++ {
		var o r1out
		if err = frostCall("dkg1", map[string]int{"id": i, "max": frostMax, "min": frostMin}, &o); err != nil {
			return
		}
		secrets1[i-1], round1[strconv.Itoa(i)] = o.Secret, o.Package
	}
	others := func(i int, m map[string]json.RawMessage) map[string]json.RawMessage {
		out := map[string]json.RawMessage{}
		for k, v := range m {
			if k != strconv.Itoa(i) {
				out[k] = v
			}
		}
		return out
	}
	secrets2 := make([]json.RawMessage, frostMax)
	inbox := make([]map[string]json.RawMessage, frostMax)
	for i := range inbox {
		inbox[i] = map[string]json.RawMessage{}
	}
	for i := 1; i <= frostMax; i++ {
		var o struct {
			Secret json.RawMessage            `json:"secret"`
			Round2 map[string]json.RawMessage `json:"round2"`
		}
		if err = frostCall("dkg2", map[string]any{"secret": secrets1[i-1], "round1": others(i, round1)}, &o); err != nil {
			return
		}
		secrets2[i-1] = o.Secret
		for to, p := range o.Round2 {
			n, _ := strconv.Atoi(to)
			if n < 1 || n > frostMax || n == i {
				return nil, nil, "", errors.New("dkg: bad recipient")
			}
			inbox[n-1][strconv.Itoa(i)] = p
		}
	}
	keys = make([]json.RawMessage, frostMax)
	for i := 1; i <= frostMax; i++ {
		var o struct {
			KeyPackage json.RawMessage `json:"key_package"`
			PKP        json.RawMessage `json:"public_key_package"`
			GroupKey   string          `json:"group_key"`
		}
		if err = frostCall("dkg3", map[string]any{"secret": secrets2[i-1], "round1": others(i, round1), "round2": inbox[i-1]}, &o); err != nil {
			return
		}
		if groupKey != "" && o.GroupKey != groupKey {
			return nil, nil, "", errors.New("dkg: participants disagree on the group key")
		}
		keys[i-1], pkp, groupKey = o.KeyPackage, o.PKP, o.GroupKey
	}
	return
}

// frostSessions holds this validator's one-time signing nonces between the
// two rounds. A nonce is used at most once and expires after a minute.
type frostSession struct {
	nonces json.RawMessage
	hash   string
	bid    string
	exp    time.Time
}

// maxSessionsPerRelease stops one escrow's owner filling the session table
// and locking everyone else out (threat model F8).
const maxSessionsPerRelease = 4

type frostSessions struct {
	mu sync.Mutex
	m  map[string]frostSession
}

func (s *frostSessions) put(nonces json.RawMessage, hash, bid string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.exp) {
			delete(s.m, k)
		}
	}
	if len(s.m) >= 256 {
		return "", errors.New("too many open signing sessions")
	}
	per := 0
	for _, v := range s.m {
		if v.bid == bid {
			per++
		}
	}
	if per >= maxSessionsPerRelease {
		return "", errors.New("too many open signing sessions for this escrow")
	}
	s.m[id] = frostSession{nonces: nonces, hash: hash, bid: bid, exp: now.Add(time.Minute)}
	return id, nil
}

// take removes and returns a session: its nonces can never be used again.
func (s *frostSessions) take(id string) (frostSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	delete(s.m, id)
	if ok && time.Now().After(v.exp) {
		return v, false
	}
	return v, ok
}

// signingPackageMessage reads the message a signing package commits to.
func signingPackageMessage(sp json.RawMessage) (string, error) {
	var p struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(sp, &p); err != nil || p.Message == "" {
		return "", errors.New("bad signing package")
	}
	return strings.ToLower(p.Message), nil
}

// releaseCoordinator runs a FROST signing round for the gateway. It holds no
// key material: it only relays commitments and shares, then aggregates them
// into one BIP-340 signature with the public key package from genesis.
type releaseCoordinator struct {
	pkp      json.RawMessage
	groupKey string
	post     func(i int, path string, body any, out any) (int, error)
	params   Params // genesis app state: keyset, lock margin (for the settler)
}

func loadCoordinator(root string, post func(int, string, any, any) (int, error)) (*releaseCoordinator, error) {
	b, err := os.ReadFile(filepath.Join(homeOf(root, 0), "config", "genesis.json"))
	if err != nil {
		return nil, err
	}
	var g struct {
		AppState Params `json:"app_state"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	if g.AppState.GroupKey == "" || len(g.AppState.FrostPublic) == 0 {
		return nil, errors.New("genesis has no FROST group key: re-run arena init")
	}
	return &releaseCoordinator{pkp: g.AppState.FrostPublic, groupKey: g.AppState.GroupKey, post: post, params: g.AppState}, nil
}

type releaseResult struct {
	Signature string              `json:"signature,omitempty"`
	GroupKey  string              `json:"groupKey"`
	Cosigners []string            `json:"cosigners"`
	Refusals  []map[string]string `json:"refusals"`
	Error     string              `json:"error,omitempty"`
}

// release runs FROST signing for one escrow release. All four validators
// are asked to commit; the three that agree on the same message (the one at
// least three of them computed) sign. If a chosen signer fails in round 2,
// a whole new round runs without it: nonces are never reused (each session
// is deleted when taken), so a retry always means fresh commitments.
func (rc *releaseCoordinator) release(req json.RawMessage) (int, releaseResult) {
	res := releaseResult{GroupKey: rc.groupKey, Cosigners: []string{}, Refusals: []map[string]string{}}
	exclude := map[int]bool{}
	var code int
	for attempt := 0; attempt < 2; attempt++ {
		var failed []int
		code, failed = rc.round(req, exclude, &res)
		if code == 200 || len(failed) == 0 {
			return code, res
		}
		for _, f := range failed {
			exclude[f] = true
		}
		if len(exclude) > frostMax-frostMin {
			break
		}
		res.Cosigners, res.Error = []string{}, ""
	}
	return code, res
}

type frostCommit struct {
	Validator   string          `json:"validator"`
	Participant int             `json:"participant"`
	Session     string          `json:"session"`
	Message     string          `json:"message"`
	Commitments json.RawMessage `json:"commitments"`
	Error       string          `json:"error"`
}

// pickSigners groups the commitments by message and returns the first three
// that share the message at least three validators agreed on.
func pickSigners(commits []frostCommit) ([]frostCommit, string) {
	count := map[string]int{}
	for _, c := range commits {
		if c.Error == "" {
			count[c.Message]++
		}
	}
	var msg string
	for m, n := range count {
		if n >= frostMin {
			msg = m
		}
	}
	if msg == "" {
		return nil, ""
	}
	var chosen []frostCommit
	for _, c := range commits {
		if c.Error == "" && c.Message == msg && len(chosen) < frostMin {
			chosen = append(chosen, c)
		}
	}
	return chosen, msg
}

// round is one commit + sign round. failed lists validators (0-based) whose
// round-2 share failed, so the caller can retry without them.
func (rc *releaseCoordinator) round(req json.RawMessage, exclude map[int]bool, res *releaseResult) (int, []int) {
	commits := make([]frostCommit, frostMax)
	var wg sync.WaitGroup
	for i := 0; i < frostMax; i++ {
		if exclude[i] {
			commits[i] = frostCommit{Validator: names[i], Error: "left out after a failed share"}
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := frostCommit{Validator: names[i]}
			code, err := rc.post(i, "/frost/commit", req, &c)
			if err != nil {
				c.Error = "offline"
			} else if code != 200 && c.Error == "" {
				c.Error = fmt.Sprintf("http %d", code)
			}
			if c.Error == "" && c.Participant != i+1 {
				c.Error = "wrong participant"
			}
			commits[i] = c
		}(i)
	}
	wg.Wait()
	var reasons []string
	res.Refusals = res.Refusals[:0]
	for _, c := range commits {
		if c.Error != "" {
			res.Refusals = append(res.Refusals, map[string]string{"validator": c.Validator, "error": c.Error})
			reasons = append(reasons, c.Validator+": "+c.Error)
		}
	}
	chosen, msg := pickSigners(commits)
	if len(chosen) < frostMin {
		n := 0
		for _, c := range commits {
			if c.Error == "" {
				n++
			}
		}
		if n >= frostMin {
			reasons = append(reasons, "validators computed different release messages")
		}
		res.Error = fmt.Sprintf("only %d of 4 validators agreed: %s", len(chosen), strings.Join(reasons, "; "))
		return 409, nil
	}
	cm := map[string]json.RawMessage{}
	for _, c := range chosen {
		cm[strconv.Itoa(c.Participant)] = c.Commitments
	}
	var sp struct {
		SigningPackage json.RawMessage `json:"signing_package"`
	}
	if err := frostCall("package", map[string]any{"commitments": cm, "message": msg}, &sp); err != nil {
		res.Error = "could not build signing package: " + err.Error()
		return 500, nil
	}
	shares := map[string]json.RawMessage{}
	var smu sync.Mutex
	var failed []string
	var failedIdx []int
	for _, c := range chosen {
		wg.Add(1)
		go func(c frostCommit) {
			defer wg.Done()
			var o struct {
				Share json.RawMessage `json:"share"`
				Error string          `json:"error"`
			}
			code, err := rc.post(c.Participant-1, "/frost/sign", map[string]any{"session": c.Session, "signing_package": sp.SigningPackage}, &o)
			smu.Lock()
			defer smu.Unlock()
			if err != nil || code != 200 || len(o.Share) == 0 {
				failed = append(failed, fmt.Sprintf("%s: %s", c.Validator, firstNonEmpty(o.Error, "no share")))
				failedIdx = append(failedIdx, c.Participant-1)
				return
			}
			shares[strconv.Itoa(c.Participant)] = o.Share
		}(c)
	}
	wg.Wait()
	if len(failed) > 0 {
		res.Error = "signing round failed: " + strings.Join(failed, "; ")
		return 502, failedIdx
	}
	var agg struct {
		Signature string `json:"signature"`
		GroupKey  string `json:"group_key"`
	}
	if err := frostCall("aggregate", map[string]any{"signing_package": sp.SigningPackage, "shares": shares, "public_key_package": rc.pkp}, &agg); err != nil {
		res.Error = "aggregate failed: " + err.Error()
		return 502, nil
	}
	// Independent check in Go before anything reaches the mint.
	h, _ := hex.DecodeString(msg)
	if agg.GroupKey != rc.groupKey || !schnorrVerifyHash(h, rc.groupKey, agg.Signature) {
		res.Error = "aggregated signature does not verify"
		return 502, nil
	}
	for _, c := range chosen {
		res.Cosigners = append(res.Cosigners, c.Validator)
	}
	res.Signature = agg.Signature
	return 200, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
