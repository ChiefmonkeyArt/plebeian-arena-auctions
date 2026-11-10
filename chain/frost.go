package main

// FROST 3-of-4 escrow key. The four validators hold one share each of a key
// made by distributed key generation (no complete private key ever exists).
// Bids are locked to the group key; a release needs a signature that only
// three cooperating validators can produce. The maths is done by the
// arena-frost tool (Zcash Foundation frost-secp256k1-tr), called over stdin.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// frostCall runs one arena-frost command: JSON in on stdin, JSON out.
func frostCall(cmd string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
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
	exp    time.Time
}

type frostSessions struct {
	mu sync.Mutex
	m  map[string]frostSession
}

func (s *frostSessions) put(nonces json.RawMessage, hash string) (string, error) {
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
	s.m[id] = frostSession{nonces: nonces, hash: hash, exp: now.Add(time.Minute)}
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
	return &releaseCoordinator{pkp: g.AppState.FrostPublic, groupKey: g.AppState.GroupKey, post: post}, nil
}

type releaseResult struct {
	Signature string              `json:"signature,omitempty"`
	GroupKey  string              `json:"groupKey"`
	Cosigners []string            `json:"cosigners"`
	Refusals  []map[string]string `json:"refusals"`
	Error     string              `json:"error,omitempty"`
}

func (rc *releaseCoordinator) release(req json.RawMessage) (int, releaseResult) {
	type commit struct {
		Validator   string          `json:"validator"`
		Participant int             `json:"participant"`
		Session     string          `json:"session"`
		Message     string          `json:"message"`
		Commitments json.RawMessage `json:"commitments"`
		Error       string          `json:"error"`
	}
	res := releaseResult{GroupKey: rc.groupKey, Cosigners: []string{}, Refusals: []map[string]string{}}
	commits := make([]commit, frostMax)
	var wg sync.WaitGroup
	for i := 0; i < frostMax; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := commit{Validator: names[i]}
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
	// Use the first three validators that agreed on the same release hash.
	var chosen []commit
	var msg string
	var reasons []string
	for _, c := range commits {
		if c.Error != "" {
			res.Refusals = append(res.Refusals, map[string]string{"validator": c.Validator, "error": c.Error})
			reasons = append(reasons, c.Validator+": "+c.Error)
			continue
		}
		if msg == "" {
			msg = c.Message
		}
		if c.Message != msg || len(chosen) == frostMin {
			continue
		}
		chosen = append(chosen, c)
	}
	if len(chosen) < frostMin {
		res.Error = fmt.Sprintf("only %d of 4 validators agreed: %s", len(chosen), strings.Join(reasons, "; "))
		return 409, res
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
		return 500, res
	}
	shares := map[string]json.RawMessage{}
	var smu sync.Mutex
	var failed []string
	for _, c := range chosen {
		wg.Add(1)
		go func(c commit) {
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
				return
			}
			shares[strconv.Itoa(c.Participant)] = o.Share
		}(c)
	}
	wg.Wait()
	if len(failed) > 0 {
		res.Error = "signing round failed: " + strings.Join(failed, "; ")
		return 502, res
	}
	var agg struct {
		Signature string `json:"signature"`
		GroupKey  string `json:"group_key"`
	}
	if err := frostCall("aggregate", map[string]any{"signing_package": sp.SigningPackage, "shares": shares, "public_key_package": rc.pkp}, &agg); err != nil {
		res.Error = "aggregate failed: " + err.Error()
		return 502, res
	}
	// Independent check in Go before anything reaches the mint.
	h, _ := hex.DecodeString(msg)
	if agg.GroupKey != rc.groupKey || !schnorrVerifyHash(h, rc.groupKey, agg.Signature) {
		res.Error = "aggregated signature does not verify"
		return 502, res
	}
	for _, c := range chosen {
		res.Cosigners = append(res.Cosigners, c.Validator)
	}
	res.Signature = agg.Signature
	return 200, res
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
