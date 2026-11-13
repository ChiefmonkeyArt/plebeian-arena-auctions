package main

// The gateway's settler (ADR 0009, v0.5.0; 2-of-2 rework, spec §5): the moment
// a block makes an escrow move due (a refund, the winner's settle), it asks
// the validators for one FROST signature over the bid's COMMITTED outcome
// template, swaps the escrow at the mint into that template's own outputs,
// pushes the new ecash to the page over the event stream and records it on
// chain with a settle tx.
//
// The settler is an EXECUTOR, not an author. It builds no outputs and chooses
// no destination: the outputs are the bidder's, fixed by its pre-signature in
// the committed template. It names the bid and the outcome (settle|refund);
// every validator re-derives the committed template's outputs from its own
// copy of the chain and signs that exact digest, so the most a broken gateway
// can do is DELAY a settlement. The old pull-release endpoint is gone (spec §5):
// the bidder's half is already pre-signed, and the committee's half is
// collected automatically, so there is nothing for a page to request.
//
// Crash safety: every attempt is journalled (the committed template's outputs,
// secrets, blinding factors, and the bidder signature) before the mint swap.
// If the swap went through but the gateway died before it saw the answer, the
// mint's restore endpoint (NUT-09) gives back the same blind signatures.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const settleWorkers = 4

// backoff: an escrow that failed to settle (say its owner already spent it,
// or the mint is down) is retried after 5 s, 10 s, 20 s ... up to 10 min,
// so a stuck escrow does not cost a mint request every block.
type backoff struct {
	n    int
	next time.Time
}

// settleAttempt journals one submission of a committed outcome template. The
// outputs and their openings are the template's own; the bidder signature is
// the one carried in the committed bid.
type settleAttempt struct {
	Bid       string       `json:"bid"`
	Outcome   string       `json:"outcome"`
	To        string       `json:"to"`
	Auction   string       `json:"auction,omitempty"`
	Outputs   []SignOutput `json:"outputs"`          // the committed template's outputs (recomputed B_)
	Reveal    []Reveal     `json:"reveal"`           // their secrets and openings, from the committed template
	BidderSig string       `json:"bidder_sig"`       // the bidder's pre-signature over the committed digest
	Sig       string       `json:"sig,omitempty"`    // the committee's FROST signature
	Proofs    []Proof      `json:"proofs,omitempty"` // set once unblinded
	At        int64        `json:"at"`
}

type settler struct {
	rc      *releaseCoordinator
	p       Params
	mint    string
	running func(int) bool
	hub     *eventHub
	journal string
	hc      *http.Client

	mu       sync.Mutex
	inflight map[string]bool
	tries    map[string][]*settleAttempt // bid -> journalled attempts
	done     map[string]*settleAttempt   // bid -> attempt with proofs (tx maybe not yet on chain)
	backoff  map[string]backoff          // bid -> when to try again after a failure
	kick     chan struct{}
}

func newSettler(rc *releaseCoordinator, mint string, running func(int) bool, hub *eventHub, journal string) *settler {
	s := &settler{rc: rc, p: rc.params, mint: strings.TrimRight(mint, "/"), running: running, hub: hub, journal: journal,
		hc:       &http.Client{Timeout: 10 * time.Second},
		inflight: map[string]bool{}, backoff: map[string]backoff{}, tries: map[string][]*settleAttempt{}, done: map[string]*settleAttempt{},
		kick: make(chan struct{}, 1)}
	s.loadJournal()
	return s
}

func (s *settler) loadJournal() {
	f, err := os.Open(s.journal)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		var a settleAttempt
		if json.Unmarshal(sc.Bytes(), &a) != nil || a.Bid == "" {
			continue
		}
		if len(a.Proofs) > 0 {
			s.done[a.Bid] = &a
		} else {
			s.tries[a.Bid] = append(s.tries[a.Bid], &a)
		}
	}
}

func (s *settler) write(a *settleAttempt) error {
	f, err := os.OpenFile(s.journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(a)
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// run follows the chain: every new block, and every 5 s as a safety net.
func (s *settler) run() {
	s.hub.watch(func(int64) { s.poke() })
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	s.poke()
	for {
		select {
		case <-s.kick:
		case <-t.C:
		}
		s.sweep()
	}
}

func (s *settler) poke() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *settler) validator() int {
	for i := 0; i < 4; i++ {
		if s.running(i) {
			return i
		}
	}
	return -1
}

func (s *settler) due() ([]dueMove, int64, error) {
	i := s.validator()
	if i < 0 {
		return nil, 0, errors.New("no validator running")
	}
	resp, err := s.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/due", httpPort(i)))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	h, _ := strconv.ParseInt(resp.Header.Get("X-Height"), 10, 64)
	var out []dueMove
	err = json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out)
	return out, h, err
}

var settleSem = make(chan struct{}, settleWorkers)

func (s *settler) sweep() {
	items, height, err := s.due()
	if err != nil {
		return
	}
	for _, it := range items {
		it := it
		s.mu.Lock()
		busy := s.inflight[it.Bid.ID] || time.Now().Before(s.backoff[it.Bid.ID].next)
		if !busy {
			s.inflight[it.Bid.ID] = true
		}
		s.mu.Unlock()
		if busy {
			continue
		}
		settleSem <- struct{}{}
		go func() {
			defer func() { <-settleSem; s.mu.Lock(); delete(s.inflight, it.Bid.ID); s.mu.Unlock() }()
			err := s.settle(it, height)
			s.mu.Lock()
			if err != nil {
				b := s.backoff[it.Bid.ID]
				d := time.Second << min(b.n, 10)
				if d > 10*time.Minute {
					d = 10 * time.Minute
				}
				s.backoff[it.Bid.ID] = backoff{n: b.n + 1, next: time.Now().Add(d)}
			} else {
				delete(s.backoff, it.Bid.ID)
			}
			s.mu.Unlock()
			if err != nil {
				log.Printf("settle %s %s: %v", it.Outcome, it.Bid.ID[:12], err)
			}
		}()
	}
}

// templateMaterial turns the bid's committed outcome template into the exact
// outputs and openings the swap needs, plus the bidder's pre-signature. If the
// bid carries no such template (an old-shape bid) the move is refused: the
// settler never builds an output of its own.
func (s *settler) templateMaterial(bid *Bid, outcome string) ([]SignOutput, []Reveal, string, error) {
	template, err := sigAllTemplateNamed(bid.OutcomeTemplates, outcome)
	if err != nil {
		return nil, nil, "", err
	}
	outs := make([]SignOutput, 0, len(template.Outputs))
	reveal := make([]Reveal, 0, len(template.Outputs))
	for i, o := range template.Outputs {
		point, err := sigAllOutputPoint(o.Secret, o.R)
		if err != nil {
			return nil, nil, "", fmt.Errorf("committed template output %d: %w", i, err)
		}
		outs = append(outs, SignOutput{Amount: o.Amount, ID: o.ID, B: point})
		reveal = append(reveal, Reveal{Secret: o.Secret, R: o.R})
	}
	if len(outs) == 0 {
		return nil, nil, "", errors.New("committed template has no outputs")
	}
	return outs, reveal, template.BidderSignature, nil
}

// settle moves one due escrow end to end: submit the committed template, take
// the committee's FROST half, swap at the mint with BOTH signatures, record.
func (s *settler) settle(it dueMove, height int64) error {
	t0 := time.Now()
	s.mu.Lock()
	d := s.done[it.Bid.ID]
	s.mu.Unlock()
	if d != nil && d.Outcome == it.Outcome {
		// already minted, the settle tx just has not landed yet
		return s.submit(d)
	}
	// The escrow may already have been swapped by an attempt whose answer we
	// never saw (crash): ask the mint whether its inputs are spent first.
	if spent, _ := s.spent(it.Bid.Proofs); spent {
		return s.recover(it)
	}
	outs, reveal, bidderSig, err := s.templateMaterial(it.Bid, it.Outcome)
	if err != nil {
		return err
	}
	a := &settleAttempt{Bid: it.Bid.ID, Outcome: it.Outcome, To: it.To, Auction: it.Bid.Auction,
		Outputs: outs, Reveal: reveal, BidderSig: bidderSig, At: time.Now().Unix()}
	if err := s.write(a); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	s.mu.Lock()
	s.tries[a.Bid] = append(s.tries[a.Bid], a)
	s.mu.Unlock()
	// The settler names the bid and the outcome only; the validators derive the
	// outputs from the committed template themselves (spec §5).
	req, _ := json.Marshal(SignReq{Bid: a.Bid, Outcome: a.Outcome, Height: height})
	code, res := s.rc.release(req)
	tFrost := time.Since(t0)
	if code != 200 || res.Signature == "" {
		return fmt.Errorf("validators refused (%d): %s %v", code, res.Error, res.Refusals)
	}
	a.Sig = res.Signature
	sigs, err := s.swap(it.Bid.Proofs, a.Outputs, a.BidderSig, a.Sig)
	tMint := time.Since(t0) - tFrost
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "spent") {
			return s.recover(it)
		}
		return err
	}
	if err := s.finish(a, sigs); err != nil {
		return err
	}
	s.announce(a, map[string]int64{"frost": tFrost.Milliseconds(), "mint": tMint.Milliseconds(), "total": time.Since(t0).Milliseconds()}, res.Cosigners)
	return s.submit(a)
}

type blindSig struct {
	ID     string `json:"id"`
	Amount int64  `json:"amount"`
	C_     string `json:"C_"`
	DLEQ   *struct {
		E string `json:"e"`
		S string `json:"s"`
	} `json:"dleq"`
}

func (s *settler) post(path string, body any, out any) (int, []byte, error) {
	b, _ := json.Marshal(body)
	resp, err := s.hc.Post(s.mint+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil {
		json.Unmarshal(raw, out)
	}
	return resp.StatusCode, raw, nil
}

// swap spends the escrow's committed proofs against the committed template's
// outputs, with the witness carrying BOTH signatures: the bidder's (from the
// committed template) and the committee's (from the FROST round). The mint
// needs two, so a committee that is missing the bidder half cannot spend.
func (s *settler) swap(inputs []Proof, outs []SignOutput, bidderSig, committeeSig string) ([]blindSig, error) {
	type in struct {
		ID      string `json:"id"`
		Amount  int64  `json:"amount"`
		Secret  string `json:"secret"`
		C       string `json:"C"`
		Witness string `json:"witness,omitempty"`
	}
	w, _ := json.Marshal(map[string][]string{"signatures": {bidderSig, committeeSig}})
	ins := make([]in, len(inputs))
	for i, p := range inputs {
		ins[i] = in{ID: p.ID, Amount: p.Amount, Secret: p.Secret, C: p.C}
		if i == 0 {
			ins[i].Witness = string(w)
		}
	}
	var r struct {
		Signatures []blindSig `json:"signatures"`
		Detail     string     `json:"detail"`
	}
	code, raw, err := s.post("/v1/swap", map[string]any{"inputs": ins, "outputs": outs}, &r)
	if err != nil {
		return nil, err
	}
	if code != 200 || len(r.Signatures) != len(outs) {
		if r.Detail == "" {
			r.Detail = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("mint swap: %s", r.Detail)
	}
	return r.Signatures, nil
}

// spent asks the mint (NUT-07) whether any escrow proof is already spent.
func (s *settler) spent(proofs []Proof) (bool, error) {
	ys := make([]string, 0, len(proofs))
	for _, p := range proofs {
		y, err := proofY(p.Secret)
		if err != nil {
			return false, err
		}
		ys = append(ys, y)
	}
	var r struct {
		States []struct {
			State string `json:"state"`
		} `json:"states"`
	}
	code, _, err := s.post("/v1/checkstate", map[string]any{"Ys": ys}, &r)
	if err != nil || code != 200 {
		return false, fmt.Errorf("checkstate failed")
	}
	for _, st := range r.States {
		if st.State == "SPENT" {
			return true, nil
		}
	}
	return false, nil
}

// recover: the escrow is spent at the mint but not settled on chain. One of
// the journalled attempts was swapped; the mint's restore gives back its
// blind signatures.
func (s *settler) recover(it dueMove) error {
	s.mu.Lock()
	tries := append([]*settleAttempt(nil), s.tries[it.Bid.ID]...)
	s.mu.Unlock()
	for i := len(tries) - 1; i >= 0; i-- {
		a := tries[i]
		if a.Outcome != it.Outcome {
			continue
		}
		var r struct {
			Outputs    []SignOutput `json:"outputs"`
			Signatures []blindSig   `json:"signatures"`
		}
		code, _, err := s.post("/v1/restore", map[string]any{"outputs": a.Outputs}, &r)
		if err != nil || code != 200 || len(r.Signatures) != len(a.Outputs) || len(r.Outputs) != len(a.Outputs) {
			continue
		}
		if a.Sig == "" {
			// crash between signing and journalling the signature: the
			// proofs are good, but the settle tx needs the group signature
			return errors.New("escrow swapped by an attempt whose signature was not journalled; the bidder's last-resort refund after locktime remains")
		}
		if err := s.finish(a, r.Signatures); err != nil {
			continue
		}
		s.announce(a, map[string]int64{"recovered": 1}, nil)
		return s.submit(a)
	}
	return errors.New("escrow already spent and no journalled attempt matches")
}

// finish unblinds C = C_ - r*A, checks each DLEQ proof and journals the
// proofs (with the group signature).
func (s *settler) finish(a *settleAttempt, sigs []blindSig) error {
	proofs := make([]Proof, len(sigs))
	for i, bs := range sigs {
		o := a.Outputs[i]
		if bs.Amount != o.Amount || bs.ID != o.ID || bs.DLEQ == nil {
			return errors.New("mint answer does not match the outputs")
		}
		A, err := parsePub(s.p.Keys[strconv.FormatInt(o.Amount, 10)])
		if err != nil {
			return err
		}
		Cb, err := parsePub(bs.C_)
		if err != nil {
			return err
		}
		r, err := parseScalar(a.Reveal[i].R)
		if err != nil {
			return err
		}
		C := add(Cb, neg(mul(r, A)))
		pr := Proof{ID: o.ID, Amount: o.Amount, Secret: a.Reveal[i].Secret, C: hex.EncodeToString(C.SerializeCompressed()),
			DLEQ: &DLEQ{E: bs.DLEQ.E, S: bs.DLEQ.S, R: a.Reveal[i].R}}
		if err := verifyDLEQ(pr, A); err != nil {
			return fmt.Errorf("mint DLEQ: %w", err)
		}
		proofs[i] = pr
	}
	a.Proofs = proofs
	if err := s.write(a); err != nil {
		return err
	}
	s.mu.Lock()
	s.done[a.Bid] = a
	s.mu.Unlock()
	return nil
}

// announce pushes refunds and settles to every open page at once; the ecash is
// locked to the recipient's wallet key, so only they can spend it.
func (s *settler) announce(a *settleAttempt, ms map[string]int64, cosigners []string) {
	if s.hub == nil {
		return
	}
	b, _ := json.Marshal(map[string]any{"type": "settled", "bid": a.Bid, "auction": a.Auction, "outcome": a.Outcome, "to": a.To, "proofs": a.Proofs, "ms": ms, "cosigners": cosigners})
	s.hub.broadcast(b)
}

// submit records the settlement on chain.
func (s *settler) submit(a *settleAttempt) error {
	tx := makeSettle(&settleTx{Bid: a.Bid, Outcome: a.Outcome, Proofs: a.Proofs, Sig: a.Sig})
	i := s.validator()
	if i < 0 {
		return errors.New("no validator running")
	}
	resp, err := s.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/broadcast_tx_sync?tx=0x%s", rpcPort(i), hex.EncodeToString(tx))) // #nosec G107 -- own loopback RPC
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var rr struct {
		Result struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
		} `json:"result"`
		Error *struct {
			Data string `json:"data"`
		} `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rr)
	if rr.Error != nil && !strings.Contains(rr.Error.Data, "already exists") {
		return fmt.Errorf("settle tx: %s", rr.Error.Data)
	}
	if rr.Result.Code != 0 {
		return fmt.Errorf("settle tx refused: %s", rr.Result.Log)
	}
	return nil
}
