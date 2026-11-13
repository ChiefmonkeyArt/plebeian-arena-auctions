package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	"github.com/cometbft/cometbft/types"
)

var names = []string{"Validator 1", "Validator 2", "Validator 3", "Validator 4"}

func p2pPort(i int) int  { return 26656 + 10*i }
func rpcPort(i int) int  { return 26657 + 10*i }
func httpPort(i int) int { return 7101 + i }

func homeOf(root string, i int) string { return filepath.Join(root, fmt.Sprintf("v%d", i+1)) }

func nodeConfig(home string, i int, peers string) *cfg.Config {
	c := cfg.DefaultConfig()
	c.SetRoot(home)
	c.Moniker = names[i]
	c.P2P.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", p2pPort(i))
	c.P2P.PersistentPeers = peers
	c.P2P.AddrBookStrict = false
	c.P2P.AllowDuplicateIP = true
	c.P2P.PexReactor = false
	c.RPC.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", rpcPort(i))
	// v0.4.0 (ADR 0003 §1): blocks only when there is something to commit,
	// plus a heartbeat every minute. Bids no longer wait for a 1 s slot,
	// and the auction closes are driven by the validators' close txs.
	c.Consensus.TimeoutCommit = 300 * time.Millisecond
	c.Consensus.TimeoutPropose = 1500 * time.Millisecond
	c.Consensus.CreateEmptyBlocks = true
	c.Consensus.CreateEmptyBlocksInterval = 60 * time.Second
	// ADR 0003 §4: nothing queries txs by hash or old ABCI results; the
	// ledger archive keeps the history instead.
	c.TxIndex.Indexer = "null"
	c.Storage.DiscardABCIResponses = true
	c.Instrumentation.Prometheus = false
	c.LogLevel = "error"
	return c
}

// chainFormat changes whenever stored state from an older release can no
// longer be trusted by this one (v0.3.0: strict lock parser, SIG_ALL with
// amounts, Nutshell 0.21 keysets). "arena init -if-needed" wipes on mismatch.
// v0.4.0: "4" (hash excludes height/time, void bids, PBTS, close txs).
// v0.5.0: "5" (two auction modes, push settlement, settle txs).
const chainFormat = "5"

// archiveOldLedgers keeps each validator's tx ledger from a chain that is
// about to be wiped, as run/chain-archive/<format>-<unix>/vN-ledger.jsonl.
func archiveOldLedgers(root string) {
	old := "unknown"
	if b, err := os.ReadFile(filepath.Join(root, "FORMAT")); err == nil {
		old = strings.TrimSpace(string(b))
	}
	dir := filepath.Join(filepath.Dir(root), "chain-archive", fmt.Sprintf("format%s-%d", old, time.Now().Unix()))
	for i := 0; i < 4; i++ {
		src := ledgerPath(homeOf(root, i))
		if st, err := os.Stat(src); err != nil || st.Size() == 0 {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("archive: %v", err)
			return
		}
		dst := filepath.Join(dir, fmt.Sprintf("v%d-ledger.jsonl", i+1))
		if err := os.Rename(src, dst); err != nil {
			log.Printf("archive %s: %v", src, err)
			continue
		}
		fmt.Printf("archived %s to %s\n", src, dst)
	}
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	root := fs.String("root", "run/chain", "chain root dir")
	mint := fs.String("mint", "http://127.0.0.1:3338", "mint url")
	margin := fs.Int64("lock-margin", 86400, "seconds between hard close and the bid refund locktime; the seller must collect within this window")
	ifNeeded := fs.Bool("if-needed", false, "keep an existing chain whose format marker matches; otherwise wipe and re-initialise")
	fs.Parse(args)
	if *margin < 10 {
		log.Fatal("-lock-margin must be at least 10 seconds")
	}
	if *ifNeeded {
		if b, err := os.ReadFile(filepath.Join(*root, "FORMAT")); err == nil && strings.TrimSpace(string(b)) == chainFormat {
			fmt.Printf("chain in %s is format %s, keeping it\n", *root, chainFormat)
			return
		}
	}

	// pin the mint's active sat keyset
	var ks struct {
		Keysets []struct {
			ID     string `json:"id"`
			Unit   string `json:"unit"`
			Active bool   `json:"active"`
		} `json:"keysets"`
	}
	mustGetJSON(*mint+"/v1/keysets", &ks)
	kid := ""
	for _, k := range ks.Keysets {
		if k.Unit == "sat" && k.Active {
			kid = k.ID
		}
	}
	if kid == "" {
		log.Fatal("no active sat keyset")
	}
	var keys struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	mustGetJSON(*mint+"/v1/keys/"+kid, &keys)

	archiveOldLedgers(*root)
	os.RemoveAll(*root)
	var vals []types.GenesisValidator
	var nodeIDs []string
	for i := 0; i < 4; i++ {
		home := homeOf(*root, i)
		c := nodeConfig(home, i, "")
		cfg.EnsureRoot(home)
		os.MkdirAll(filepath.Join(home, "data"), 0o700)
		pv, err := privval.GenFilePV(c.PrivValidatorKeyFile(), c.PrivValidatorStateFile(), func() (crypto.PrivKey, error) { return ed25519.GenPrivKey(), nil })
		check(err)
		pv.Save()
		nk, err := p2p.LoadOrGenNodeKey(c.NodeKeyFile())
		check(err)
		nodeIDs = append(nodeIDs, string(nk.ID()))
		pub, _ := pv.GetPubKey()
		vals = append(vals, types.GenesisValidator{Address: pub.Address(), PubKey: pub, Power: 10, Name: names[i]})
	}
	// FROST key ceremony: four shares of one escrow key, 3 needed to sign.
	// Each share is written only to its own validator's home. (On a single
	// host the operator can still read all four; separate machines fix that.)
	shares, pkp, groupKey, err := frostDKG()
	check(err)
	for i := 0; i < 4; i++ {
		kb, _ := json.MarshalIndent(frostKeyFile{Participant: i + 1, KeyPackage: shares[i], GroupKey: groupKey}, "", " ")
		check(os.WriteFile(filepath.Join(homeOf(*root, i), "config", "frost_key.json"), kb, 0o600))
	}
	params := Params{MintURL: *mint, KeysetID: kid, Keys: keys.Keysets[0].Keys, GroupKey: groupKey, FrostPublic: pkp, ValidatorNames: names,
		MinWindowSec: 15, MaxWindowSec: 900, LockMarginSec: *margin, MinDurationSec: 20, MaxDurationSec: 7200,
		MaxProofs: 64, Threshold: 3}
	ab, _ := json.Marshal(params)
	// PBTS (v0.4.0): block time is the proposer's clock, checked by every
	// validator against its own within 505 ms + message delay. Under the old
	// BFT time a block after an idle minute could be stamped up to a minute
	// in the past, which would close lots late and let late bids in.
	cp := types.DefaultConsensusParams()
	cp.Feature.PbtsEnableHeight = 1
	// A proposer may stamp a block up to MessageDelay+Precision in the past
	// and still be "timely". 2 s (CometBFT's default is 15 s) bounds how far
	// a dishonest proposer can backdate a late bid; CometBFT widens it by
	// 10% per failed round, so slow links cost a round, not liveness.
	cp.Synchrony.MessageDelay = 2 * time.Second
	gen := &types.GenesisDoc{ChainID: "arena-auctions-fake-sats", GenesisTime: time.Now().UTC(), ConsensusParams: cp,
		Validators: vals, AppState: ab}
	check(gen.ValidateAndComplete())
	for i := 0; i < 4; i++ {
		home := homeOf(*root, i)
		check(gen.SaveAs(filepath.Join(home, "config", "genesis.json")))
		var peers []string
		for j := 0; j < 4; j++ {
			if j != i {
				peers = append(peers, fmt.Sprintf("%s@127.0.0.1:%d", nodeIDs[j], p2pPort(j)))
			}
		}
		check(os.WriteFile(filepath.Join(home, "peers.txt"), []byte(strings.Join(peers, ",")), 0o600))
	}
	check(os.WriteFile(filepath.Join(*root, "FORMAT"), []byte(chainFormat+"\n"), 0o600))
	fmt.Printf("initialised 4 validators in %s, keyset %s, FROST group key %s, lock margin %ds\n", *root, kid, groupKey, *margin)
}

func cmdNode(args []string) {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	root := fs.String("root", "run/chain", "chain root dir")
	idx := fs.Int("i", 1, "validator number 1-4")
	every := fs.Int64("snapshot-every", 1000, "write a state snapshot every N blocks (0: only on clean shutdown)")
	retain := fs.Int64("retain-blocks", 100000, "prune blocks more than N below the newest snapshot (0: keep every block)")
	var relays relayURLs
	fs.Var(&relays, "relay", "relay websocket URL to ingest auction events from (repeatable)")
	fs.Parse(args)
	if *every < 0 || *retain < 0 {
		log.Fatal("-snapshot-every and -retain-blocks must be >= 0")
	}
	i := *idx - 1
	home := homeOf(*root, i)
	peers, err := os.ReadFile(filepath.Join(home, "peers.txt"))
	check(err)
	c := nodeConfig(home, i, string(peers))
	pv := privval.LoadFilePV(c.PrivValidatorKeyFile(), c.PrivValidatorStateFile())
	nk, err := p2p.LoadOrGenNodeKey(c.NodeKeyFile())
	check(err)
	var fk frostKeyFile
	kb, err := os.ReadFile(filepath.Join(home, "config", "frost_key.json"))
	check(err)
	check(json.Unmarshal(kb, &fk))
	if fk.Participant != i+1 {
		log.Fatal("frost_key.json belongs to another validator")
	}
	sessions := &frostSessions{m: map[string]frostSession{}}

	app := NewApp()
	// ADR 0003 §2: start from the newest verified snapshot, if any.
	app.snap = &snapshotter{dir: snapshotDir(home), every: *every}
	snap, err := loadSnapshot(app.snap.dir, cometRecord(c))
	if err != nil {
		log.Fatalf("%s: %v (delete that file to start from the previous snapshot, or from genesis)", names[i], err)
	}
	if snap != nil {
		app.restore(snap)
		app.snap.last = snap.height
		log.Printf("%s: restored state snapshot at height %d", names[i], snap.height)
	}
	app.ledger, err = openLedger(ledgerPath(home))
	check(err)
	defer app.ledger.close()
	app.retain = *retain
	logger := cmtlog.NewFilter(cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout)), cmtlog.AllowError())
	n, err := node.NewNode(context.Background(), c, pv, nk, proxy.NewLocalClientCreator(app),
		node.DefaultGenesisDocProviderFunc(c), cfg.DefaultDBProvider, node.DefaultMetricsProvider(c.Instrumentation), logger)
	check(err)
	check(n.Start())
	log.Printf("%s up: p2p %d rpc %d http %d", names[i], p2pPort(i), rpcPort(i), httpPort(i))
	stopCloser := make(chan struct{})
	go runCloser(app, fmt.Sprintf("http://127.0.0.1:%d", rpcPort(i)), stopCloser)

	mux := http.NewServeMux()
	cache := &committedCache{}
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("view") != "client" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(app.Snapshot())
			return
		}
		cv := clientView(cache.get(app), parseBidders(q.Get("bidders")), parseClosed(q.Get("closed")))
		cv.Now = time.Now().UnixMilli()
		body, tag := encodeView(cv)
		w.Header().Set("ETag", tag)
		w.Header().Set("Cache-Control", "no-cache")
		if etagMatch(r.Header.Get("If-None-Match"), tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	// one committed bid with its proofs (the browser needs them to release it)
	mux.HandleFunc("/bid", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if !lowerHex(id, 64) {
			writeJSON(w, 400, map[string]string{"error": "id must be 64 lowercase hex"})
			return
		}
		b := cache.get(app).Bids[id]
		if b == nil {
			writeJSON(w, 404, map[string]string{"error": "no such bid"})
			return
		}
		writeJSON(w, 200, b)
	})
	// /height?after=N waits (up to 20 s) until a block above N is committed:
	// the gateway long-polls it instead of asking ten times a second (v0.5.0).
	mux.HandleFunc("/height", func(w http.ResponseWriter, r *http.Request) {
		h, _, _, _ := app.committedSnapshot()
		if a := r.URL.Query().Get("after"); a != "" {
			after, err := strconv.ParseInt(a, 10, 64)
			if err == nil && after >= h {
				h = app.waitCommit(r.Context(), after, 20*time.Second)
			}
		}
		writeJSON(w, 200, map[string]int64{"height": h})
	})
	// escrows due to move now, with their proofs (push settlement, ADR 0009)
	mux.HandleFunc("/due", func(w http.ResponseWriter, r *http.Request) {
		st := cache.get(app)
		w.Header().Set("X-Height", strconv.FormatInt(st.Height, 10))
		writeJSON(w, 200, st.dueMoves(time.Now().Unix()))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		bs := n.BlockStore()
		h := bs.Height()
		out := map[string]any{"name": names[i], "index": i + 1, "height": h, "peers": n.Switch().Peers().Size(), "frostParticipant": fk.Participant, "groupKey": fk.GroupKey}
		if meta := bs.LoadBlockMeta(h); meta != nil {
			out["time"] = meta.Header.Time.Unix()
			out["appHash"] = hex.EncodeToString(meta.Header.AppHash)
			out["blockHash"] = meta.BlockID.Hash.String()
			out["txs"] = meta.NumTxs
		}
		if cm := bs.LoadSeenCommit(h); cm != nil {
			signed := []bool{}
			for _, s := range cm.Signatures {
				signed = append(signed, s.BlockIDFlag == types.BlockIDFlagCommit)
			}
			out["signers"] = signed
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("/frost/commit", func(w http.ResponseWriter, r *http.Request) { handleCommit(w, r, app, fk, sessions, i) })
	mux.HandleFunc("/frost/sign", func(w http.ResponseWriter, r *http.Request) { handleShare(w, r, fk, sessions, i) })
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", httpPort(i)), Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { log.Println(srv.ListenAndServe()) }()

	// Relay ingest: subscribe to the configured relay(s) and submit every
	// verified auction/bid event into THIS node's mempool.  One observer per
	// relay, per validator; a client thus never has to know which node leads.
	stopIngest, err := startRelayIngest(context.Background(), relays, fmt.Sprintf("http://127.0.0.1:%d", rpcPort(i)), log.Default())
	check(err)
	defer stopIngest()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	stopIngest()
	srv.Close()
	close(stopCloser)
	n.Stop()
	n.Wait()
	// clean shutdown: snapshot the last committed state so the next start
	// replays nothing
	if h, t, hash, raw := app.committedSnapshot(); h > 0 {
		if err := app.snap.write(h, t, hash, raw); err != nil {
			log.Printf("%s: shutdown snapshot %d: %v", names[i], h, err)
		} else {
			log.Printf("%s: wrote state snapshot at height %d", names[i], h)
		}
	}
}

// sigAllMessage is the NUT-11 SIG_ALL message as Nutshell 0.21 builds it:
// each input's secret and C, then each output's amount and B_. Covering the
// amounts stops a relay from re-denominating the outputs (internal audit A6).
func sigAllMessage(proofs []Proof, outs []SignOutput) string {
	var sb strings.Builder
	for _, p := range proofs {
		sb.WriteString(p.Secret)
		sb.WriteString(p.C)
	}
	for _, o := range outs {
		sb.WriteString(strconv.FormatInt(o.Amount, 10))
		sb.WriteString(o.B)
	}
	return sb.String()
}

type SignOutput struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	B      string `json:"B_"`
}

// Reveal is one pushed output's secret and blinding factor, so a validator
// can see what it is signing for: B_ = hash_to_curve(secret) + r*G.
type Reveal struct {
	Secret string `json:"secret"`
	R      string `json:"r"`
}

type SignReq struct {
	Bid     string       `json:"bid"`
	Move    string       `json:"move,omitempty"`   // push: refund | payout | relock
	Reveal  []Reveal     `json:"reveal,omitempty"` // push: one per output
	Purpose string       `json:"purpose"` // refund | payout (pull, wallet-authorised) | push (validators' own settlement)
	Outputs []SignOutput `json:"outputs"`
	Auth    string       `json:"auth"` // BIP340 sig by the bidder (refund) or seller (payout) wallet over the SIG_ALL hash
	// Height the asker read the state at: a validator a block behind waits
	// for it (at most 2 s) before judging, instead of refusing (v0.5.0)
	Height int64 `json:"height,omitempty"`
}

// releasePolicy: this validator agrees to a release of escrowed proofs only
// when its own copy of the agreed state allows it, and the right wallet has
// authorised it. Returns the SIG_ALL hash the escrow signature must cover.
func releasePolicy(app *App, req SignReq) (h [32]byte, code int, err error) {
	var msg, authKey string
	app.Read(func(s *State) {
		bid, ok := s.Bids[req.Bid]
		if !ok {
			err = errors.New("unknown bid")
			return
		}
		au := s.Auctions[bid.Auction]
		if bid.Settled != "" {
			err = errors.New("escrow already settled")
			return
		}
		if req.Purpose == "push" {
			// no wallet authorises a push: the outputs themselves must be
			// locked to the key the agreed state names (ADR 0009)
			now := time.Now().Unix()
			var to string
			if to, err = s.moveDue(bid, req.Move, now, true); err != nil {
				return
			}
			if len(req.Reveal) != len(req.Outputs) {
				err = errors.New("every pushed output must be revealed")
				return
			}
			secrets := make([]string, len(req.Reveal))
			for k, rv := range req.Reveal {
				b, e := blinded(rv.Secret, rv.R)
				if e != nil || b != req.Outputs[k].B {
					err = errors.New("output does not match its revealed secret")
					return
				}
				secrets[k] = rv.Secret
			}
			if _, err = s.checkOutputs(bid, req.Move, to, req.Outputs, secrets, now+s.Params.LockMarginSec-2*lockGraceSec); err != nil {
				return
			}
			msg = sigAllMessage(bid.Proofs, req.Outputs)
			return
		}
		switch req.Purpose {
		case "refund":
			if bid.Status != "outbid" && bid.Status != "lost" && bid.Status != "void" {
				err = fmt.Errorf("bid is %s, not refundable", bid.Status)
				return
			}
			authKey = bid.Wallet
		case "payout":
			if au.Status != "closed" || au.Winner != bid.ID {
				err = errors.New("only the winning bid of a closed auction pays out")
				return
			}
			authKey = au.SellerWallet
		default:
			err = errors.New("purpose must be refund or payout")
			return
		}
		if len(req.Outputs) == 0 || len(req.Outputs) > 64 {
			err = errors.New("bad output count")
			return
		}
		var sum int64
		for _, o := range req.Outputs {
			if o.ID != s.Params.KeysetID || o.Amount <= 0 || !lowerHex(o.B, 66) {
				err = errors.New("bad output")
				return
			}
			if _, ok := s.Params.Keys[fmt.Sprint(o.Amount)]; !ok {
				err = errors.New("bad output amount")
				return
			}
			if sum > math.MaxInt64-o.Amount {
				err = errors.New("output total overflows")
				return
			}
			sum += o.Amount
		}
		if sum != bid.Amount {
			err = fmt.Errorf("outputs total %d, escrow is %d", sum, bid.Amount)
			return
		}
		msg = sigAllMessage(bid.Proofs, req.Outputs)
	})
	if err != nil {
		return h, 409, err
	}
	h = sha256.Sum256([]byte(msg))
	if req.Purpose == "push" {
		return h, 200, nil
	}
	if !schnorrVerifyHash(h[:], authKey, req.Auth) {
		return h, 403, errors.New("authorisation signature invalid")
	}
	return h, 200, nil
}

// handleCommit: FROST round 1. If policy allows the release, make fresh
// one-time nonces bound to this exact release and publish their commitments.
func handleCommit(w http.ResponseWriter, r *http.Request, app *App, fk frostKeyFile, ss *frostSessions, i int) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req SignReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	if req.Height > 0 {
		app.waitCommit(r.Context(), req.Height-1, 2*time.Second)
	}
	h, code, err := releasePolicy(app, req)
	if err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error(), "validator": names[i]})
		return
	}
	var out struct {
		Nonces      json.RawMessage `json:"nonces"`
		Commitments json.RawMessage `json:"commitments"`
	}
	if err := frostCall("commit", map[string]any{"key_package": fk.KeyPackage}, &out); err != nil {
		writeJSON(w, 500, map[string]string{"error": "commit failed", "validator": names[i]})
		return
	}
	id, err := ss.put(out.Nonces, hex.EncodeToString(h[:]), req.Bid)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": err.Error(), "validator": names[i]})
		return
	}
	writeJSON(w, 200, map[string]any{"validator": names[i], "participant": fk.Participant, "session": id, "message": hex.EncodeToString(h[:]), "commitments": out.Commitments})
}

// handleShare: FROST round 2. Sign only the release agreed in round 1; the
// nonces are deleted before use so they can never sign twice.
func handleShare(w http.ResponseWriter, r *http.Request, fk frostKeyFile, ss *frostSessions, i int) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		Session        string          `json:"session"`
		SigningPackage json.RawMessage `json:"signing_package"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	sess, ok := ss.take(req.Session)
	if !ok {
		writeJSON(w, 409, map[string]string{"error": "unknown or expired signing session", "validator": names[i]})
		return
	}
	m, err := signingPackageMessage(req.SigningPackage)
	if err != nil || m != sess.hash {
		writeJSON(w, 409, map[string]string{"error": "signing package is not the release this validator agreed to", "validator": names[i]})
		return
	}
	var out struct {
		Share json.RawMessage `json:"share"`
	}
	if err := frostCall("sign", map[string]any{"key_package": fk.KeyPackage, "nonces": sess.nonces, "signing_package": req.SigningPackage}, &out); err != nil {
		writeJSON(w, 409, map[string]string{"error": "sign failed: " + err.Error(), "validator": names[i]})
		return
	}
	writeJSON(w, 200, map[string]any{"validator": names[i], "participant": fk.Participant, "share": out.Share})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func mustGetJSON(url string, v any) {
	resp, err := http.Get(url)
	check(err)
	defer resp.Body.Close()
	check(json.NewDecoder(resp.Body).Decode(v))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// runCloser sends this validator's close tx for every open auction that is
// due by its own clock, at most once a second per auction, until the chain
// closes it (ADR 0003 §1). With blocks on demand nothing else would make the
// block that closes an idle lot.
func runCloser(app *App, rpc string, stop <-chan struct{}) {
	cl := &http.Client{Timeout: 2 * time.Second}
	sent := map[string]int64{}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		now := time.Now().Unix()
		var due [][2]any
		app.Read(func(s *State) {
			for id, au := range s.Auctions {
				if au.Status == "open" && (au.EndAt <= now || s.expiring(au, now)) {
					due = append(due, [2]any{id, au.EndAt})
				}
			}
		})
		for _, d := range due {
			id, end := d[0].(string), d[1].(int64)
			if sent[id] == now {
				continue
			}
			sent[id] = now
			tx := makeClose(id, end, now)
			resp, err := cl.Get(rpc + "/broadcast_tx_async?tx=0x" + hex.EncodeToString(tx)) // #nosec G107 -- own loopback RPC, hex payload
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		if len(sent) > 1024 {
			sent = map[string]int64{}
		}
	}
}
