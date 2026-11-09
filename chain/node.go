package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	c.Consensus.TimeoutCommit = 1000 * time.Millisecond
	c.Consensus.TimeoutPropose = 1500 * time.Millisecond
	c.Consensus.CreateEmptyBlocks = true
	c.Instrumentation.Prometheus = false
	c.LogLevel = "error"
	return c
}

type signerKey struct {
	Priv string `json:"priv"`
	Pub  string `json:"pub"`
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	root := fs.String("root", "run/chain", "chain root dir")
	mint := fs.String("mint", "http://127.0.0.1:3338", "mint url")
	fs.Parse(args)

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

	os.RemoveAll(*root)
	var vals []types.GenesisValidator
	var nodeIDs []string
	var cashu []string
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
		// Cashu signer key (the validator's share of the 3-of-4 escrow lock)
		var b [32]byte
		rand.Read(b[:])
		sk, _ := btcec.PrivKeyFromBytes(b[:])
		pk := hex.EncodeToString(sk.PubKey().SerializeCompressed())
		cashu = append(cashu, pk)
		kb, _ := json.MarshalIndent(signerKey{Priv: hex.EncodeToString(b[:]), Pub: pk}, "", " ")
		check(os.WriteFile(filepath.Join(home, "config", "cashu_signer.json"), kb, 0o600))
	}
	params := Params{MintURL: *mint, KeysetID: kid, Keys: keys.Keysets[0].Keys, Validators: cashu, ValidatorNames: names,
		SoftCloseSec: 20, ExtendSec: 20, MaxExtendSec: 60, LockMarginSec: 30, MinDurationSec: 20, MaxDurationSec: 7200,
		MaxProofs: 64, Threshold: 3}
	ab, _ := json.Marshal(params)
	gen := &types.GenesisDoc{ChainID: "arena-auctions-fake-sats", GenesisTime: time.Now().UTC(), ConsensusParams: types.DefaultConsensusParams(),
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
	fmt.Printf("initialised 4 validators in %s, keyset %s\n", *root, kid)
}

func cmdNode(args []string) {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	root := fs.String("root", "run/chain", "chain root dir")
	idx := fs.Int("i", 1, "validator number 1-4")
	fs.Parse(args)
	i := *idx - 1
	home := homeOf(*root, i)
	peers, err := os.ReadFile(filepath.Join(home, "peers.txt"))
	check(err)
	c := nodeConfig(home, i, string(peers))
	// in-memory app replays from genesis, so start the block store fresh-compatible:
	pv := privval.LoadFilePV(c.PrivValidatorKeyFile(), c.PrivValidatorStateFile())
	nk, err := p2p.LoadOrGenNodeKey(c.NodeKeyFile())
	check(err)
	var sk signerKey
	kb, err := os.ReadFile(filepath.Join(home, "config", "cashu_signer.json"))
	check(err)
	check(json.Unmarshal(kb, &sk))

	app := NewApp()
	logger := cmtlog.NewFilter(cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout)), cmtlog.AllowError())
	n, err := node.NewNode(context.Background(), c, pv, nk, proxy.NewLocalClientCreator(app),
		node.DefaultGenesisDocProviderFunc(c), cfg.DefaultDBProvider, node.DefaultMetricsProvider(c.Instrumentation), logger)
	check(err)
	check(n.Start())
	log.Printf("%s up: p2p %d rpc %d http %d", names[i], p2pPort(i), rpcPort(i), httpPort(i))

	mux := http.NewServeMux()
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(app.Snapshot())
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		bs := n.BlockStore()
		h := bs.Height()
		out := map[string]any{"name": names[i], "index": i + 1, "height": h, "peers": n.Switch().Peers().Size(), "cashuPub": sk.Pub}
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
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) { handleSign(w, r, app, sk, i) })
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", httpPort(i)), Handler: mux}
	go func() { log.Println(srv.ListenAndServe()) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Close()
	n.Stop()
	n.Wait()
}

type SignOutput struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	B      string `json:"B_"`
}

type SignReq struct {
	Bid     string       `json:"bid"`
	Purpose string       `json:"purpose"` // refund | payout
	Outputs []SignOutput `json:"outputs"`
	Auth    string       `json:"auth"` // BIP340 sig by the bidder (refund) or seller (payout) wallet over the SIG_ALL hash
}

// handleSign: this validator co-signs a release of escrowed proofs only when its own
// copy of the agreed state says the release is allowed.
func handleSign(w http.ResponseWriter, r *http.Request, app *App, sk signerKey, i int) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var req SignReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	var msg string
	var authKey string
	var err error
	app.Read(func(s *State) {
		bid, ok := s.Bids[req.Bid]
		if !ok {
			err = errors.New("unknown bid")
			return
		}
		au := s.Auctions[bid.Auction]
		switch req.Purpose {
		case "refund":
			if bid.Status != "outbid" && bid.Status != "lost" {
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
		var sum int64
		var sb strings.Builder
		for _, p := range bid.Proofs {
			sb.WriteString(p.Secret)
		}
		for _, o := range req.Outputs {
			if o.ID != s.Params.KeysetID || o.Amount <= 0 || len(o.B) != 66 {
				err = errors.New("bad output")
				return
			}
			if _, ok := s.Params.Keys[fmt.Sprint(o.Amount)]; !ok {
				err = errors.New("bad output amount")
				return
			}
			sum += o.Amount
			sb.WriteString(o.B)
		}
		if sum != bid.Amount {
			err = fmt.Errorf("outputs total %d, escrow is %d", sum, bid.Amount)
			return
		}
		msg = sb.String()
	})
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error(), "validator": names[i]})
		return
	}
	h := sha256.Sum256([]byte(msg))
	if !schnorrVerifyHash(h[:], authKey, req.Auth) {
		writeJSON(w, 403, map[string]string{"error": "authorisation signature invalid", "validator": names[i]})
		return
	}
	kb, _ := hex.DecodeString(sk.Priv)
	priv, _ := btcec.PrivKeyFromBytes(kb)
	sig, e := schnorr.Sign(priv, h[:])
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": "sign failed"})
		return
	}
	writeJSON(w, 200, map[string]string{"validator": names[i], "pubkey": sk.Pub, "signature": hex.EncodeToString(sig.Serialize())})
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
