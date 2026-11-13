package main

// Real-mint integration tests for the 2-of-2 [bidder, committee] SIG_ALL
// escrow lock. They need a throwaway Nutshell >= 0.20.3 (0.21.0) mint with the
// FakeWallet bolt11 backend, so quotes pay themselves. Point them at one with
// ARENA_TEST_MINT (default http://127.0.0.1:13438). If the mint is unreachable
// the tests SKIP, so `go test ./...` on a machine without a mint still passes.
//
// What they prove against the mint itself (not our code):
//   - the settle spend (bidder + committee over the committed settle outputs)
//     is ACCEPTED;
//   - the refund spend after locktime (bidder alone, refund branch) is
//     ACCEPTED -- the safety valve that does not depend on the committee;
//   - the committee-ALONE spend is REFUSED (signature threshold not met): the
//     committee cannot move the escrow by itself;
//   - a signature over a different output set is REFUSED (Schnorr is
//     message-bound, so nobody can redirect an already-signed transaction).
//
// They mint fake sats, lock them to the 2-of-2 condition, and spend. The
// mint's own NUT-11 verification is the judge.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func testMintURL() string {
	if u := os.Getenv("ARENA_TEST_MINT"); u != "" {
		return u
	}
	return "http://127.0.0.1:13438"
}

type mintOutput struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	B      string `json:"B_"`
}

type mintSigned struct {
	Amount int64  `json:"amount"`
	ID     string `json:"id"`
	C      string `json:"C_"`
}

func postJSON(t *testing.T, url string, in any, out any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(in)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil {
		_ = json.Unmarshal(body, out)
	}
	return resp.StatusCode, string(body)
}

func getJSON(t *testing.T, url string, out any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil {
		_ = json.Unmarshal(body, out)
	}
	return resp.StatusCode
}

func getJSONStatus(url string, out any) int {
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil {
		_ = json.Unmarshal(body, out)
	}
	return resp.StatusCode
}

// liveMint returns the mint url, keyset id and keys, or skips the test.
func liveMint(t *testing.T) (string, string, map[string]string) {
	t.Helper()
	url := testMintURL()
	var info struct {
		Version string `json:"version"`
	}
	if code := getJSONStatus(url+"/v1/info", &info); code != 200 {
		t.Skipf("no mint at %s (set ARENA_TEST_MINT to run the escrow spend tests)", url)
	}
	var ks struct {
		Keysets []struct {
			ID     string `json:"id"`
			Unit   string `json:"unit"`
			Active bool   `json:"active"`
		} `json:"keysets"`
	}
	getJSON(t, url+"/v1/keysets", &ks)
	id := ""
	for _, k := range ks.Keysets {
		if k.Unit == "sat" && k.Active {
			id = k.ID
		}
	}
	if id == "" {
		t.Skipf("mint %s has no active sat keyset", url)
	}
	var keys struct {
		Keysets []struct {
			Keys map[string]string `json:"keys"`
		} `json:"keysets"`
	}
	getJSON(t, url+"/v1/keys/"+id, &keys)
	if len(keys.Keysets) == 0 {
		t.Skipf("mint %s returned no keys", url)
	}
	return url, id, keys.Keysets[0].Keys
}

func blind(secret string, amount int64, id string) (mintOutput, *btcec.ModNScalar, error) {
	Y, err := hashToCurve([]byte(secret))
	if err != nil {
		return mintOutput{}, nil, err
	}
	r := new(btcec.ModNScalar)
	rb := make([]byte, 32)
	if _, err := rand.Read(rb); err != nil {
		return mintOutput{}, nil, err
	}
	r.SetByteSlice(rb)
	B := add(Y, mulG(r))
	return mintOutput{Amount: amount, ID: id, B: hex.EncodeToString(B.SerializeCompressed())}, r, nil
}

func unblind(t *testing.T, s mintSigned, r *btcec.ModNScalar, secret string, keys map[string]string) Proof {
	t.Helper()
	A, err := parsePub(keys[strconv.FormatInt(s.Amount, 10)])
	if err != nil {
		t.Fatal(err)
	}
	Cp, err := parsePub(s.C)
	if err != nil {
		t.Fatal(err)
	}
	C := add(Cp, neg(mul(r, A)))
	return Proof{ID: s.ID, Amount: s.Amount, Secret: secret, C: hex.EncodeToString(C.SerializeCompressed())}
}

// mintProof mints one fresh plain proof of amount.
func mintProof(t *testing.T, url, id string, keys map[string]string, amount int64) Proof {
	t.Helper()
	var q struct {
		Quote string `json:"quote"`
		State string `json:"state"`
	}
	postJSON(t, url+"/v1/mint/quote/bolt11", map[string]any{"amount": amount, "unit": "sat"}, &q)
	if q.Quote == "" {
		t.Fatalf("no quote from %s", url)
	}
	deadline := time.Now().Add(20 * time.Second)
	for q.State != "PAID" && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		getJSON(t, url+"/v1/mint/quote/bolt11/"+q.Quote, &q)
	}
	if q.State != "PAID" {
		t.Fatalf("quote %s never paid (is the backend FakeWallet?)", q.Quote)
	}
	secret := "2of2-test-secret-" + hex.EncodeToString(randBytes(t))
	out, r, err := blind(secret, amount, id)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Signatures []mintSigned `json:"signatures"`
	}
	code, body := postJSON(t, url+"/v1/mint/bolt11", map[string]any{"quote": q.Quote, "outputs": []mintOutput{out}}, &minted)
	if code != 200 || len(minted.Signatures) != 1 {
		t.Fatalf("mint/bolt11: %d %s", code, body)
	}
	return unblind(t, minted.Signatures[0], r, secret, keys)
}

// lockProof swaps one plain proof into a single 2-of-2 SIG_ALL locked proof.
func lockProof(t *testing.T, url, id string, keys map[string]string, plain Proof, bidder, committee string, locktime int64) (Proof, string) {
	t.Helper()
	secret := lockForSigAll(committee, bidder, locktime, hex.EncodeToString(randBytes(t)))
	out, r, err := blind(secret, plain.Amount, id)
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Signatures []mintSigned `json:"signatures"`
		Detail     string       `json:"detail"`
	}
	code, body := postJSON(t, url+"/v1/swap",
		map[string]any{"inputs": []Proof{plain}, "outputs": []mintOutput{out}}, &res)
	if code != 200 || len(res.Signatures) != 1 {
		t.Fatalf("lock swap: %d %s", code, body)
	}
	return unblind(t, res.Signatures[0], r, secret, keys), secret
}

// spendOutputs builds one plain output for a locked proof.
func spendOutputs(t *testing.T, id string, locked Proof) ([]mintOutput, []SignOutput) {
	t.Helper()
	secret := "2of2-spend-" + hex.EncodeToString(randBytes(t))
	out, _, err := blind(secret, locked.Amount, id)
	if err != nil {
		t.Fatal(err)
	}
	return []mintOutput{out}, []SignOutput{{Amount: locked.Amount, ID: id, B: out.B}}
}

// sigAllSwap submits a SIG_ALL swap with the given witness signatures.
func sigAllSwap(t *testing.T, url string, locked Proof, outs []mintOutput, sigs []string) (int, string) {
	t.Helper()
	w, _ := json.Marshal(map[string]any{"signatures": sigs})
	in := map[string]any{"amount": locked.Amount, "id": locked.ID, "secret": locked.Secret, "C": locked.C, "witness": string(w)}
	return postJSON(t, url+"/v1/swap", map[string]any{"inputs": []any{in}, "outputs": outs}, nil)
}

func signDigest(t *testing.T, sk *btcec.PrivateKey, digest [32]byte) string {
	t.Helper()
	sig, err := schnorr.Sign(sk, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sig.Serialize())
}

func sigAllHash(locked Proof, outs []SignOutput) [32]byte {
	return sha256.Sum256([]byte(sigAllMessage([]Proof{locked}, outs)))
}

func randScalarHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newKeys makes a fresh bidder/committee keypair as compressed hex.
func newKeys(t *testing.T) (bidderSk, committeeSk *btcec.PrivateKey, bidder, committee string) {
	t.Helper()
	bidderSk, _ = btcec.NewPrivateKey()
	committeeSk, _ = btcec.NewPrivateKey()
	return bidderSk, committeeSk,
		hex.EncodeToString(bidderSk.PubKey().SerializeCompressed()),
		hex.EncodeToString(committeeSk.PubKey().SerializeCompressed())
}

// The settle spend -- bidder AND committee over the committed settle outputs --
// is accepted by a real mint.
func TestMintAcceptsSettleTwoOfTwo(t *testing.T) {
	url, id, keys := liveMint(t)
	bidderSk, committeeSk, bidder, committee := newKeys(t)

	plain := mintProof(t, url, id, keys, 64)
	locked, _ := lockProof(t, url, id, keys, plain, bidder, committee, time.Now().Unix()+3600)
	outs, signOuts := spendOutputs(t, id, locked)
	digest := sigAllHash(locked, signOuts)
	sigs := []string{signDigest(t, bidderSk, digest), signDigest(t, committeeSk, digest)}

	code, body := sigAllSwap(t, url, locked, outs, sigs)
	if code != 200 || !strings.Contains(body, "signatures") {
		t.Fatalf("mint refused a valid 2-of-2 settle spend: %d %s", code, body)
	}
}

// The refund spend after locktime -- the bidder ALONE, via the refund branch --
// is accepted by a real mint. This is the last-resort path that does not depend
// on the committee.
func TestMintAcceptsRefundAfterLocktime(t *testing.T) {
	url, id, keys := liveMint(t)
	bidderSk, _, bidder, committee := newKeys(t)

	plain := mintProof(t, url, id, keys, 64)
	locked, _ := lockProof(t, url, id, keys, plain, bidder, committee, time.Now().Unix()-60)
	outs, signOuts := spendOutputs(t, id, locked)
	digest := sigAllHash(locked, signOuts)

	code, body := sigAllSwap(t, url, locked, outs, []string{signDigest(t, bidderSk, digest)})
	if code != 200 || !strings.Contains(body, "signatures") {
		t.Fatalf("mint refused the bidder's post-locktime refund: %d %s", code, body)
	}
}

// The committee ALONE is refused: with only one of the two required signatures
// the mint returns a signature-threshold error. This is the property the PR
// actually buys -- the committee cannot move the escrow by itself.
func TestMintRefusesCommitteeAlone(t *testing.T) {
	url, id, keys := liveMint(t)
	_, committeeSk, bidder, committee := newKeys(t)

	plain := mintProof(t, url, id, keys, 64)
	locked, _ := lockProof(t, url, id, keys, plain, bidder, committee, time.Now().Unix()+3600)
	outs, signOuts := spendOutputs(t, id, locked)
	digest := sigAllHash(locked, signOuts)

	code, body := sigAllSwap(t, url, locked, outs, []string{signDigest(t, committeeSk, digest)})
	if code == 200 {
		t.Fatalf("mint ACCEPTED a committee-alone spend: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "threshold") && !strings.Contains(strings.ToLower(body), "signature") {
		t.Fatalf("committee-alone refusal was not a signature error: %d %s", code, body)
	}
}

// A signature over a DIFFERENT output set than the one submitted is refused:
// this is what stops a party re-denominating or redirecting an already-signed
// transaction (Schnorr is message-bound).
func TestMintRefusesRedirectedOutputs(t *testing.T) {
	url, id, keys := liveMint(t)
	bidderSk, committeeSk, bidder, committee := newKeys(t)

	plain := mintProof(t, url, id, keys, 64)
	locked, _ := lockProof(t, url, id, keys, plain, bidder, committee, time.Now().Unix()+3600)
	_, signOuts := spendOutputs(t, id, locked)
	digest := sigAllHash(locked, signOuts)
	sigs := []string{signDigest(t, bidderSk, digest), signDigest(t, committeeSk, digest)}

	// submit a DIFFERENT output set than the one signed
	outs2, _ := spendOutputs(t, id, locked)
	code, body := sigAllSwap(t, url, locked, outs2, sigs)
	if code == 200 {
		t.Fatalf("mint accepted signatures over a different output set: %s", body)
	}
}
