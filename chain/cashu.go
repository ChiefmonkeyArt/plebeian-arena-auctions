package main

// Deterministic Cashu checks used inside the validator state machine.
// No network or mint calls: proofs are checked against the mint keyset
// pinned in genesis, using the mint's DLEQ proof (NUT-12).

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type DLEQ struct {
	E string `json:"e"`
	S string `json:"s"`
	R string `json:"r"`
}

type Proof struct {
	ID     string `json:"id"`
	Amount int64  `json:"amount"`
	Secret string `json:"secret"`
	C      string `json:"C"`
	DLEQ   *DLEQ  `json:"dleq,omitempty"`
}

var domainSeparator = []byte("Secp256k1_HashToCurve_Cashu_")

func hashToCurve(msg []byte) (*btcec.PublicKey, error) {
	h := sha256.Sum256(append(append([]byte{}, domainSeparator...), msg...))
	for counter := uint32(0); counter < 1<<16; counter++ {
		var c [4]byte
		binary.LittleEndian.PutUint32(c[:], counter)
		hh := sha256.Sum256(append(h[:], c[:]...))
		pk, err := btcec.ParsePubKey(append([]byte{0x02}, hh[:]...))
		if err == nil {
			return pk, nil
		}
	}
	return nil, errors.New("hash_to_curve failed")
}

func parsePub(h string) (*btcec.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(b)
}

func parseScalar(h string) (*btcec.ModNScalar, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad scalar")
	}
	var s btcec.ModNScalar
	if overflow := s.SetByteSlice(b); overflow {
		return nil, errors.New("scalar overflow")
	}
	return &s, nil
}

func toJac(p *btcec.PublicKey) btcec.JacobianPoint {
	var j btcec.JacobianPoint
	p.AsJacobian(&j)
	return j
}

func fromJac(j *btcec.JacobianPoint) *btcec.PublicKey {
	j.ToAffine()
	return btcec.NewPublicKey(&j.X, &j.Y)
}

func add(a, b *btcec.PublicKey) *btcec.PublicKey {
	ja, jb := toJac(a), toJac(b)
	var r btcec.JacobianPoint
	btcec.AddNonConst(&ja, &jb, &r)
	return fromJac(&r)
}

func mul(k *btcec.ModNScalar, p *btcec.PublicKey) *btcec.PublicKey {
	jp := toJac(p)
	var r btcec.JacobianPoint
	btcec.ScalarMultNonConst(k, &jp, &r)
	return fromJac(&r)
}

func mulG(k *btcec.ModNScalar) *btcec.PublicKey {
	var r btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(k, &r)
	return fromJac(&r)
}

func neg(p *btcec.PublicKey) *btcec.PublicKey {
	j := toJac(p)
	j.ToAffine()
	j.Y.Negate(1).Normalize()
	return btcec.NewPublicKey(&j.X, &j.Y)
}

func hashE(pks ...*btcec.PublicKey) [32]byte {
	var sb strings.Builder
	for _, p := range pks {
		sb.WriteString(hex.EncodeToString(p.SerializeUncompressed()))
	}
	return sha256.Sum256([]byte(sb.String()))
}

// verifyDLEQ proves C was signed by mint key A for this secret (NUT-12, "Carol").
func verifyDLEQ(p Proof, A *btcec.PublicKey) error {
	if p.DLEQ == nil {
		return errors.New("missing DLEQ proof")
	}
	e, err := parseScalar(p.DLEQ.E)
	if err != nil {
		return err
	}
	s, err := parseScalar(p.DLEQ.S)
	if err != nil {
		return err
	}
	r, err := parseScalar(p.DLEQ.R)
	if err != nil {
		return err
	}
	C, err := parsePub(p.C)
	if err != nil {
		return err
	}
	Y, err := hashToCurve([]byte(p.Secret))
	if err != nil {
		return err
	}
	Cb := add(C, mul(r, A))            // C_ = C + r*A
	Bb := add(Y, mulG(r))              // B_ = Y + r*G
	R1 := add(mulG(s), neg(mul(e, A))) // R1 = s*G - e*A
	R2 := add(mul(s, Bb), neg(mul(e, Cb)))
	got := hashE(R1, R2, A, Cb)
	eb := e.Bytes()
	if hex.EncodeToString(got[:]) != hex.EncodeToString(eb[:]) {
		return errors.New("invalid DLEQ proof")
	}
	return nil
}

func proofY(secret string) (string, error) {
	Y, err := hashToCurve([]byte(secret))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(Y.SerializeCompressed()), nil
}

type p2pkLock struct {
	Data     string
	Pubkeys  []string
	NSigs    int
	Locktime int64
	Refund   []string
	SigFlag  string
	TagsJSON string
}

// strictObject decodes one JSON object and refuses duplicate keys and any key
// not in allowed (exact, case-sensitive). Go's decoder alone would match keys
// case-insensitively and keep the last duplicate, while the mint (Python)
// matches exactly; any such difference lets a lock mean one thing to the
// validators and another to the mint (internal audit A1).
func strictObject(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		k, ok := kt.(string)
		if err != nil || !ok {
			return nil, errors.New("bad object key")
		}
		known := false
		for _, a := range allowed {
			known = known || a == k
		}
		if !known {
			return nil, fmt.Errorf("unexpected key %q", k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("bad object value")
		}
		out[k] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errors.New("bad object end")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// parseP2PK reads a NUT-11 P2PK secret strictly: one copy of each key and
// tag, no escapes, valid UTF-8, so the validators and the mint can only ever
// see the same lock.
func parseP2PK(secret string) (*p2pkLock, error) {
	if !utf8.ValidString(secret) || strings.ContainsRune(secret, '\\') {
		return nil, errors.New("secret must be plain UTF-8 without escapes")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(secret), &arr); err != nil || len(arr) != 2 {
		return nil, errors.New("secret is not a NUT-10 secret")
	}
	var kind string
	if err := json.Unmarshal(arr[0], &kind); err != nil || kind != "P2PK" {
		return nil, errors.New("secret is not P2PK")
	}
	obj, err := strictObject(arr[1], "nonce", "data", "tags")
	if err != nil {
		return nil, fmt.Errorf("bad P2PK body: %v", err)
	}
	var nonce, data string
	var tags [][]string
	if json.Unmarshal(obj["nonce"], &nonce) != nil || json.Unmarshal(obj["data"], &data) != nil || nonce == "" || data == "" {
		return nil, errors.New("P2PK body needs a nonce and data")
	}
	if raw, ok := obj["tags"]; ok && json.Unmarshal(raw, &tags) != nil {
		return nil, errors.New("bad P2PK tags")
	}
	if !lowerHex(data, 66) {
		return nil, errors.New("P2PK data must be a lowercase compressed pubkey")
	}
	l := &p2pkLock{Data: data, NSigs: 1}
	tj, _ := json.Marshal(tags)
	l.TagsJSON = string(tj)
	seen := map[string]bool{}
	for _, t := range tags {
		if len(t) < 2 {
			return nil, errors.New("bad tag")
		}
		if seen[t[0]] {
			return nil, fmt.Errorf("duplicate tag %q", t[0])
		}
		seen[t[0]] = true
		single := func() error {
			if len(t) != 2 {
				return fmt.Errorf("tag %q takes one value", t[0])
			}
			return nil
		}
		switch t[0] {
		case "pubkeys":
			for _, v := range t[1:] {
				l.Pubkeys = append(l.Pubkeys, strings.ToLower(v))
			}
		case "n_sigs":
			if err := single(); err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(t[1])
			if err != nil {
				return nil, errors.New("bad n_sigs")
			}
			l.NSigs = n
		case "locktime":
			if err := single(); err != nil {
				return nil, err
			}
			n, err := strconv.ParseInt(t[1], 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != t[1] {
				return nil, errors.New("bad locktime")
			}
			l.Locktime = n
		case "refund":
			for _, v := range t[1:] {
				if !lowerHex(v, 66) {
					return nil, errors.New("refund keys must be lowercase compressed pubkeys")
				}
				l.Refund = append(l.Refund, v)
			}
		case "sigflag":
			if err := single(); err != nil {
				return nil, err
			}
			l.SigFlag = t[1]
		case "n_sigs_refund":
			if err := single(); err != nil {
				return nil, err
			}
			if t[1] != "1" {
				return nil, errors.New("refund must need exactly 1 signature")
			}
		default:
			return nil, fmt.Errorf("unexpected tag %q", t[0])
		}
	}
	return l, nil
}

// schnorrVerifyMsg verifies a BIP340 signature over sha256(msg) by a 02/03-prefixed or x-only key.
func schnorrVerifyHash(h []byte, pubHex, sigHex string) bool {
	pb, err := hex.DecodeString(pubHex)
	if err != nil {
		return false
	}
	if len(pb) == 33 {
		pb = pb[1:]
	}
	pk, err := schnorr.ParsePubKey(pb)
	if err != nil {
		return false
	}
	sb, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	sig, err := schnorr.ParseSignature(sb)
	if err != nil {
		return false
	}
	return sig.Verify(h, pk)
}
