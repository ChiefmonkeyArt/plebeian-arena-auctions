package main

// ADR 0003 §2 snapshot tests: a restored app continues with the same app
// hashes as one that never stopped; damaged, non-canonical, misnamed or
// chain-contradicting snapshots are refused; only two are kept.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

func block(t *testing.T, a *App, h int64) []byte {
	t.Helper()
	res, err := a.FinalizeBlock(context.Background(), &abci.FinalizeBlockRequest{Height: h, Time: time.Unix(1_800_000_000+h, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Commit(context.Background(), &abci.CommitRequest{}); err != nil {
		t.Fatal(err)
	}
	return res.AppHash
}

func snapApp(t *testing.T, dir string) *App {
	a := NewApp()
	a.st = viewState(1_800_000_000) // 22 lots, 66 bids with proofs; two open lots close in block 501
	a.st.Height = 500
	a.snap = &snapshotter{dir: dir, every: 1}
	return a
}

// waitSnap waits for Commit's background write of height h.
func waitSnap(t *testing.T, dir string, h int64) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(filepath.Join(dir, snapshotName(h))); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("snapshot %d not written", h)
}

func TestSnapshotRestoreMatchesUninterruptedRun(t *testing.T) {
	dir := t.TempDir()
	a := snapApp(t, dir)
	h501 := block(t, a, 501)
	waitSnap(t, dir, 501)

	// a second validator restarts from the snapshot
	snap, err := loadSnapshot(dir, func(h int64) ([]byte, bool, error) { return h501, true, nil })
	if err != nil || snap == nil || snap.height != 501 {
		t.Fatalf("load: %v %v", snap, err)
	}
	b := NewApp()
	b.restore(snap)
	info, _ := b.Info(context.Background(), &abci.InfoRequest{})
	if info.LastBlockHeight != 501 || !bytes.Equal(info.LastBlockAppHash, h501) {
		t.Fatalf("Info must report the snapshot: %d %x", info.LastBlockHeight, info.LastBlockAppHash)
	}
	if b.st.Auctions[hx(21)].Status != "closed" {
		t.Fatal("restored state must include block 501's closes")
	}
	for h := int64(502); h <= 505; h++ {
		if x, y := block(t, a, h), block(t, b, h); !bytes.Equal(x, y) {
			t.Fatalf("height %d: restored app hash %x, uninterrupted %x", h, y, x)
		}
	}
	waitSnap(t, dir, 505) // let the background write finish before TempDir cleanup
	// no snapshots yet: Info says 0, so CometBFT replays from genesis
	if info, _ := NewApp().Info(context.Background(), &abci.InfoRequest{}); info.LastBlockHeight != 0 || len(info.LastBlockAppHash) != 0 {
		t.Fatal("fresh app must report height 0")
	}
}

func TestSnapshotKeepsTwoAndShutdownWrite(t *testing.T) {
	dir := t.TempDir()
	a := snapApp(t, dir)
	a.snap.every = 0 // only explicit (shutdown) writes
	for h := int64(501); h <= 503; h++ {
		block(t, a, h)
		hh, hash, raw := a.committedSnapshot()
		if err := a.snap.write(hh, hash, raw); err != nil {
			t.Fatal(err)
		}
	}
	hs, _ := listSnapshots(dir)
	if len(hs) != 2 || hs[0] != 503 || hs[1] != 502 {
		t.Fatalf("want [503 502], got %v", hs)
	}
	fi, _ := os.Stat(filepath.Join(dir, snapshotName(503)))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v, want 0600", fi.Mode().Perm())
	}
	if err := a.snap.write(502, nil, []byte("{}")); err != nil || len(must(listSnapshots(dir))) != 2 {
		t.Fatal("an older height must not be written over a newer one")
	}
}

var errAbove = errors.New("snapshot height 9 is above the block store (1)")

func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func must[T any](v T, _ error) T { return v }

func TestSnapshotRefusals(t *testing.T) {
	dir := t.TempDir()
	a := snapApp(t, dir)
	good := block(t, a, 501)
	waitSnap(t, dir, 501)
	p := filepath.Join(dir, snapshotName(501))
	orig, _ := os.ReadFile(p)
	rewrite := func(f func(string) string) {
		if err := os.WriteFile(p, []byte(f(string(orig))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ok := func(h int64) ([]byte, bool, error) { return good, true, nil }
	refuse := func(name, want string, rec chainRecord) {
		t.Helper()
		if _, err := loadSnapshot(dir, rec); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want error containing %q, got %v", name, want, err)
		}
	}

	rewrite(func(s string) string { return strings.Replace(s, `"title":"lot 3"`, `"title":"lot 9"`, 1) })
	refuse("tampered state", "state hashes to", ok)

	// non-canonical: valid JSON, hash recomputed, but extra whitespace
	rewrite(func(s string) string {
		i := strings.Index(s, `"state":`) + len(`"state":`)
		st := strings.Replace(s[i:len(s)-2], `{"height"`, `{ "height"`, 1)
		sum := sha256Hex(st)
		return strings.Replace(s[:i], hex.EncodeToString(good), sum, 1) + st + "}\n"
	})
	refuse("non-canonical", "not canonical", ok)

	rewrite(func(s string) string { return s })
	refuse("chain disagrees", "the chain recorded", func(int64) ([]byte, bool, error) { return bytes.Repeat([]byte{1}, 32), true, nil })
	refuse("above the store", "above the block store", func(int64) ([]byte, bool, error) {
		return nil, false, errAbove
	})

	os.Rename(p, filepath.Join(dir, snapshotName(600)))
	refuse("misnamed", "file name says 600", ok)
	os.Remove(filepath.Join(dir, snapshotName(600)))

	os.WriteFile(p, []byte("{not json"), 0o600)
	refuse("garbage", "unreadable", ok)

	os.Remove(p)
	os.Symlink("/etc/passwd", p)
	refuse("symlink", "not a regular file", ok)
	os.Remove(p)

	if s, err := loadSnapshot(dir, ok); s != nil || err != nil {
		t.Fatalf("no snapshot: want nil, nil; got %v %v", s, err)
	}
	if s, err := loadSnapshot(filepath.Join(dir, "missing"), ok); s != nil || err != nil {
		t.Fatal("missing dir: want nil, nil")
	}
}
