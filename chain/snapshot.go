package main

// State snapshots on disk (ADR 0003 §2, v0.3.3). The app keeps its state in
// memory; without these a restart replays every block from genesis (about
// 5 minutes at 42k blocks on the live demo). Each validator writes its
// committed state every SnapshotEvery blocks and on clean shutdown, and
// starts from the newest one, so CometBFT replays only the blocks after it.
//
// A file is the exact canonical JSON the app hash covers, wrapped with its
// height and hash. On load it must hash to the stored hash, re-encode to the
// same bytes, and match the chain's own record of that height (the next
// block header's AppHash, or the saved CometBFT state at the tip). Anything
// else stops the validator: it never quietly falls back to a full replay.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	cfg "github.com/cometbft/cometbft/config"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
)

const (
	snapshotFormat = 2 // v0.4.0: canonical state (height/time zero) + "time"
	snapshotsKept  = 2
	maxSnapshotB   = 256 << 20 // refuse absurd files rather than exhaust memory
)

type snapshotFile struct {
	Format  int             `json:"format"`
	Height  int64           `json:"height"`
	Time    int64           `json:"time"`
	AppHash string          `json:"appHash"`
	State   json.RawMessage `json:"state"`
}

type snapshot struct {
	height  int64
	time    int64
	appHash []byte
	raw     []byte // canonical state JSON, as hashed
	state   *State
}

type snapshotter struct {
	dir   string
	every int64
	mu    sync.Mutex // serialises writes (block-interval and shutdown)
	last  int64
}

func snapshotDir(home string) string { return filepath.Join(home, "data", "app-state") }

func snapshotName(h int64) string { return strconv.FormatInt(h, 10) + ".json" }

// write stores one snapshot atomically: temp file, fsync, rename, fsync dir.
// raw is never modified after Commit publishes it, so it can be written from
// another goroutine without copying.
// lastHeight is the newest snapshot written (or restored).
func (s *snapshotter) lastHeight() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *snapshotter) write(h, t int64, appHash, raw []byte) error {
	if h <= 0 || len(raw) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h <= s.last {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".snap-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	var head bytes.Buffer
	fmt.Fprintf(&head, `{"format":%d,"height":%d,"time":%d,"appHash":"%s","state":`, snapshotFormat, h, t, hex.EncodeToString(appHash))
	for _, b := range [][]byte{head.Bytes(), raw, []byte("}\n")} {
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, snapshotName(h))); err != nil {
		return err
	}
	if d, err := os.Open(s.dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	s.last = h
	s.prune()
	return nil
}

// prune keeps the newest snapshotsKept files and removes stray temp files.
func (s *snapshotter) prune() {
	hs, _ := listSnapshots(s.dir)
	for i, h := range hs {
		if i >= snapshotsKept {
			os.Remove(filepath.Join(s.dir, snapshotName(h)))
		}
	}
	if ents, err := os.ReadDir(s.dir); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".snap-") {
				os.Remove(filepath.Join(s.dir, e.Name()))
			}
		}
	}
}

// listSnapshots returns snapshot heights, newest first.
func listSnapshots(dir string) ([]int64, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hs []int64
	for _, e := range ents {
		n := e.Name()
		// any type counts here; readSnapshot refuses non-regular files, so a
		// symlink is an error, not a silent fall-back to an older snapshot
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		h, err := strconv.ParseInt(strings.TrimSuffix(n, ".json"), 10, 64)
		if err != nil || h <= 0 || snapshotName(h) != n {
			continue
		}
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i] > hs[j] })
	return hs, nil
}

// readSnapshot loads and self-checks one file: format, height, hash and
// canonical encoding. It does not consult the chain (see verifyAgainstChain).
func readSnapshot(path string, wantHeight int64) (*snapshot, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > maxSnapshotB {
		return nil, fmt.Errorf("%d bytes, over the %d limit", fi.Size(), maxSnapshotB)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f snapshotFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("unreadable: %w", err)
	}
	if f.Format != snapshotFormat {
		return nil, fmt.Errorf("format %d, want %d", f.Format, snapshotFormat)
	}
	if f.Height != wantHeight {
		return nil, fmt.Errorf("holds height %d, file name says %d", f.Height, wantHeight)
	}
	want, err := hex.DecodeString(f.AppHash)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("bad appHash")
	}
	got := sha256.Sum256(f.State)
	if !bytes.Equal(got[:], want) {
		return nil, fmt.Errorf("state hashes to %x, file says %x", got, want)
	}
	st := newState()
	if err := json.Unmarshal(f.State, st); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if !bytes.Equal(st.canonical(), f.State) {
		return nil, errors.New("state is not canonical (re-encodes differently)")
	}
	st.Height, st.Time = f.Height, f.Time
	return &snapshot{height: f.Height, time: f.Time, appHash: want, raw: []byte(f.State), state: st}, nil
}

// chainRecord is what the chain itself says the app hash after height h was:
// the AppHash in block h+1's header, or, if h is the tip, the saved state.
type chainRecord func(h int64) (hash []byte, ok bool, err error)

// cometRecord reads a validator's block store and state store. Both are
// closed again before the node opens them.
func cometRecord(c *cfg.Config) chainRecord {
	return func(h int64) ([]byte, bool, error) {
		bdb, err := cfg.DefaultDBProvider(&cfg.DBContext{ID: "blockstore", Config: c})
		if err != nil {
			return nil, false, err
		}
		bs := store.NewBlockStore(bdb)
		defer bs.Close()
		if h > bs.Height() {
			return nil, false, fmt.Errorf("snapshot height %d is above the block store (%d)", h, bs.Height())
		}
		if m := bs.LoadBlockMeta(h + 1); m != nil {
			return m.Header.AppHash, true, nil
		}
		sdb, err := cfg.DefaultDBProvider(&cfg.DBContext{ID: "state", Config: c})
		if err != nil {
			return nil, false, err
		}
		ss := sm.NewStore(sdb, sm.StoreOptions{})
		defer ss.Close()
		s, err := ss.Load()
		if err != nil {
			return nil, false, err
		}
		if s.LastBlockHeight == h {
			return s.AppHash, true, nil
		}
		// Commit ran but CometBFT did not save its state for h yet (crash
		// window); the handshake replays h with a mock app and checks then.
		return nil, false, nil
	}
}

// loadSnapshot returns the newest snapshot, verified, or nil when there is
// none. Any snapshot that fails a check is an error: the operator decides
// (delete the file to replay from the previous one or from genesis).
func loadSnapshot(dir string, rec chainRecord) (*snapshot, error) {
	hs, err := listSnapshots(dir)
	if err != nil || len(hs) == 0 {
		return nil, err
	}
	h := hs[0]
	p := filepath.Join(dir, snapshotName(h))
	snap, err := readSnapshot(p, h)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s refused: %w", p, err)
	}
	if rec != nil {
		want, ok, err := rec(h)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", p, err)
		}
		if ok && !bytes.Equal(want, snap.appHash) {
			return nil, fmt.Errorf("snapshot %s refused: app hash %x, the chain recorded %x", p, snap.appHash, want)
		}
	}
	return snap, nil
}

// restore installs a verified snapshot as the committed state. Called before
// the node starts, so CometBFT's Info handshake sees its height and hash.
func (a *App) restore(s *snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.st = s.state
	a.committed, a.committedH, a.committedT, a.appHash = s.raw, s.height, s.time, s.appHash
	a.committedHash = s.appHash
}

// committedSnapshot is the latest committed height, hash and bytes.
func (a *App) committedSnapshot() (int64, int64, []byte, []byte) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.committedH, a.committedT, a.committedHash, a.committed
}
