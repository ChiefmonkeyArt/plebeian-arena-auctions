package main

// The ledger archive (ADR 0003 §4, v0.4.0). Each validator appends one JSON
// line per transaction it executed (accepted, void or rejected) before the
// block that held it can be pruned, so the full bid history survives block
// pruning. Lines are written at Commit, after the block is final. On a
// restart CometBFT may replay blocks the ledger already holds; those are
// skipped by height.

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type ledgerLine struct {
	Height int64           `json:"height"`
	Time   int64           `json:"time"`
	Kind   int             `json:"kind,omitempty"`
	Event  string          `json:"event,omitempty"`
	Result string          `json:"result"` // ok | void | rejected
	Reason string          `json:"reason,omitempty"`
	Tx     json.RawMessage `json:"tx,omitempty"` // the signed event, for accepted txs
}

type ledger struct {
	mu   sync.Mutex
	f    *os.File
	last int64 // highest height already in the file
}

func ledgerPath(home string) string { return filepath.Join(home, "data", "ledger.jsonl") }

// openLedger opens (or creates) the archive and finds the last height in it.
// A torn final line from a crash is cut off.
func openLedger(path string) (*ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path under the validator home
	if err != nil {
		return nil, err
	}
	l := &ledger{f: f}
	var good int64
	r := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			break // a final line without '\n' is torn: dropped below
		}
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		var ll ledgerLine
		if json.Unmarshal(line, &ll) != nil {
			break
		}
		good += int64(len(line))
		if ll.Height > l.last {
			l.last = ll.Height
		}
	}
	if err := f.Truncate(good); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(good, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

// append writes the lines of block h, once, and syncs them to disk.
func (l *ledger) append(h int64, lines []ledgerLine) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if h <= l.last || len(lines) == 0 {
		return nil
	}
	w := bufio.NewWriter(l.f)
	for _, ll := range lines {
		b, err := json.Marshal(ll)
		if err != nil {
			return err
		}
		_, _ = w.Write(b)
		_ = w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		return err
	}
	l.last = h
	return l.f.Sync()
}

func (l *ledger) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
