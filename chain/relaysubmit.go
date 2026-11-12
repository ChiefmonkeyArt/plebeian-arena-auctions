package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Submitter turns an observed signed event into a committed chain transaction.
//
// It is deliberately an interface with one method: the observer loop has no
// business knowing whether the transaction reaches the chain through a local
// CometBFT RPC endpoint, a remote one, or a fake in a test.  That is what lets
// one observer run per validator without the loop changing.
type Submitter interface {
	SubmitEvent(ctx context.Context, event Event) (SubmitResult, error)
}

// SubmitResult mirrors what the HTTP /api/tx path already reports back: the
// height the transaction landed at and the application code.  A caller can log
// it and a test can assert on it.
type SubmitResult struct {
	Height int64
	Code   uint32
	TxHash string
}

// EventTransaction builds the exact transaction bytes the gateway's /api/tx
// path submits: the compact JSON of the Nostr event, which is what decodeTx
// unmarshals.  Both transports must agree byte for byte, so there is one
// function and not two.
func EventTransaction(event Event) ([]byte, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, err
	}
	// Prove the shape now rather than at submit time: a round-trip through the
	// app's own decoder catches a malformed event here, not three hops later.
	if _, err := decodeTx(compact.Bytes()); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

// RPCSubmitter submits events through a CometBFT RPC endpoint's
// broadcast_tx_sync.  It speaks plain HTTP/JSON so the ingest links no extra
// client, and it targets the node's own local RPC port, exactly as the gateway
// does on the client's behalf today.
type RPCSubmitter struct {
	// RPCURL is the validator's RPC base, e.g. http://127.0.0.1:26657.
	RPCURL string
	// Timeout bounds one submission.  Zero means 20s.
	Timeout time.Duration
	// Client overrides the HTTP client; nil uses one with Timeout.
	Client *http.Client
}

func (submitter RPCSubmitter) SubmitEvent(ctx context.Context, event Event) (SubmitResult, error) {
	if submitter.RPCURL == "" {
		return SubmitResult{}, errors.New("submitter requires an RPC URL")
	}
	tx, err := EventTransaction(event)
	if err != nil {
		return SubmitResult{}, err
	}
	timeout := submitter.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/broadcast_tx_sync?tx=0x%s", submitter.RPCURL, hex.EncodeToString(tx))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return SubmitResult{}, err
	}
	client := submitter.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	response, err := client.Do(request)
	if err != nil {
		return SubmitResult{}, err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))

	var decoded struct {
		Result *struct {
			Code uint32 `json:"code"`
			Log  string `json:"log"`
			Hash string `json:"hash"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return SubmitResult{}, fmt.Errorf("decode broadcast result: %w", err)
	}
	if decoded.Error != nil {
		message := decoded.Error.Data
		if message == "" {
			message = decoded.Error.Message
		}
		// A duplicate the node already has in its mempool is success, not a
		// failure: it is the same transaction, and it will commit once.
		if contains(message, "already exists in cache") {
			return SubmitResult{}, nil
		}
		return SubmitResult{}, fmt.Errorf("broadcast rejected: %s", message)
	}
	if decoded.Result == nil {
		return SubmitResult{}, errors.New("broadcast returned no result")
	}
	if decoded.Result.Code != 0 {
		return SubmitResult{}, fmt.Errorf("CheckTx rejected: %s", decoded.Result.Log)
	}
	return SubmitResult{Code: decoded.Result.Code, TxHash: decoded.Result.Hash}, nil
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// MemorySubmitter records submissions in memory.  It exists so the observer loop
// and its reconnect behaviour can be tested without a chain, and so a validator
// process that only wants to observe can be started without a broadcaster.
type MemorySubmitter struct {
	mu          sync.Mutex
	submissions []Event
	failures    map[string]error
}

func NewMemorySubmitter() *MemorySubmitter {
	return &MemorySubmitter{failures: map[string]error{}}
}

// FailEvery makes the submitter return err for the named event, once.
func (submitter *MemorySubmitter) FailEvery(eventID string, err error) {
	submitter.mu.Lock()
	defer submitter.mu.Unlock()
	submitter.failures[eventID] = err
}

func (submitter *MemorySubmitter) SubmitEvent(_ context.Context, event Event) (SubmitResult, error) {
	submitter.mu.Lock()
	defer submitter.mu.Unlock()
	if err, ok := submitter.failures[event.ID]; ok {
		delete(submitter.failures, event.ID)
		return SubmitResult{}, err
	}
	submitter.submissions = append(submitter.submissions, event)
	return SubmitResult{Height: int64(len(submitter.submissions)), TxHash: event.ID}, nil
}

// Submissions returns the events accepted so far, oldest first.  The slice is a
// copy, so a test cannot accidentally mutate the record.
func (submitter *MemorySubmitter) Submissions() []Event {
	submitter.mu.Lock()
	defer submitter.mu.Unlock()
	out := make([]Event, len(submitter.submissions))
	copy(out, submitter.submissions)
	return out
}
