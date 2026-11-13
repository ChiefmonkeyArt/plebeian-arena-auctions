package main

// A minimal NIP-01 relay client: exactly the two operations the verdict-publish
// path needs -- publish a signed event, and subscribe to read events back.
//
// It is deliberately NOT go-nostr.  The ingest branch (feat/relay-ingest) uses
// go-nostr v0.52.1 and carries a documented internal data race on connection
// teardown; the publish path needs none of go-nostr's surface (no NIP-19, no
// pool, no nip42), so a small client over gorilla/websocket -- already in this
// module's graph via CometBFT -- keeps the dependency light and the teardown
// race-free.  If the two branches converge, go-nostr can back this interface
// without touching the publisher.
//
// Wire format (NIP-01):
//
//	client -> relay: ["EVENT", <event>]
//	                 ["REQ", <subid>, <filter>, ...]
//	                 ["CLOSE", <subid>]
//	relay -> client: ["OK", <event_id>, true|false, <message>]
//	                 ["EVENT", <subid>, <event>]
//	                 ["EOSE", <subid>]
//	                 ["NOTICE", <message>]

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// RelayFilter is the subset of a NIP-01 filter this client uses: kinds and
// authors.  Both are optional; an empty filter matches everything.
type RelayFilter struct {
	Kinds   []int    `json:"kinds,omitempty"`
	Authors []string `json:"authors,omitempty"`
}

// RelayClient is one websocket connection to a relay.  Writes are serialised;
// reads run on one goroutine that fans out OK receipts and subscription events.
type RelayClient struct {
	url  string
	conn *websocket.Conn

	writeMu sync.Mutex

	mu      sync.Mutex
	okWait  map[string]chan error
	subs    map[string]chan *Event
	subSeq  int64
	readErr error

	closeOnce sync.Once
	closed    chan struct{}
}

// DialRelay connects to a relay websocket.  It is the caller's job to Close.
func DialRelay(ctx context.Context, url string) (*RelayClient, error) {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, resp, err := dialer.DialContext(ctx, url, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("dial %s: %w (http %d)", url, err, resp.StatusCode)
		}
		return nil, fmt.Errorf("dial %s: %w", url, err)
	}
	c := &RelayClient{url: url, conn: conn, okWait: map[string]chan error{}, subs: map[string]chan *Event{}, closed: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

// readLoop dispatches relay frames until the connection ends, then fails every
// pending publish and closes every subscription so no caller blocks forever.
func (c *RelayClient) readLoop() {
	defer c.failAll(errors.New("relay connection closed"))
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			c.mu.Unlock()
			return
		}
		var frame []json.RawMessage
		if json.Unmarshal(data, &frame) != nil || len(frame) == 0 {
			continue
		}
		var kind string
		if json.Unmarshal(frame[0], &kind) != nil {
			continue
		}
		switch kind {
		case "OK":
			if len(frame) < 3 {
				continue
			}
			var id string
			var ok bool
			if json.Unmarshal(frame[1], &id) != nil || json.Unmarshal(frame[2], &ok) != nil {
				continue
			}
			var msg string
			if len(frame) >= 4 {
				_ = json.Unmarshal(frame[3], &msg)
			}
			c.mu.Lock()
			ch := c.okWait[id]
			delete(c.okWait, id)
			c.mu.Unlock()
			if ch != nil {
				if ok {
					ch <- nil
				} else {
					ch <- fmt.Errorf("relay rejected event %s: %s", id, msg)
				}
			}
		case "EVENT":
			if len(frame) < 3 {
				continue
			}
			var subid string
			if json.Unmarshal(frame[1], &subid) != nil {
				continue
			}
			var ev Event
			if json.Unmarshal(frame[2], &ev) != nil {
				continue
			}
			c.mu.Lock()
			ch := c.subs[subid]
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- &ev:
				case <-c.closed:
				}
			}
		}
	}
}

// failAll releases every waiter and closes every subscription channel.
func (c *RelayClient) failAll(reason error) {
	c.mu.Lock()
	pending := c.okWait
	c.okWait = map[string]chan error{}
	subs := c.subs
	c.subs = map[string]chan *Event{}
	c.mu.Unlock()
	for _, ch := range pending {
		select {
		case ch <- reason:
		default:
		}
	}
	for _, ch := range subs {
		close(ch)
	}
}

// Publish sends a signed event and waits for the relay's OK.
func (c *RelayClient) Publish(ctx context.Context, ev *Event) error {
	if ev == nil {
		return errors.New("publish: nil event")
	}
	receipt := make(chan error, 1)
	c.mu.Lock()
	c.okWait[ev.ID] = receipt
	c.mu.Unlock()

	frame := []any{"EVENT", ev}
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if err := c.write(body); err != nil {
		c.mu.Lock()
		delete(c.okWait, ev.ID)
		c.mu.Unlock()
		return err
	}
	select {
	case err := <-receipt:
		return err
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.okWait, ev.ID)
		c.mu.Unlock()
		return ctx.Err()
	case <-c.closed:
		return errors.New("publish: relay connection closed")
	}
}

// Subscribe opens a subscription and returns a channel of events plus a cancel
// function that sends CLOSE.  The channel is closed when the connection drops.
func (c *RelayClient) Subscribe(ctx context.Context, filters ...RelayFilter) (<-chan *Event, func(), error) {
	c.mu.Lock()
	c.subSeq++
	subid := "arena-" + strconv.FormatInt(c.subSeq, 10)
	ch := make(chan *Event, 256)
	c.subs[subid] = ch
	c.mu.Unlock()

	frame := []any{"REQ", subid}
	for _, f := range filters {
		frame = append(frame, f)
	}
	body, err := json.Marshal(frame)
	if err != nil {
		return nil, nil, err
	}
	if err := c.write(body); err != nil {
		return nil, nil, err
	}
	cancel := func() {
		c.mu.Lock()
		delete(c.subs, subid)
		c.mu.Unlock()
		closeFrame, _ := json.Marshal([]any{"CLOSE", subid})
		_ = c.write(closeFrame)
	}
	return ch, cancel, nil
}

func (c *RelayClient) write(body []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, body)
}

// Close shuts the connection down.  Safe to call more than once.
func (c *RelayClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.conn.Close()
	})
	return err
}

// RelayWriter is the publisher's transport: anything that can publish a signed
// event.  A *RelayClient satisfies it; tests use an in-memory recorder.  The
// publisher never knows whether the relay is nak, a public relay, or a fake.
type RelayWriter interface {
	Publish(ctx context.Context, ev *Event) error
}

// MultiRelayWriter publishes to several relays.  Publishing to more than one
// relay is the mitigation for a single relay showing different verdicts to
// different clients (equivocation): the client diffs them.  A publish succeeds
// if at least one relay accepts it; if every relay fails, the error is returned
// so the publisher retries on the next Step.
type MultiRelayWriter struct {
	Writers []RelayWriter
}

func (m MultiRelayWriter) Publish(ctx context.Context, ev *Event) error {
	if len(m.Writers) == 0 {
		return errors.New("no relays configured")
	}
	var lastErr error
	accepted := 0
	for _, w := range m.Writers {
		if err := w.Publish(ctx, ev); err != nil {
			lastErr = err
			continue
		}
		accepted++
	}
	if accepted == 0 {
		return lastErr
	}
	return nil
}

// DialRelays connects to each relay URL and returns a MultiRelayWriter plus a
// close function.  It is an error only if NO relay connects.
func DialRelays(ctx context.Context, urls []string) (*MultiRelayWriter, func(), error) {
	w := &MultiRelayWriter{}
	var clients []*RelayClient
	for _, url := range urls {
		client, err := DialRelay(ctx, url)
		if err != nil {
			continue
		}
		clients = append(clients, client)
		w.Writers = append(w.Writers, client)
	}
	if len(w.Writers) == 0 {
		return nil, func() {}, errors.New("no relay could be reached")
	}
	closeAll := func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}
	return w, closeAll, nil
}
