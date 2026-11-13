package main

import (
	"context"
	"errors"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

// relaySubscription is one live relay subscription over a websocket client.
// Events is closed when the connection ends; CloseReason explains why.
type relaySubscription struct {
	Events chan *nostr.Event

	relay *nostr.Relay
	inner *nostr.Subscription

	mu     sync.Mutex
	reason error
	closed bool
}

// CloseReason returns the error that ended the subscription, or a generic reason
// if it ended without one.  The observer turns a non-nil reason into a reconnect.
func (subscription *relaySubscription) CloseReason() error {
	subscription.mu.Lock()
	defer subscription.mu.Unlock()
	if subscription.reason != nil {
		return subscription.reason
	}
	return errors.New("relay subscription ended")
}

// Close tears down the connection.  Safe to call more than once; the observer
// defers it on every session.
//
// It deliberately does NOT call relay.Close().  connectAndSubscribe returns only
// after the reader goroutine below has drained inner.Events, and that goroutine
// exists only when relay.Subscribe succeeded -- so the reader is up and a
// round-trip has happened before subscription.relay is ever observed by a closer.
// Calling relay.Close() here would race go-nostr's own teardown (relay.go:175
// write vs relay.go:564 read, see relayobserve_test.go's
// TestRelayIngestConnectionHelpersStayRaceFree) on any path that reaches Close
// before that.  Cancelling the subscription context lets the reader finish
// cleanly, and the relay's connection context is the observer's ctx (via
// RelayConnect), so Run returning closes the socket anyway.
func (subscription *relaySubscription) Close() {
	subscription.mu.Lock()
	if subscription.closed {
		subscription.mu.Unlock()
		return
	}
	subscription.closed = true
	subscription.mu.Unlock()
	if subscription.inner != nil {
		subscription.inner.Close()
	}
}

// connectAndSubscribe dials the relay and opens a subscription for filters.
//
// The historical replay is what makes a reconnect lossless: go-nostr's
// Subscribe uses the filters' `since`, which a relay answers from its stored
// events, so a reconnect with an advanced `since` re-fetches exactly the window
// that may have been missed while this observer was down.
func connectAndSubscribe(ctx context.Context, url string, filters nostr.Filters) (*relaySubscription, error) {
	relay, err := nostr.RelayConnect(ctx, url)
	if err != nil {
		return nil, err
	}

	subscription := &relaySubscription{Events: make(chan *nostr.Event, 256), relay: relay}

	inner, err := relay.Subscribe(ctx, filters)
	if err != nil {
		// We are the last holder of this connection: connectAndSubscribe has not
		// returned, so its reader cannot have started, and nothing else can reach
		// this relay.  Closing here is safe.
		relay.Close()
		return nil, err
	}
	subscription.inner = inner

	// go-nostr owns the raw channels; one goroutine pumps them onto Events and
	// records why the connection ended.  It must not read any go-nostr field its
	// own reader goroutine writes: relay.ConnectionError is stamped from there
	// (relay.go:210) and reading it here was a recorded data race, so the reason
	// comes from the relay's connection context, which is set once and never
	// rewritten, with a generic fallback in CloseReason.
	go func() {
		defer close(subscription.Events)
		for event := range inner.Events {
			select {
			case subscription.Events <- event:
			case <-ctx.Done():
				subscription.setReason(ctx.Err())
				return
			}
		}
		if cause := context.Cause(relay.Context()); cause != nil {
			subscription.setReason(cause)
		}
	}()
	return subscription, nil
}

func (subscription *relaySubscription) setReason(err error) {
	subscription.mu.Lock()
	if subscription.reason == nil && err != nil {
		subscription.reason = err
	}
	subscription.mu.Unlock()
}
