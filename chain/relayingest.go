package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// relayURLs is a repeatable string flag: `-relay ws://a -relay ws://b`.  It is
// a list, not a single URL, because a validator should be able to follow several
// relays; the deployment today configures one, tests configure one, but nothing
// assumes it.
type relayURLs []string

func (urls *relayURLs) String() string { return strings.Join(*urls, ",") }

func (urls *relayURLs) Set(value string) error {
	for _, u := range *urls {
		if u == value {
			return nil
		}
	}
	*urls = append(*urls, value)
	return nil
}

// startRelayIngest starts one observer per configured relay URL.  Each submits
// into localRPC (this validator's own node) so the local mempool fills from the
// relay without any client having to know which node is the leader.  The
// returned stop function cancels every observer and waits for them to exit.
func startRelayIngest(ctx context.Context, urls []string, localRPC string, logger *log.Logger) (func(), error) {
	if len(urls) == 0 {
		return func() {}, nil
	}
	if logger == nil {
		logger = log.Default()
	}
	ingestContext, cancel := context.WithCancel(ctx)
	var stops []func()
	for _, url := range urls {
		submitter := RPCSubmitter{RPCURL: localRPC, Timeout: 20 * time.Second}
		observer, err := NewObserver(ObserverConfig{URL: url, Submitter: submitter, Logger: logger})
		if err != nil {
			cancel()
			for _, stop := range stops {
				stop()
			}
			return nil, err
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := observer.Run(ingestContext); err != nil && !errors.Is(err, context.Canceled) {
				logger.Printf("relay observer (%s) stopped: %v", url, err)
			}
		}()
		stops = append(stops, func() { <-done })
		logger.Printf("relay ingest: %s -> %s", url, localRPC)
	}
	return func() {
		cancel()
		for _, stop := range stops {
			stop()
		}
	}, nil
}

// relayPublisher is how a client's event reaches the relay (the transport) when
// the gateway is configured with one.  The gateway keeps its direct-submit path
// as a fallback for a client that has no relay.
type relayPublisher struct {
	urls   []string
	client *http.Client
}

func newRelayPublisher(urls []string) *relayPublisher {
	if len(urls) == 0 {
		return nil
	}
	return &relayPublisher{urls: urls, client: &http.Client{Timeout: 10 * time.Second}}
}

// Publish sends an already signed Nostr event to every configured relay.  It
// returns nil if at least one relay accepted it, and the last error otherwise.
// The caller (gateway /api/tx) then falls back to the direct validator submit
// when there is no relay at all.
func (publisher *relayPublisher) Publish(ctx context.Context, event Event) error {
	if publisher == nil || len(publisher.urls) == 0 {
		return errors.New("no relay configured")
	}
	var lastErr error
	for _, url := range publisher.urls {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			lastErr = err
			continue
		}
		converted, err := toNostrEvent(event)
		if err != nil {
			relay.Close()
			lastErr = err
			continue
		}
		if err := relay.Publish(ctx, *converted); err != nil {
			relay.Close()
			lastErr = err
			continue
		}
		relay.Close()
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no relay accepted the event")
	}
	return lastErr
}

// toNostrEvent is the inverse of toChainEvent, used by the publisher.
func toNostrEvent(event Event) (*nostr.Event, error) {
	converted := &nostr.Event{
		ID:        event.ID,
		PubKey:    event.Pubkey,
		CreatedAt: nostr.Timestamp(event.CreatedAt),
		Kind:      event.Kind,
		Content:   event.Content,
		Sig:       event.Sig,
	}
	converted.Tags = make(nostr.Tags, len(event.Tags))
	for index, tag := range event.Tags {
		converted.Tags[index] = nostr.Tag(append([]string(nil), tag...))
	}
	return converted, nil
}
