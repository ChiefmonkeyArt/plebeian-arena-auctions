package main

// Relay ingest: instead of (only) accepting a signed Nostr event over HTTP at
// the gateway, every validator subscribes to the configured relay(s) and
// submits the events it sees there into its own node's mempool.  The relay is
// transport and discovery; the chain stays the durable record.
//
// This is a port of the observer half of the sibling `internal/relay` package
// onto this module.  It keeps the behaviour that mattered there:
//
//   - the event's Schnorr signature is verified BEFORE anything else, so a
//     hostile or malformed event is dropped rather than crashing the observer;
//   - events are de-duplicated by id, so a republish (or a replay) commits once;
//   - a reconnect re-subscribes from the last created_at actually seen, so a
//     dropped connection loses nothing the relay still holds;
//   - the last transport error and the live-subscription flag are exposed for
//     readiness probes and tests.
//
// The relay itself is not implemented here.  It is an external process (for
// tests, `nak serve`; in production, any NIP-01 relay) and it never timestamps,
// never orders, and never decides validity beyond a signature check.  Every
// time rule keeps running on committed block time.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// RelayKinds are the only kinds the ingest transports: auction create and bid.
var RelayKinds = []int{KindCreate, KindBid}

// IsRelayKind reports whether kind is one this ingest transports.
func IsRelayKind(kind int) bool {
	for _, k := range RelayKinds {
		if kind == k {
			return true
		}
	}
	return false
}

// ObserverConfig configures one observer.
type ObserverConfig struct {
	// URL is the relay websocket, e.g. ws://127.0.0.1:10547.
	URL string
	// Submitter delivers each observed event to the chain.
	Submitter Submitter
	// Kinds overrides the subscribed kinds; defaults to RelayKinds.
	Kinds []int
	// Since is the earliest created_at to request on the first subscribe.  It
	// advances as events are seen so a reconnect only re-fetches the window it
	// might have missed.  Zero means "from the beginning of the relay".
	Since *time.Time
	// ReconnectDelay is how long to wait before retrying a dropped connection.
	ReconnectDelay time.Duration
	// OnSubmit, when set, is called after a successful submission.  It must not
	// block.
	OnSubmit func(event Event, result SubmitResult)
	// Logger receives progress; nil means log.Default.
	Logger *log.Logger
}

// Observer reads auction events from a relay and submits them to the chain.  One
// observer per validator is the intended deployment.  The chain's own state
// guard (a create for an existing auction, a bid already recorded) makes a
// replay a no-op, so running more than one observer is safe too.
type Observer struct {
	config ObserverConfig

	mu         sync.Mutex
	lastSeen   time.Time
	seenIDs    map[string]struct{}
	submitted  int
	lastError  error
	subscribed bool
}

// NewObserver validates configuration and returns an observer ready to Run.
func NewObserver(config ObserverConfig) (*Observer, error) {
	if config.URL == "" {
		return nil, errors.New("observer requires a relay URL")
	}
	if config.Submitter == nil {
		return nil, errors.New("observer requires a submitter")
	}
	if len(config.Kinds) == 0 {
		config.Kinds = append([]int(nil), RelayKinds...)
	}
	if config.ReconnectDelay <= 0 {
		config.ReconnectDelay = time.Second
	}
	if config.Logger == nil {
		config.Logger = log.Default()
	}
	observer := &Observer{config: config, seenIDs: map[string]struct{}{}}
	if config.Since != nil {
		observer.lastSeen = *config.Since
	}
	return observer, nil
}

// Run observes until ctx is cancelled, reconnecting on transport failure.
func (observer *Observer) Run(ctx context.Context) error {
	for {
		if err := observer.session(ctx); err != nil && !errors.Is(err, context.Canceled) {
			observer.recordError(err)
			observer.config.Logger.Printf("relay observer: session ended: %v (retrying in %s)", err, observer.config.ReconnectDelay)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(observer.config.ReconnectDelay):
		}
	}
}

// session runs one connection.  Every fresh subscription asks for events since
// the last one it actually processed, so anything published while disconnected
// is delivered by the replay rather than lost.
func (observer *Observer) session(ctx context.Context) error {
	observer.mu.Lock()
	since := observer.lastSeen
	kinds := append([]int(nil), observer.config.Kinds...)
	observer.mu.Unlock()

	filters := make([]nostr.Filter, 0, len(kinds))
	for _, kind := range kinds {
		filter := nostr.Filter{Kinds: []int{kind}}
		if !since.IsZero() {
			// One second of slack so an event created in the same second as
			// the last one seen is not skipped by the boundary.
			stamp := nostr.Timestamp(since.Unix() - 1)
			filter.Since = &stamp
		}
		filters = append(filters, filter)
	}

	observer.config.Logger.Printf("relay observer: subscribing to %s since=%s kinds=%v", observer.config.URL, describeSince(since), kinds)
	subscription, err := connectAndSubscribe(ctx, observer.config.URL, filters)
	if err != nil {
		return err
	}
	observer.setSubscribed(true)
	defer func() {
		observer.setSubscribed(false)
		subscription.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-subscription.Events:
			if !ok {
				return subscription.CloseReason()
			}
			if event == nil {
				continue
			}
			observer.handle(ctx, event)
		}
	}
}

// handle verifies and submits one event.  A verification failure is a drop, not
// a crash: a hostile or malformed event must not take a validator's observer
// down, and the chain would reject it anyway.
func (observer *Observer) handle(ctx context.Context, event *nostr.Event) {
	signed := toChainEvent(event)
	// The same gate decodeTx applies: canonical serializer + Schnorr verify.
	// Verifying here means a relay can forward garbage cheaply without ever
	// reaching this node's mempool.
	if err := signed.Verify(); err != nil {
		observer.config.Logger.Printf("relay observer: dropping unverifiable event %s: %v", event.ID, err)
		return
	}
	if !IsRelayKind(signed.Kind) {
		observer.config.Logger.Printf("relay observer: dropping unsupported kind %d (%s)", signed.Kind, event.ID)
		return
	}
	observer.mu.Lock()
	if _, duplicate := observer.seenIDs[event.ID]; duplicate {
		observer.mu.Unlock()
		return
	}
	observer.seenIDs[event.ID] = struct{}{}
	observer.mu.Unlock()

	result, err := observer.config.Submitter.SubmitEvent(ctx, signed)
	if err != nil {
		// Forget the id so a retry after a transient submit failure is
		// attempted again on reconnect, instead of being silently marked done.
		observer.mu.Lock()
		delete(observer.seenIDs, event.ID)
		observer.mu.Unlock()
		observer.recordError(fmt.Errorf("submit %s: %w", event.ID, err))
		observer.config.Logger.Printf("relay observer: submit failed for %s: %v", event.ID, err)
		return
	}
	observer.mu.Lock()
	if created := time.Unix(int64(event.CreatedAt), 0); created.After(observer.lastSeen) {
		observer.lastSeen = created
	}
	observer.submitted++
	observer.mu.Unlock()
	if observer.config.OnSubmit != nil {
		observer.config.OnSubmit(signed, result)
	}
	observer.config.Logger.Printf("relay observer: committed %s kind=%d height=%d", event.ID, event.Kind, result.Height)
}

// Stats reports how many events this observer committed, the newest created_at
// it has seen, and the last transport error; readiness probes and tests use them.
func (observer *Observer) Stats() (submitted int, lastSeen time.Time, lastError error) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.submitted, observer.lastSeen, observer.lastError
}

// HandleForTest runs one event through the same verification and submission path
// a live subscription uses, without a socket.  It exists so a delivery whose
// bytes a relay might refuse can still be tested at the verification boundary;
// production code reaches this path only through session().
func (observer *Observer) HandleForTest(ctx context.Context, event *nostr.Event) {
	observer.handle(ctx, event)
}

// Subscribed reports whether a relay subscription is currently open.  Tests and
// readiness probes use it to avoid publishing before the observer is listening
// (an ephemeral relay may drop an EVENT that has no matching subscriber).
func (observer *Observer) Subscribed() bool {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.subscribed
}

func (observer *Observer) setSubscribed(value bool) {
	observer.mu.Lock()
	observer.subscribed = value
	observer.mu.Unlock()
}

func (observer *Observer) recordError(err error) {
	observer.mu.Lock()
	observer.lastError = err
	observer.mu.Unlock()
}

func describeSince(since time.Time) string {
	if since.IsZero() {
		return "beginning"
	}
	return since.UTC().Format(time.RFC3339)
}

// toChainEvent converts a go-nostr event into this module's wire form.  Tag
// order and values are preserved exactly: the event id is a hash over them, so
// any reordering or loss would invalidate a legitimate event.
func toChainEvent(event *nostr.Event) Event {
	converted := Event{
		ID:        event.ID,
		Pubkey:    event.PubKey,
		CreatedAt: int64(event.CreatedAt),
		Kind:      event.Kind,
		Content:   event.Content,
		Sig:       event.Sig,
	}
	converted.Tags = make([][]string, len(event.Tags))
	for index, tag := range event.Tags {
		converted.Tags[index] = append([]string(nil), tag...)
	}
	return converted
}

// SortedSubmissions returns the events a MemorySubmitter recorded in chain
// order; a small helper for tests and callers that want a stable ordering.
func SortedSubmissions(submitter *MemorySubmitter) []Event {
	events := submitter.Submissions()
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CreatedAt != events[j].CreatedAt {
			return events[i].CreatedAt < events[j].CreatedAt
		}
		return events[i].ID < events[j].ID
	})
	return events
}
