package main

import (
	"encoding/json"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// TestGoNostrEventMatchesChainSerializer is the load-bearing assumption for the
// whole ingest: an event signed by the go-nostr library (what a front end or nak
// produces) must verify under this module's own Event.Verify, which hashes
// Event.Serialize. If this fails, no relayed event could ever be accepted.
func TestGoNostrEventMatchesChainSerializer(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	event := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(1_700_000_000),
		Kind:      KindCreate,
		Tags:      nostr.Tags{{"a", "b"}},
		Content:   `{"title":"x"}`,
	}
	if err := event.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var chainEvent Event
	if err := json.Unmarshal(raw, &chainEvent); err != nil {
		t.Fatalf("unmarshal into chain Event: %v", err)
	}
	if chainEvent.ID != event.ID {
		t.Fatalf("id mismatch: chain=%s go-nostr=%s", chainEvent.ID, event.ID)
	}
	if err := chainEvent.Verify(); err != nil {
		t.Fatalf("chain Event.Verify rejected a go-nostr signed event: %v", err)
	}
}
