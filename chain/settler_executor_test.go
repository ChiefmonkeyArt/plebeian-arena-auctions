package main

// The settler is an EXECUTOR, not an author (spec §5). These tests pin the two
// properties that make that true, without needing the FROST tool:
//
//   - the settler derives its outputs from the bid's COMMITTED outcome
//     template (templateMaterial), never from anything caller-supplied;
//   - the swap it submits carries TWO witness signatures: the bidder's
//     pre-signature from the committed template, and the committee's -- in
//     that order. With only one, the mint refuses.
//
// The coordinator's own FROST round is exercised by the /frost handlers and by
// releasePolicy; here we drive the swap directly against a stub mint, so the
// assertions are about the witness the settler builds and the template it
// reads, not about HTTP plumbing.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSettlerSwapCarriesBidderAndCommitteeSignatures runs the settler's swap
// against a stub mint and asserts the witness order and the outputs submitted.
func TestSettlerSwapCarriesBidderAndCommitteeSignatures(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	_, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)
	bid := a.st.Bids[ev1.ID]
	if bid.Status != "outbid" {
		t.Fatal("setup")
	}

	var gotWitness []string
	var gotOutputs []SignOutput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/swap" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Inputs []struct {
				Witness string `json:"witness"`
			} `json:"inputs"`
			Outputs []SignOutput `json:"outputs"`
		}
		json.Unmarshal(body, &req)
		gotOutputs = req.Outputs
		var w2 struct {
			Signatures []string `json:"signatures"`
		}
		json.Unmarshal([]byte(req.Inputs[0].Witness), &w2)
		gotWitness = w2.Signatures
		sigs := make([]blindSig, len(req.Outputs))
		for i, o := range req.Outputs {
			sigs[i] = m.blindSign(t, o)
		}
		json.NewEncoder(w).Encode(map[string]any{"signatures": sigs})
	}))
	defer srv.Close()

	st := &settler{p: a.st.Params, mint: srv.URL, hc: &http.Client{}}
	outs, _, bidderSig, err := st.templateMaterial(bid, "refund")
	if err != nil {
		t.Fatal(err)
	}
	const committeeSig = "00" // placeholder: the stub mint does not verify it
	if _, err := st.swap(bid.Proofs, outs, bidderSig, committeeSig); err != nil {
		t.Fatalf("swap: %v", err)
	}

	if len(gotWitness) != 2 {
		t.Fatalf("the witness must carry BOTH signatures, got %d", len(gotWitness))
	}
	if gotWitness[0] != bidderSig {
		t.Fatal("the first witness signature must be the bidder's committed pre-signature")
	}
	if gotWitness[1] != committeeSig {
		t.Fatal("the second witness signature must be the committee's")
	}
	// The outputs submitted are exactly the committed refund template's.
	want, _, _, _ := st.templateMaterial(bid, "refund")
	if len(gotOutputs) != len(want) {
		t.Fatalf("outputs submitted %d, want %d", len(gotOutputs), len(want))
	}
	for i := range want {
		if gotOutputs[i].B != want[i].B || gotOutputs[i].Amount != want[i].Amount {
			t.Fatalf("output %d is not the committed template's output", i)
		}
	}
}

// TestSettlerRefusesTemplatelessBid: the settler never builds an output of its
// own, so a bid with no committed template cannot be moved by it.
func TestSettlerRefusesTemplatelessBid(t *testing.T) {
	a, _, id := liveApp(t)
	st := &settler{p: a.st.Params}
	bid := &Bid{ID: hx(1), Auction: id, Wallet: hx(2), Amount: 100, Proofs: []Proof{{ID: a.st.Params.KeysetID, Amount: 100, Secret: "s", C: "c"}}}
	if _, _, _, err := st.templateMaterial(bid, "refund"); err == nil {
		t.Fatal("a template-less bid must not be movable by the settler")
	}
}

// TestReleasePolicySignsCommittedOutputs: the committee's hash is over the
// committed template's outputs, so the committee signs exactly what the bidder
// pre-signed. A leading bid is not refundable; an unknown outcome is refused.
func TestReleasePolicySignsCommittedOutputs(t *testing.T) {
	a, m, id := liveApp(t)
	alice, bob := newBidder(t), newBidder(t)
	ev1, tx1 := m.bidTx(t, a, alice, id, 150, "aa")
	ev2, tx2 := m.bidTx(t, a, bob, id, 200, "bb")
	finalize(t, a, 11, tNow+1, tx1, tx2)

	h, code, err := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "refund"})
	if code != 200 {
		t.Fatalf("committed refund refused: %d %v", code, err)
	}
	outs, _, _, _ := (&settler{p: a.st.Params}).templateMaterial(a.st.Bids[ev1.ID], "refund")
	want := sha256Sum(sigAllMessage(a.st.Bids[ev1.ID].Proofs, outs))
	if h != want {
		t.Fatal("the committee hash must cover the committed template's outputs")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev2.ID, Outcome: "refund"}); code == 200 {
		t.Fatal("a leading bid must not be refundable")
	}
	if _, code, _ := releasePolicy(a, SignReq{Bid: ev1.ID, Outcome: "nonsense"}); code == 200 {
		t.Fatal("an unknown outcome must be refused")
	}
}
