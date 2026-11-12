# ADR 0009: Validators push every settlement; two auction modes

Status: accepted (approved by the owner 2026-11-12; shipped in v0.5.0, chain format 5)

## Context

The owner wants two kinds of auction, chosen by the seller when they list:

- **Fixed time.** A lot ends at a set time. Last-second sniping is allowed, and the highest bid at zero wins.
- **Anti-snipe.** The seller sets a duration and a window X. Any bid in the last X resets the countdown to X. There is no hidden hard end.

Losing bids must be refunded continually, and the winning bid must reach the seller the moment the clock hits zero.

v0.4.2 does not do this:

- **One soft close for every lot.** A late bid adds 20 s (`ExtendSec`), but only up to `HardEnd = end + MaxExtendSec`. That hard end is still a snipe point.
- **Refunds and payouts are pulled.** A release needs the receiving wallet to sign the exact outputs (`/api/release` with `auth`). An outbid bidder's page must be open to collect the refund. The seller must open the site within the lock margin after the close to be paid.
- **Lock expiry is tied to the hard end.** Each bid's locktime must be at least `HardEnd + LockMarginSec`. With no end time, an anti-snipe lot could outlast a lock. The leading bidder could then reclaim their sats alone while still winning.

## Decision

### Auction modes

- The listing event (kind 1440) gets `mode: "fixed" | "antisnipe"`. Anti-snipe lots also get `windowSec`.
- **`fixed`:** `endAt = created + durationSec`. Bids never move it. There is no hard end.
- **`antisnipe`:** a bid that lands with less than `windowSec` left sets `endAt = blockTime + windowSec`. There is no cap and no hard end.
- `windowSec` must be within the range set by `Params.MinWindowSec` and `Params.MaxWindowSec`. Built: 15 s to 15 min.
- The global `SoftCloseSec`, `ExtendSec`, `MaxExtendSec` and `HardEnd` are removed.
- Lots still close on time. Each validator sends `close` when a lot is due (ADR 0007), and block time is the proposer's clock.

### Validators push; nobody has to be online

A **settler** loop runs in the gateway after every committed block. Each move below is one FROST 3-of-4 signing round and one mint swap.

| Trigger | Move | Output lock |
|---|---|---|
| A bid becomes `outbid`, `void` or `lost` | Refund | P2PK to the bidder's wallet key |
| A lot closes with a winner | Payout | P2PK to the seller's wallet key |
| The leading bid's locktime is less than `LockMarginSec / 2` away | Re-lock | P2PK to the FROST group key, refund key = bidder, new locktime = now + `LockMarginSec` |

- **The validators can check what they sign.** Outputs are blinded, so for each output the settler reveals the secret and the blinding factor. Each validator recomputes `B_` and checks three things: the lock is the one in the table for this bid, the amounts add up, and the bid's chain status allows the move. Only then does it commit a nonce. Revealing these is harmless, because each output can only be spent with the recipient's key (or the group key, for a re-lock).
- **Settlements are recorded on chain.** After the swap, the settler sends a `settle` transaction with the bid ID, the move, the new proofs and the mint's DLEQ proofs. Validators check that it matches the move they signed, then:
  - set the bid's `settled` field;
  - for a re-lock, replace the bid's proofs and locktime.

  A bid is settled at most once per move. A re-lock bumps a counter.
- **Collecting.** Wallets collect pushed refunds and payouts from the client view whenever they are online. Each one only needs the recipient's own key, so there is no deadline.
- **Timing.** A refund or payout completes in the block after its trigger, plus one FROST round and one swap. Measured in v0.5.0, see below.

### Lock expiry for bids

- **Fixed lots:** `locktime ≥ endAt + LockMarginSec`, as today.
- **Anti-snipe lots:** `locktime ≥ blockTime + LockMarginSec`. The re-lock rule keeps the leading bid covered for as long as the lot runs.
- **If a re-lock cannot happen** (fewer than 3 validators reachable until the leading lock expires), the lot closes with no sale. The bid becomes `lost` and is refunded by push, or by the bidder's own reclaim. A winner is never left in a lock the bidder can empty.

### Kept as fallbacks

- The existing pull release (`/api/release` with the wallet's `auth`) stays, so a page can still settle if the settler is behind.
- Reclaim after locktime stays as the last resort if every validator is gone.
- Neither changes who can move funds: every escrow move still needs 3 of 4 validators.

## Consequences

- **Good:**
  - Refunds are instant and continual.
  - The seller is paid at zero.
  - Anti-snipe lots have no snipe point.
  - Bidders and sellers can close the page.
- **Cost:**
  - One FROST round and one mint swap per outbid bid and per close.
  - Re-locks for long anti-snipe lots.
  - The settler queue bounds the rate. A burst of outbids is processed in order.
- **New chain format (5):** the live demo chain is reset on upgrade. The 78 closed demo lots are archived, not migrated.
- **Risk:** the settler reveals output blinding factors on chain. That is safe for P2PK outputs, and tests will cover spending them with the wrong key.

## Tests (added to `tests/e2e.mjs` and `go test ./chain/`)

- **Fixed lot:** a bid at T−1 s wins; there is no extension; the payout is pushed with the seller offline.
- **Anti-snipe lot:**
  - a bid inside X resets the countdown to X;
  - repeated resets have no cap;
  - the payout is pushed at zero.
- **Refund pushed while the bidder is offline:** the bidder's page is closed when outbid, then opened later and collects the refund.
- **Re-lock:** with a short `LockMarginSec`, a long anti-snipe lot re-locks the leading bid, and the bidder's reclaim attempt is refused before the new locktime.
- **No quorum:**
  - with 2 of 4 validators up, the settler does nothing;
  - once a third validator returns, the queue drains;
  - if the leading lock expires unrenewed, the lot closes with no sale.
- **Validator refusals:** each validator refuses a settle whose revealed output does not match `B_`, has the wrong lock key or the wrong amount.
- **Conservation:** total sats across wallets, escrow and pushed proofs never change.

## As built (v0.5.0)

### FROST signing: all four asked, three needed

- The settler asks **all four** validators for a nonce commitment at once (`/frost/commit`). Each one checks the move against its own copy of the chain, as above.
- **Majority wins.** The coordinator groups the answers by the exact message each validator agreed to sign, and picks three that agree (`pickSigners`). One validator that is offline, behind or misbehaving cannot block or change the signature.
- **Retry without a bad share.** If one of the three chosen returns a bad round-2 share, the coordinator runs one more round without it, using the fourth validator.
- **A validator one block behind waits.** The settler sends the height it read the due list at; a validator not yet at that height waits for it (at most 2 s) before judging. Without this, with one validator down, a validator a few milliseconds behind refused and the push waited 5–9 s for a retry.
- Each validator runs one long-lived `arena-frost serve` process (Rust), so a signing round starts no new processes.
- The settler checks the mint's DLEQ proof on every new output before it records the settlement, and keeps a journal (`run/settle-journal.jsonl`) so a crash between the swap and the `settle` transaction is recovered from the mint (`/v1/checkstate`, `/v1/restore`), not lost. Failed attempts back off from 1 s up to 10 min.
- Each pushed result goes to the page over the existing event stream as `{type: "settled", bid, to, proofs, ms, cosigners}`. A page that missed it collects the same ecash from the chain (`/api/bid?id=`). The page's pull claim runs only for a bid left unsettled for more than 10 s.
- The re-lock trigger is the leading lock being less than `LockMarginSec / 2` away, as decided; anti-snipe locks are set to `now + LockMarginSec + 60`, fixed ones to `endAt + LockMarginSec + 15`.

### Speed (local run, 4 validators and the mint on one machine)

| Step | Measured |
|---|---|
| FROST round (commit + sign + aggregate, 3 of 4) | 10–73 ms, usually 10–30 ms |
| Mint swap | 17–34 ms |
| Settler total (FROST + mint + DLEQ + journal) | about 30–100 ms |
| Ecash in the wallet, counted from the block's timestamp | 15–790 ms (refunds 300–790 ms; the two payouts 15 ms and at the end second) |
| Same, with Validator 4 stopped | 786 ms (was 8.2 s before the height wait) |

The 0.5 s goal is met by the settlement work itself (under 0.1 s). What is left is the block: a refund can only start once the outbidding bid is committed, and block timestamps are the proposer's clock, so the "after the block" figure also carries clock skew. The payout is pushed in the same second the clock reaches zero.

### Security points

- No validator, gateway or settler can move an escrow alone: every move is one signature from the FROST group key, which needs 3 of 4 key shares. All four shares still sit on one host in this demo (see the threat model); real separation needs four operators.
- What the validators sign is fixed by the chain: refund to the bidder's own wallet key, payout to the seller's wallet key from the signed listing, re-lock to the same group key with the bidder's refund path. A settler that asks for anything else gets no signature (tests: forged outputs, wrong lock key, wrong amount, redirecting a settled escrow).
- Revealed blinding factors only let someone recompute the output; spending still needs the recipient's key.
- A pushed proof is locked (P2PK) to the recipient's wallet key, so the event stream can be public.
- The pull release and the reclaim after locktime stay as fallbacks.

