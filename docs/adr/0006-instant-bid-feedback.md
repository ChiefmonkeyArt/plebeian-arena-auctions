# ADR 0006: Instant bid feedback and one-tap bids

Status: accepted (v0.3.4)

## Context

After v0.3.2 a bid still felt unresponsive on the live demo, and the one-tap buttons (Next, Jump, Big move) looked as if they did nothing. Measured on auctions.chiefmonkey.art from a nearby host, a tap went through a slim view read, a Coco lock swap with the mint, a balance refresh and `POST /api/tx` before anything changed on screen (about 0.8 to 1.0 s), and the bid appeared only after its block committed (1.5 to 2.3 s). From farther away, every round trip adds to that. During that time:

- the page showed nothing: the button only pulsed after success;
- a second tap was silently dropped (`previous bid still settling`), so people tapped again and again;
- the demo bots running in the same browser kept bidding, so a tap was often priced against a bid that had already been beaten, and came back as a rejection with its sats locked until locktime;
- the first bid of a session could also wait for the faucet.

## Decision

- **Optimistic pending bid.** On tap, in the same frame, the page shows your bid as the price ("Your bid · sending"), a pending row at the top of the bid list, and a ring on the button. After `/api/tx` accepts it the label changes to "sent, next block". The pending state clears when a poll shows your bid at that amount (or after 10 s), or immediately with a toast and a shake if it is refused. The chain stays the only source of truth: nothing is recorded locally as a bid.
- **One-tap buttons price against the fresh view.** Next, Jump and Big move mean "0, 2 or 5 increments above the next valid bid". The amount is computed from the view read just before the lock. If that is more than two increments above what the button showed, the bid is refused before any sats are locked and the toast says the new price. A typed Exact amount is never changed.
- **Taps are never silently dropped.** A tap made while your bid is in flight is held (only the latest), with a toast. When the first bid lands, the held tap is sent only if you are no longer leading; otherwise it is skipped with a toast.
- **Bots yield.** The demo bots in this browser do not bid while your bid is in flight or for 5 s after your tap.
- **Fewer steps before the submit.** The balance refresh and ledger entry move after `/api/tx`; a bid waits for an in-flight top-up instead of racing the wallet; while a lot is open the page tops up in the background when your balance falls below two Big moves.
- Buttons use `touch-action: manipulation` and a pressed state, so a tap registers without a double-tap-zoom delay.

## Consequences

- Every tap gets visible feedback within a frame; the chain result follows about one block later.
- A one-tap bid can cost up to two increments more than the button showed when the price moves mid-flight. That is the meaning of "next bid", and it is bounded.
- Repeated taps cannot stack several bids, and rejections from racing your own bots are gone. Bids from other browsers can still win a race; those still come back as a rejection with sats locked until locktime (threat model).
- Front end only. Chain, gateway, app hash and `FORMAT` (3) are unchanged, so an upgrade keeps the chain and the v0.3.3 snapshots.
