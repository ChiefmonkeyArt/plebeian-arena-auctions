# ADR 0011: Wallets repair themselves after the browser loses their store

Status: accepted (bug fix in v0.5.1, after the owner reported on 2026-11-13 that bidding had stopped on his phone)

## Context

Each identity's Coco wallet makes its ecash outputs from a seed kept in localStorage. Its proofs and the counters that say which outputs it has already used are kept in IndexedDB. A browser can clear IndexedDB but keep localStorage. iOS browsers do this under storage pressure. The counters then start again at 0, and the mint refuses every new output as "outputs already signed". Top-ups, received refunds and payouts, and bid locks all failed. The bots' bids and the background top-ups fail without a message, so the page showed 0 sats and no bids.

## Decision

- **Restore on the refusal.** When the mint answers "already signed", the wallet runs Cashu restore (NUT-09, which the mint supports) once for that identity. Restore moves the counters past every output the mint has signed and brings back the identity's unspent ecash. The wallet then retries the top-up, receive or bid lock once. Concurrent failures share one restore.
- **Failures show.** A failed top-up, or demo-bot bids failing three times in a row, now shows a toast, at most once a minute for each kind. Each also logs a warning.
- **Out of scope.** No change to the chain, the mint or the protocol. Ecash from a release swap that failed to land before this fix is not recoverable by restore (those outputs are random). It is fake sats.

## Consequences

- A wallet whose store was lost repairs itself on its next action, and gets its unspent ecash back.
- A restore costs a few mint calls (batches of blinded messages) once per lost store.
- Test: `web/test/resync.mjs`, 8 checks against the local stack: top-up, bid lock and receive on a lost store.

## Addendum (v0.5.2): wallet worker handshake

The owner's phone (Brave on iOS) then showed "wallet worker: unknown op faucet" on page load. The page posted its `init` message to the wallet worker (v0.4.2) before the worker's module graph had loaded. iOS WebKit dropped that message, so the worker had no client and refused every wallet operation. Top-ups, refunds and bot bids all failed. Before v0.5.1 those failures were silent, so this was probably part of the original "bids stopped" report too.

- **Handshake.** The worker posts `ready` once its handler is installed. The page queues wallet calls until `ready`, then sends `init` and the queue.
- **Belt and braces.** Every message carries the API base, and the worker builds its client on the first call if `init` was lost.
- **Fallback.** If no `ready` arrives within 8 s, or the worker errors, the page stops the worker and runs the wallet in the page (as before v0.4.2).
- Test: `web/test/worker-ready.mjs`, 9 checks with a fake worker that drops early messages or never becomes ready.
