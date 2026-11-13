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
