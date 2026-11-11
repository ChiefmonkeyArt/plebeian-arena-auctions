# ADR 0008: Keep the page's main thread free (wallet worker, 10 Hz redraw)

Status: accepted (v0.4.2)

## Context

On a phone-class CPU (Chromium, 4× CPU throttle) with the demo bots bidding, a v0.4.1 page was busy for 18.5 s of every 19 s. It had 33 long tasks (the longest 298 ms, 4.7 s in total), so taps waited up to 120 ms before the page saw them. A profile showed where the time went:

| Cost | Time | Cause |
| --- | --- | --- |
| Frame redraw | 6.4 s | `renderFrame` ran on every animation frame (60 Hz). Each run looked up about 30 `[data-v]` slots with `querySelectorAll` and checked every bid's owner. |
| Public keys | 3.4 s | `idPub()` and `walletPub()` did a full elliptic-curve multiplication on every call, and the redraw called them for every bid. |
| Formatting | 1.5 s | `toLocaleString` and `toLocaleTimeString` build a new formatter on each call. |
| Wallet maths | 2–3 s | Coco and cashu-ts blinding, unblinding, P2PK locks and release swaps. |

ADR 0006 promises that a tap shows on screen within a frame. That still holds under load only if the main thread has frames to spare.

## Decision

- **Wallet worker.** `WalletClient` (`web/src/lib/wallet.js`) is the page's `ArenaClient`. These calls go to a module Web Worker (`wallet-worker.js`) that runs its own `ArenaClient`: `balance`, `receive`, `faucet`, `lockForBid`, `claim`, `reclaimExpired`, `spent` and `close`.
  - Each wallet's Coco instance, its IndexedDB store and every proof step run there.
  - Reads (`view`, `network`, `chat`) and signed submits stay on the page. They are only fetches and a single Schnorr signature.
  - Errors cross over with `message`, `status`, `body`, `refusals` and `mint`, so the page's handling is unchanged.
  - If the worker cannot start or fails to load, pending and later calls run in the page as before. `arena.js` loads `@cashu/coco-core` on first use, so the main bundle stays small.
- **Redraw at 10 Hz, and at once when something happens.** `renderFrame` runs every 100 ms (the clocks show tenths of a second). It also runs on the next animation frame after a pointer, click, input or key event, a new state, and the pending bid's "sending" and "sent" steps (`kick()`). The instant feedback from ADR 0006 keeps its one-frame promise.
- **Derive each public key once.** `idPub` and `walletPub` keep results in memory, keyed by the secret key. The keys live in the page's memory already, so the cache adds no exposure.
- **Reuse formatters.** One `Intl.NumberFormat('en-GB')` and one `Intl.DateTimeFormat('en-GB')`. The `[data-v]` slots, which are all static in `index.html`, are looked up once per key.

## Consequences

Same profile, same load, local build:

| Measure | v0.4.1 | v0.4.2 |
| --- | --- | --- |
| Main thread busy | 18.5 s | 9.3 s |
| Long tasks | 33 (4.7 s) | 11 (0.86 s) |
| Longest task | 298 ms | 199 ms |

The 40 s tap test showed 6 long tasks totalling 561 ms (live v0.4.1: 18, totalling 2.9 s).

The main page script drops from 398 kB to 73 kB, plus a 264 kB cashu-ts chunk. The wallet worker is a separate 298 kB file, loaded in parallel. CSP already allows `worker-src 'self'`.

The wallet runs in a different thread from the page. Both use the same IndexedDB databases, and only the worker writes to them while it is running.

This is a front-end change only. The chain, gateway, app hash and `FORMAT` (4) are unchanged, so an upgrade keeps the chain.

Tests:
- `web/test/page-cost.mjs` (13 checks, run by `scripts/package.sh` on release) covers the memoised keys and the worker's routing, error passing and fallback.
- `tests/e2e.mjs` (55 checks) is unchanged and passes.
