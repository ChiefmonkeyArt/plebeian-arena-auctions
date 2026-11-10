# ADR 0005: Slim pre-bid check, burst polling and the mint WebSocket

Status: accepted (v0.3.2)

## Context

After v0.3.1 the page still felt slow on the live demo. There were three causes:

- Every bid, including the demo bots' automatic ones, first fetched the full `GET /api/state` (1.25 MB, 370 KB gzipped) to check the lot was still open and the amount high enough. Several bot bids a second meant megabytes of download and a 1.25 MB JSON parse on the main thread. The slow fetch also widened the gap between "check" and "submit", so more bids lost the race and came back as `400` from `/api/tx`.
- After a bid the page waited for its next 1 s poll, after the block (about 1 s) had committed, so a result took up to about 2 s to appear.
- Coco opens the mint's NUT-17 WebSocket (`/mint/v1/ws`) for quote and proof-state updates. It failed on every attempt: nginx did not pass the upgrade headers, so the mint answered 404. Even with them, the gateway would have cut the socket after 15 s, because a hijacked connection keeps the Go server's read and write deadlines.

## Decision

- `placeBid` checks against `GET /api/state?view=client` (ADR 0004). It has the same auctions, high bids and params, without proofs.
- After the user's own bid or a new lot, the page polls every 250 ms for 3 s (`burst()`), then drops back to 1 s. Polls never overlap. Unchanged polls are 304s with no body.
- The gateway lets exactly `GET /mint/v1/ws` upgrade. It replaces the server's 15 s / 60 s deadlines with a 10-minute session cap for that connection only; Coco reconnects on its own. Any other upgrade attempt gets a 400. Suite's nginx passes `Upgrade` and `Connection` on that one location, with HTTP/1.1 and a matching read timeout.

## Consequences

- A bid now costs a few KB before the lock, not 370 KB, and the check-to-submit window is much shorter, so fewer bids are rejected. Note that a rejected bid's sats stay locked until the locktime (24 h by default); see the threat model.
- A user's own actions show as soon as their block commits.
- Coco gets pushed updates instead of failing retries in the console.
- Long-lived sockets are a new resource surface (see the threat model).
- The chain, app hash and `FORMAT` (3) are unchanged, so an upgrade keeps the chain. Restarts still replay from genesis until ADR 0003's snapshots land (they did, in v0.3.3).
