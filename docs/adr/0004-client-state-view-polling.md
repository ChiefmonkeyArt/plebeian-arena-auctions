# ADR 0004: Slim client state view, 304 polling and gzip

Status: accepted (v0.3.1)

## Context

The page polled `GET /api/state` every second and got the whole committed state: every auction, every bid with all of its Cashu proofs (about 4 KB each), and the full used-token list. On the live demo, after one day of bot bidding (74 auctions, 225 bids), that was 1.19 MB a poll, uncompressed, which made bidding feel slow. The state grows with every bid, so it would only get worse. Each validator also serialised the full state twice per block (once for the app hash, once for the snapshot).

## Decision

- `GET /api/state?view=client&bidders=pk,…&closed=N` returns a slim view (`chain/view.go`):
  - every open auction, plus the newest N finished ones (default 12, at most 50);
  - finished auctions, up to 7 days after closing, where one of the caller's Nostr keys (up to 16) still has a refund or a payout to collect;
  - all bids of those auctions with `proofCount` in place of `proofs`;
  - `usedCount` in place of `usedY`.
- The view has an ETag over everything except height and time. The page sends `If-None-Match`; an unchanged view answers `304` with no body, and the page keeps its state. The block height shown comes from `/api/network`.
- `GET /api/bid?id=` returns one committed bid with its proofs. `ArenaClient.claim` fetches them when it is handed a bid from the view.
- The gateway gzips `/api/*` JSON and text assets (JS, CSS, HTML, SVG) when the browser accepts it. It never gzips the mint proxy, images, fonts, range requests or 304s.
- `FinalizeBlock` serialises the state once. The app hash is the SHA-256 of those bytes, as before, and `Commit` publishes the same bytes. The view is built from the committed snapshot, parsed at most once per block.
- The full `GET /api/state` is unchanged, for tools and tests.

## Consequences

- Live data: the view is 47 KB (10 KB gzipped) for a new visitor and 137 KB (28 KB gzipped) for a browser holding five busy demo identities. Most polls are a 304. Before: 1.19 MB every second.
- The app hash and state format are unchanged. v0.3.1 validators agree with v0.3.0 ones, and `FORMAT` stays `3`, so an upgrade keeps the chain.
- The server cannot tell which refunds a browser has already collected, because releases are not recorded on chain. That is why the view keeps the caller's finished auctions for 7 days. ADR 0003's `Settled` mark would let it drop them as soon as they are settled.
- The full state still grows. This ADR shrinks what browsers download; ADR 0003 (snapshots, trimming, pruning) shrinks what validators keep.
- A browser that has been away for more than 7 days no longer sees its old unsettled bids in the view. By then the 24-hour locktime has passed, so the bidder can reclaim alone.
