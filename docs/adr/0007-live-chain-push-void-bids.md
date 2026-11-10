# ADR 0007: Push updates, timings and void bids

Status: accepted (v0.4.0)

## Context

After v0.3.4 a bid showed on screen at once (ADR 0006), but three things were still slow or costly:

- **The page polled.** It asked for the state every second, and every 250 ms for 3 s after a bid. A block could commit just after a poll and stay unseen for up to a second.
- **Nobody could see where the time went.** "It's slow" could mean the network, the wallet, the validators or the block.
- **A bid that lost a race stayed locked for a day.** If your bid was priced against a state that had just changed (someone bid first, or the lot ended), the validators rejected it after your wallet had locked the sats to the escrow key. The sats came back only after the locktime (24 h on the live demo), alone, through the mint.

Blocks on demand (ADR 0003 §1) change the chain format anyway, so the rule change for the last point ships in the same new chain.

## Decision

### Void bids

- The validators check a bid in two stages. First: is it a real, fully locked escrow (event signature, proofs from the pinned keyset, valid DLEQ, unused, the right total, a lock to the FROST key with the bidder's refund key and a long enough locktime)? A bid that fails is refused, as before.
- Second: did it lose a race (lot closed or past its end, already the highest bidder, below the minimum, the seller's own lot)? Such a bid is now **void**. It is recorded on chain with status `void`, its proofs are marked used, and it is listed in the auction's `voids`, not in `bids`. It never leads and never wins.
- A void bid is refundable at once. The validators' release policy treats `void` like `outbid` and `lost`, and the page's settle loop refunds it through FROST like any other refund.
- CheckTx answers a late bid with code 0 and `late: <reason>`. The gateway passes that on as `late`, so the page can say "too late, your sats come straight back" before the block.
- Each auction keeps at most 256 void bids. Past that, late bids are refused and wait for the locktime as before. Every void bid costs a real lock at the mint, so the cap and the nginx request limits bound the spam.
- The client view shows a caller's own void bids and nobody else's.

### Push

- `GET /api/events` on the gateway is a Server-Sent Events stream. It sends `{"h": <height>, "now": <ms>}` when the first running validator's committed height changes, checked every 100 ms and only while someone listens. The first listener after an idle spell gets its first height from the next check, not the height kept from before (fixed in v0.4.1). It also sends a ping every 15 s, `retry: 2000` and `X-Accel-Buffering: no`. It is not gzipped. Each write has a 10 s deadline. Each stream ends after 15 min (the browser reconnects), and 512 streams at most are allowed (then 503; polling still works).
- The page opens one `EventSource`. On each new height it fetches the state at once, usually a small conditional request. While the stream is open the fallback poll slows from 1 s to 5 s and the after-bid burst is skipped.
- The page's clock now follows the validators' wall clock (`now` in the view and the events), not the last block's time. With blocks on demand the last block can be a minute old.

### Timings

The Network drawer lists your last 20 bids, each with the time from tap to on screen, tap to accepted by a validator, and tap to in a block. It also shows whether updates are pushed or polled, and the round trip to the gateway.

## Considered options

- **WebSocket instead of SSE.** It works both ways, which we do not need. It also needs an upgrade path through nginx, and the Suite already proxies one WebSocket (the mint's). SSE is plain HTTP and reconnects by itself. Chosen: SSE.
- **Push the whole state.** That means more bytes per block for every listener, and the per-user view would need per-stream filters. A height tick plus a conditional fetch is cheap enough.
- **Refuse late bids before the lock.** The page already does this against a fresh view (ADR 0006). It cannot close the race window between the check and the block.
- **Refund void bids from the chain without the bidder.** The release needs fresh mint outputs blinded by the bidder's wallet, so the bidder's page has to ask. It does so on its next settle pass, about 1.5 s later.

## Consequences

- A void bid is history like any other bid: it stays in the state and the ledger archive (ADR 0003 §4), and its proofs stay in `UsedY`.
- `TxCount` counts void bids. `rejections` lists only refused ones.
- Chain format 4: the new rules and the hash change (ADR 0003 §1) need a new chain. `arena init -if-needed` re-creates it on upgrade. Old bids, lots and blocks are gone (fake sats). Wallet balances, held by the mint and Coco, are kept. Locks from the old chain are reclaimable after their locktime, as before.
- The Suite's nginx must not buffer `/api/events`. The gateway's `X-Accel-Buffering: no` header covers that without a vhost change.
- Measured locally after the change: on screen 11 to 23 ms, accepted by a validator 0.3 s, in a block 0.6 to 1.1 s (v0.3.4 on the live site: 1.2 to 2.1 s). A commit reaches the page about 0.4 s after the transaction.

## Related

- ADR 0003 (blocks on demand, pruning), ADR 0006 (instant bid feedback), `docs/THREAT_MODEL.md`.
