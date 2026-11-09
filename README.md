# Plebeian Auctions · Arena (fake sats, 4 validators)

A from-scratch, working MVP of decentralised live auctions: four CometBFT validators order every listing and bid, bids are real Cashu ecash locked to a 3-of-4 validator escrow, and outbid bidders are refunded the moment they are beaten. Front end is the C Arena template wired to the live chain. Fake sats only.

## Architecture

```
browser (C Arena UI, cashu-ts, nostr-tools)
   │  signed Nostr events (1440 list · 1441 bid · 1442 chat) + locked ecash
   ▼
gateway :8080 ── static UI, /api/*, /mint/* proxy, supervises 4 nodes
   │
   ├─ V1..V4  CometBFT v1 (in-process) + ABCI auction app + escrow co-signer
   │          p2p 26656+10i · rpc 26657+10i · http 7101+i
   └─ Nutshell mint :3338 (FakeWallet, NUT-11 P2PK, NUT-12 DLEQ)
```

- Consensus: blocks need ≥3 of 4 validator signatures; the chain keeps running with one validator down.
- Bid validity (deterministic, on every validator): signed by bidder, ≥ high + step, not the seller, DLEQ-verified proofs from the pinned keyset, unspent-on-chain, sum = amount, lock = P2PK to V1 with V2–V4 as extra pubkeys, `n_sigs=3`, `SIG_ALL`, refund key = bidder, locktime ≥ hard end + margin.
- Soft close: late bids add 20 s, capped by a hard end.
- Settlement: each validator's `/sign` only co-signs a refund for an outbid/lost bid (authorised by the bidder) or a payout of the winning bid to the seller. The mint enforces 3 of 4 signatures. If validators vanish, the bidder reclaims alone after locktime.

## Run

```bash
cd arena-auctions && ./scripts.sh build && ./serve.sh
```

Open http://127.0.0.1:8080. Other commands:

```bash
./scripts.sh reset && ./scripts.sh start && ./scripts.sh test
```

`test` runs `tests/e2e.mjs`: 30 acceptance checks (bids, instant refunds, payout, 2-of-4 rejected by the mint, validator stop/catch-up, reclaim after locktime, conservation of sats).

## Limits (MVP)

- Fake sats, unaudited, one operator runs all four validators on localhost.
- Native NUT-11 3-of-4 multisig instead of FROST; CometBFT p2p instead of FIPS; cashu-ts instead of Coco.
- Per-browser generated Nostr keys (no NIP-07 yet); chat is signed but held in gateway memory, not on chain.
- App state is in memory and replays from genesis on restart.
