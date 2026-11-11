# Plebeian Auctions · Arena (fake sats, 4 validators)

A from-scratch, working MVP of decentralised live auctions: four CometBFT validators order every listing and bid, bids are real Cashu ecash locked to one FROST 3-of-4 group key held by the validators, and outbid bidders are refunded the moment they are beaten. Front end is the C Arena template wired to the live chain. Fake sats only.

## Architecture

```
browser (C Arena UI, Coco wallet + cashu-ts, nostr-tools)
   │  signed Nostr events (1440 list · 1441 bid · 1442 chat) + locked ecash
   ▼
gateway :8080 ── static UI, /api/* (incl. /api/release), /mint/* proxy, supervises 4 nodes
   │
   ├─ V1..V4  CometBFT v1 (in-process) + ABCI auction app + FROST share
   │          (/frost/commit · /frost/sign via bin/arena-frost, Rust)
   │          p2p 26656+10i · rpc 26657+10i · http 7101+i
   └─ Nutshell 0.21 mint :3338 (FakeWallet, NUT-11 P2PK, NUT-12 DLEQ)
```

- Consensus: blocks need ≥3 of 4 validator signatures; the chain keeps running with one validator down.
- Bid validity (deterministic, on every validator): signed by bidder, ≥ high + step, not the seller, DLEQ-verified proofs from the pinned keyset, unspent-on-chain, sum = amount, lock = P2PK to the FROST group key only (no extra pubkeys, one signature), `SIG_ALL`, refund key = bidder, locktime ≥ hard end + margin (24 h by default). Lock secrets are parsed strictly (no duplicate, unknown or case-variant keys, no repeated tags) so the validators and the mint always read the same lock.
- Soft close: late bids add 20 s, capped by a hard end.
- Keys: `arena init` runs a FROST (secp256k1, Taproot/BIP-340) key ceremony between the four validators; each keeps only its own share in `vN/config/frost_key.json`. Genesis carries the group key.
- Settlement: `/api/release` asks every validator for a nonce commitment; each one only commits to a refund for an outbid, lost or void bid (authorised by the bidder) or a payout of the winning bid to the seller. Three that agree on the same message sign their share, and the shares combine into one ordinary Schnorr signature the mint accepts. Fewer than three: no signature. If validators vanish, the bidder reclaims alone after locktime. The seller must open the site within the lock margin after the close to collect.
- Polling (v0.3.1, ADR 0004): the page reads `/api/state?view=client`, a slim view without proofs that answers `304` when nothing changed; `/api/bid?id=` returns one bid's proofs when it is released. API JSON and text assets are gzipped.
- Live feel (v0.3.2, ADR 0005): a bid checks the slim view, not the full state; after an action the page polls every 250 ms for 3 s so the result shows as soon as its block commits; the mint's NUT-17 WebSocket (`/mint/v1/ws`) is proxied so Coco gets pushed updates.
- Live chain (v0.4.0, ADR 0003 §1 and §4, [ADR 0007](docs/adr/0007-live-chain-push-void-bids.md), chain format 4):
  - Blocks come only when there is something to commit, plus one a minute as a heartbeat. Each validator sends a `close` transaction when a lot is due, and block time is the proposer's clock (PBTS), so lots close on time.
  - A locked bid that lost a race is recorded as void and refunded at once.
  - `/api/events` pushes "new block" to the page. (v0.4.1: the first message after the stream was idle is the current height, not the one from the last listener.)
  - Each validator archives every transaction to `vN/data/ledger.jsonl` and prunes blocks 100,000 below its newest snapshot.
  - The Network drawer times your last 20 bids.
- Wallet: the browser holds ecash in Coco (`@cashu/coco-core`, IndexedDB per identity); bids are Coco P2PK sends.
- Light page (v0.4.2, [ADR 0008](docs/adr/0008-page-main-thread-budget.md)): the Coco wallets and all proof maths run in a Web Worker; the page redraws ten times a second (at once after a tap or a new block), derives each public key once and reuses its number and time formatters.

## Run

```bash
./scripts.sh build && ./serve.sh   # needs Go, Rust (cargo) and Node 20
```

Open http://127.0.0.1:8080. Other commands:

```bash
LOCK_MARGIN=30 ./scripts.sh reset && DEMO_CONTROLS=1 ./scripts.sh start && ./scripts.sh test
```

`LOCK_MARGIN=30` lets the test exercise the reclaim-after-locktime path; with the 24 h default it is skipped. `DEMO_CONTROLS=1` turns on the validator stop/start route (`-demo-controls`), which the test needs and a real deployment must not have.

`test` runs `tests/e2e.mjs`: 55 acceptance checks (bids, instant refunds, void late bids, idle chain and on-time closes, pushed events, payout, group-key lock, single 64-byte signature, release refused with 2 of 4 validators, forged signature rejected by the mint, validator stop/catch-up, reclaim after locktime, conservation of sats, unsafe image path refused). `go test ./chain/` runs the audit regression tests and fuzz seeds. `node web/test/frost-roundtrip.mjs frost/target/release/arena-frost` checks the key ceremony and signing (10 checks).

## Limits (MVP)

- Fake sats, internally reviewed only ([audit](docs/SECURITY_AUDIT_2026-11-10.md)), one operator runs all four validators on localhost.
- All four FROST shares sit on one host, so that operator could sign alone; real security needs the validators on separate machines run by different people.
- CometBFT p2p instead of FIPS.
- Per-browser generated Nostr keys (no NIP-07 yet); chat is signed but held in gateway memory, not on chain.
- Bids respond on tap (v0.3.4, [ADR 0006](docs/adr/0006-instant-bid-feedback.md)): the page shows your bid as sending at once, then sent, then on chain about a second later.
- App state is in memory, saved to disk every 1,000 blocks and on clean shutdown (v0.3.3, [ADR 0003](docs/adr/0003-block-growth-snapshots-pruning.md) §2); a restart replays only the blocks after the newest snapshot. State sync for new validators and state trimming (ADR 0003 §3, §5) are still proposed.

## Torii node install

Tagging `v*` runs `.github/workflows/release.yml`, which builds `plebeian-auctions-<tag>.tar.gz` with `scripts/package.sh`. The tarball holds the static `bin/arena` and `bin/arena-frost` (Rust, musl), the built front end and a private CPython 3.12 with Nutshell, installed from the hash-pinned `mint/requirements.txt` using prebuilt wheels only. Nothing is built on the VPS.

The Torii Suite installs a pinned release with `installers/install-auctions.sh` (opt-in, `INSTALL_AUCTIONS=1`) at `https://auctions.<domain>/`. It has no launcher card: it is for the team, not the public. The gateway listens on loopback only and nginx fronts it. The four validators, their FROST endpoints and the mint all bind `127.0.0.1`.

Build a tarball locally:

```bash
scripts/package.sh v0.4.2 dist-release
```

Design decisions: [ADR 0001](docs/adr/0001-frost-escrow-coco-wallet.md), [ADR 0002](docs/adr/0002-strict-locks-nutshell-021.md), [ADR 0003 (proposed)](docs/adr/0003-block-growth-snapshots-pruning.md). Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
