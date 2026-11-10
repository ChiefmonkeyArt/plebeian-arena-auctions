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
   └─ Nutshell mint :3338 (FakeWallet, NUT-11 P2PK, NUT-12 DLEQ)
```

- Consensus: blocks need ≥3 of 4 validator signatures; the chain keeps running with one validator down.
- Bid validity (deterministic, on every validator): signed by bidder, ≥ high + step, not the seller, DLEQ-verified proofs from the pinned keyset, unspent-on-chain, sum = amount, lock = P2PK to the FROST group key only (no extra pubkeys, one signature), `SIG_ALL`, refund key = bidder, locktime ≥ hard end + margin.
- Soft close: late bids add 20 s, capped by a hard end.
- Keys: `arena init` runs a FROST (secp256k1, Taproot/BIP-340) key ceremony between the four validators; each keeps only its own share in `vN/config/frost_key.json`. Genesis carries the group key.
- Settlement: `/api/release` asks every validator for a nonce commitment; each one only commits to a refund for an outbid/lost bid (authorised by the bidder) or a payout of the winning bid to the seller. Three that agree on the same message sign their share, and the shares combine into one ordinary Schnorr signature the mint accepts. Fewer than three: no signature. If validators vanish, the bidder reclaims alone after locktime.
- Wallet: the browser holds ecash in Coco (`@cashu/coco-core`, IndexedDB per identity); bids are Coco P2PK sends.

## Run

```bash
./scripts.sh build && ./serve.sh   # needs Go, Rust (cargo) and Node 20
```

Open http://127.0.0.1:8080. Other commands:

```bash
./scripts.sh reset && ./scripts.sh start && ./scripts.sh test
```

`test` runs `tests/e2e.mjs`: 34 acceptance checks (bids, instant refunds, payout, group-key lock, single 64-byte signature, release refused with 2 of 4 validators, forged signature rejected by the mint, validator stop/catch-up, reclaim after locktime, conservation of sats). `node web/test/frost-roundtrip.mjs frost/target/release/arena-frost` checks the key ceremony and signing (10 checks).

## Limits (MVP)

- Fake sats, unaudited, one operator runs all four validators on localhost.
- All four FROST shares sit on one host, so that operator could sign alone; real security needs the validators on separate machines run by different people.
- CometBFT p2p instead of FIPS.
- Per-browser generated Nostr keys (no NIP-07 yet); chat is signed but held in gateway memory, not on chain.
- App state is in memory and replays from genesis on restart.

## Torii node install

Tagging `v*` runs `.github/workflows/release.yml`, which builds `plebeian-auctions-<tag>.tar.gz` with `scripts/package.sh`. The tarball holds the static `bin/arena` and `bin/arena-frost` (Rust, musl), the built front end and a private CPython 3.12 with Nutshell, installed from the hash-pinned `mint/requirements.txt` using prebuilt wheels only. Nothing is built on the VPS.

The Torii Suite installs a pinned release with `installers/install-auctions.sh` (opt-in, `INSTALL_AUCTIONS=1`) at `https://auctions.<domain>/`. It has no launcher card: it is for the team, not the public. The gateway listens on loopback only and nginx fronts it. The four validators, their FROST endpoints and the mint all bind `127.0.0.1`.

Build a tarball locally:

```bash
scripts/package.sh v0.2.0 dist-release
```

Design decision: [ADR 0001](docs/adr/0001-frost-escrow-coco-wallet.md).
