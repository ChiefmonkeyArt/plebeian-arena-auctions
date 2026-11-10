# Threat model: Plebeian Auctions arena (v0.2.0, status updated for v0.3.4)

Status: draft, 2026-11-10. Covers `ChiefmonkeyArt/plebeian-arena-auctions` v0.2.0 as installed by Torii Suite v0.9.50-alpha at `auctions.<domain>`. Fake sats only. This document defines what must hold before real sats are used, and what an auditor should test.

## What we protect

| Asset | Why it matters |
|---|---|
| Escrowed bids (Cashu proofs locked to the FROST group key) | Theft or loss of bidders' and sellers' sats |
| The four FROST key shares (`chain/vN/config/frost_key.json`) | Any 3 can move every escrow |
| Wallet keys and Nostr keys in each browser | Control of a user's refunds, payouts and identity |
| Mint signing key (`/etc/torii/auctions/mint.env`) | Can create or refuse ecash |
| Agreed auction state (CometBFT chain) | Decides who won, who is refunded, who is paid |
| Availability of validators and gateway | Refunds and payouts need 3 of 4 validators online |

## Security goals

1. Only the bidder can direct a refund of an outbid or lost bid; only the seller's wallet can direct the winning bid's payout.
2. No party below the threshold (fewer than 3 validators) can move escrowed sats.
3. A winning bid is always payable to the seller; a bidder can never lose sats to anyone except the seller of an auction they won.
4. Every validator applies the same bid rules; a bid that breaks them never enters the state.
5. If the validators fail, bidders recover their sats without anyone's help (time-locked refund path).

## Trust boundaries

```
internet ──HTTPS──► nginx (rate limit, CSP, GET/HEAD + POST /api only)
                      │ loopback
                      ▼
                    gateway :8795/8796 ── /api/state /api/bid /api/network /api/tx /api/release /api/chat /api/admin/* /mint/*
                      │ loopback                 │
                      ▼                          ▼
              V1..V4 (CometBFT + ABCI + /frost/*)   Nutshell mint :13338 (FakeWallet)
                      │ stdin/stdout JSON
                      ▼
                    bin/arena-frost (Rust, frost-secp256k1-tr 3.0.0)
```

Today all boxes below nginx run on one host under one operator. The intended trust model (each validator run by a different person on a different machine) is not deployed yet.

## Actors

| Actor | Wants to | Prevented by | Gap today |
|---|---|---|---|
| Anonymous visitor | Disrupt auctions, steal sats | Locks to group key; auth signatures checked by each validator; nginx rate limit | **Can stop validators** via `/api/admin/validator/N/stop` (F1). Can flood chat. |
| Bidder | Bid without paying; get refunded while winning; reuse proofs | Bid needs DLEQ-valid proofs from the pinned keyset, summing to the amount, locked to the group key with `SIG_ALL`; proofs recorded in `UsedY`; refunds only for `outbid`/`lost` | **Winning bidder can reclaim after locktime** if the seller has not been paid (F2). |
| Seller | Inflate price; keep sats without delivering | Seller's Nostr key cannot bid on its own lot | Shill bids from a second key (F6). No delivery or dispute step: payout releases at close (F5). |
| One validator (malicious or compromised) | Sign alone; censor; corrupt state | 3-of-4 FROST; BFT consensus needs 3 of 4 votes; each validator checks policy and the exact message before signing | Can delay bids during its proposer turns. |
| Gateway / release coordinator | Redirect a release | Each validator checks the bidder's or seller's authorisation over the exact outputs, and signs only the message it committed to | Can refuse to coordinate (bidder falls back to locktime). |
| Host operator (one machine, all shares) | Anything | Nothing on a single host | **Holds all 4 shares, mint key and gateway** (F3). |
| Mint operator | Inflate, refuse swaps, track users | Validators verify DLEQ against a keyset pinned in genesis | Custodial by design (F4); the mint sees group key and refund keys. |
| Supply-chain attacker | Ship a malicious release | Exact-pinned npm deps, `Cargo.lock`, `go.sum`, hash-pinned Python wheels; Suite pins tag + SHA-256 in a reviewed PR | Releases are built by GitHub Actions and not signed or reproducible (F9). |
| Browser attacker (XSS, malicious extension, shared device) | Steal keys | Strict CSP (only own-origin and hashed scripts), no third-party requests | Keys live in localStorage/IndexedDB; no NIP-07; no tested recovery (F7). |

## Findings

Severity is for real sats; with fake sats nothing is at financial risk.

### F1 Critical: unauthenticated validator stop/start on the public gateway

v0.3.0: off unless the gateway runs with `-demo-controls`; the team demo still enables it. Must be off before real sats.

`POST /api/admin/validator/{1-4}/{stop|start}` (`chain/main.go`) has no authentication and nginx forwards all `/api/` POSTs. Anyone with the address can stop two validators and halt the chain, so no bids, refunds or payouts until restarted. Confirmed reachable on the live site (GET answers `405 POST only` from the gateway); not exercised.

Fix: disable the route unless the gateway is started with an explicit test flag, and deny `/api/admin/` in the Suite vhost. Tests that stop validators use the flag on loopback only.

### F2 High: winning bid can be reclaimed by the bidder after locktime

v0.3.0: lock margin defaults to 24 h (audit A3). Still open: payout that does not need the seller online.

Locktime only has to be at least hard end + 30 s (`LockMarginSec`). Payout is triggered by the seller's own browser (`settleLoop`). If the seller is offline past locktime, the winner can take the escrow back with the refund key, breaking goal 3.

Fix: much longer margin (days, not seconds), and make payout independent of the seller being online (e.g. the validators release to outputs the seller pre-authorised when listing).

### F3 High: one host holds every key

`arena init` runs the key ceremony in one process and writes all four shares to one disk, next to the mint key and gateway. The operator, or anyone who compromises the host, can sign any release and mint ecash. The FROST threshold gives no protection here.

Fix: one validator per machine and per person; a real distributed key ceremony over authenticated channels; the mint run separately from the validators.

### F4 High (for real sats): custodial mint

Cashu is custodial: the mint can inflate, refuse swaps or disappear. The FakeWallet mint also gives unlimited free sats to anyone through `/mint/`. The mint learns every lock's group key and refund key, linking a bidder's bids.

Fix: a Lightning-backed mint operated by a party the team trusts, independently of the validators; plan for keyset rotation (the keyset is pinned in genesis).

### F5 Medium: escrow protects payment, not delivery

The winning bid is released to the seller at close. A seller who never ships keeps the sats.

Fix: a delivery/confirmation window or a dispute path (e.g. release after buyer confirmation or a timeout, with validator arbitration rules).

### F6 Medium: shill bidding and bid censorship

A seller can bid from a second Nostr key to raise the price. A malicious proposer can delay a late bid during its turn; soft close (20 s, capped at 60 s) limits but does not remove this.

Fix: reputation or identity linking (out of scope for the escrow), and longer soft-close windows for high-value lots.

### F7 Medium: browser key custody

Nostr and wallet keys are generated and stored in the browser. Losing browser data loses unsettled sats; any script running on the origin could read them.

Fix: NIP-07 signer for identity; tested seed backup and restore for the Coco wallet; keep the strict CSP.

### F8 Low: resource exhaustion

v0.3.0: HTTP timeouts on every server, at most 4 open signing sessions per escrow.

- Each validator holds at most 256 open signing sessions for one minute. Only authorised requests create them, but one bidder repeating valid release requests can fill them and delay others' releases.
- Chat accepts any validly signed event (300-message ring, 280 chars), so it can be flooded.
- Mitigated in part by the nginx rate limit (zone `torii_auctions`).

Fix: per-bid session limits, per-key chat limits.

### F9 Low: release integrity

Releases are built in CI and pinned by checksum in a Suite PR, which is the only review point. A compromised GitHub account could publish a different tarball for a new tag.

Fix: reproducible builds checked by a second builder, and signed release checksums.

### F10 Info: privacy

All auctions, bids, amounts, bidder wallet keys and Nostr keys are public through `/api/state`. v0.3.1 adds `/api/state?view=client` and `/api/bid?id=` (ADR 0004). They expose nothing the full state did not already, and the `bidders` parameter only tells the gateway which public keys a browser holds, which it already learns when they sign events. Gzip is safe here: these responses carry no secrets, so compression side channels (BREACH) do not apply. Intended for an auction, but bidders are linkable across lots.

v0.3.2 (ADR 0005) lets one path, `/mint/v1/ws`, upgrade to a WebSocket that is passed straight to the mint. Every other upgrade attempt gets a 400. A held socket costs a goroutine and two file descriptors and is cut after 10 minutes. Nginx rate-limits new upgrades like any other request, but this is not a cap on open sockets per client: on real sats, add a per-IP connection limit (`limit_conn`) in front.

v0.3.3 (ADR 0003 §2) writes state snapshots to `vN/data/app-state/<height>.json` (0600, directory 0700). Anyone who can write there can already rewrite the block store, so this adds no new attacker, but a snapshot must never become a quiet way to change state. On start a validator loads only the newest file and refuses to run unless it is a regular file under 256 MiB, hashes to its stored app hash, re-encodes to the same bytes, and matches the chain's own record (the next block header's app hash, or the saved CometBFT state at the tip). A refusal never falls back to an older snapshot or to genesis on its own; the operator deletes the file. Snapshots contain only public state (the same data as `/api/state`), no keys.

v0.3.4 (ADR 0006) changes only the page. A one-tap bid (Next, Jump, Big move, the sticky Bid button, swipe) is priced against the view read just before the lock, so it can be up to two increments above the amount the button showed; anything higher is refused before any sats are locked, and the toast states the amount actually bid. A tap made while a bid is in flight is held (latest one wins) and dropped if you are leading when the first lands, so taps cannot stack bids. The demo bots in your own browser wait 5 s after your tap, which removes the most common cause of a stale-amount rejection (and its sats locked until locktime). Nothing changes on the chain or the gateway.

## Already in place

- Bids locked only to the FROST group key, `SIG_ALL`, refund key = bidder; validators reject any other lock (`checkLock`).
- DLEQ verification against the genesis-pinned keyset; duplicate proofs and proofs used in an earlier bid rejected.
- Release policy checked independently by each validator from its own state; authorisation is a BIP-340 signature by the bidder's or seller's wallet key over the exact SIG_ALL message (`releasePolicy`).
- FROST nonces are single-use, deleted before signing, expire after a minute; a validator signs only the message it committed to (`handleShare`).
- The coordinator verifies the aggregated signature before returning it; the mint rejects forged signatures (tested).
- Everything except nginx binds loopback; services run as sandboxed DynamicUser units with `IPAddressAllow=localhost`; key files are 0600.
- Strict CSP, noindex, HSTS, no framing; no third-party requests.
- 34 end-to-end checks (including 2-of-4 refusal and forged-signature rejection) and a FROST roundtrip test.

## Before real sats

- [ ] F1 fixed and deployed.
- [ ] F2: long locktime margin and seller-independent payout.
- [ ] F3: validators on separate machines and operators; distributed key ceremony.
- [ ] F4: Lightning-backed mint run independently.
- [ ] F5: delivery or dispute rule decided.
- [ ] F7: NIP-07 and wallet backup/restore.
- [ ] Fuzzing of bid and release checks; tests for a misbehaving validator.
- [ ] Independent audit of the FROST flow, escrow rules and validator code, against this document.
- [ ] Small per-auction caps and a bug bounty for the first real-sats trial.
