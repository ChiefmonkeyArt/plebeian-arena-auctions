# Internal security audit: arena v0.2.0 (2026-11-10)

Scope: `ChiefmonkeyArt/plebeian-arena-auctions` at v0.2.0 (fee2ce3) plus the Suite install (v0.9.50-alpha). This is an internal review, not an independent audit. Read with [THREAT_MODEL.md](THREAT_MODEL.md). Fake sats only; nothing here was exercised against the live site.

Method: dependency scans (govulncheck, cargo audit, npm audit, pip-audit), static analysis (gosec), three Go fuzz targets (about 1.2 million inputs), manual review of the escrow, release, FROST and front-end code, and parser-differential tests against Nutshell's own parser.

## Summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| A1 | **Critical** | Validators and mint read bid locks differently: escrow bypass | Open |
| A2 | High | CometBFT v1.0.0 and Go deps: 11 reachable known vulnerabilities, incl. p2p stall | Open |
| A3 | High | Winning bid reclaimable after locktime if the seller is unpaid (threat model F2) | Open |
| A4 | Medium | Nostr hex case not canonical: self-bid check bypass, listing replay | Open |
| A5 | Medium | Listing image URL inserted unescaped into HTML | Open |
| A6 | Medium | SIG_ALL message (Nutshell 0.20.2) omits output amounts | Open |
| A7 | Medium | Mint Python deps: 34 known advisories in 6 packages | Open |
| A8 | Low | crypto-bigint timing advisory under the FROST library | Upstream |
| A9 | Low | HTTP servers without header/read timeouts | Open |
| A10 | Low | Unchecked integer sums; validator logs 0644 | Open |
| A11 | Info | Demo stop/start route in the build | By design (demo only) |

## A1 Critical: lock-parser differential (escrow bypass)

`parseP2PK` (`chain/cashu.go`) uses Go's `encoding/json`, which matches object keys case-insensitively and lets a later duplicate tag override an earlier one. Nutshell matches keys exactly and uses the **first** matching tag (`Tags.get_tag`, unchanged in 0.21.0). A bidder who builds their own secret can make the validators see a valid escrow while the mint enforces something else.

Tested with Nutshell 0.20.2's `P2PKSecret.from_secret` and the validators' `checkLock`, group key `02 11…`, attacker key `03 22…`:

| Crafted secret body | Validators | Mint |
|---|---|---|
| `"data": <attacker>, "Data": <group>` | accept: locked to group key | locked to **attacker's key** |
| `["locktime","1"], ["locktime","9999999999"]` | accept: locktime far future | locktime **1** (refund path open now) |
| `["sigflag","SIG_INPUTS"], ["sigflag","SIG_ALL"]` | accept: SIG_ALL | SIG_INPUTS |
| `"tags": [locktime 1…], "Tags": [valid tags]` | accept: valid tags | locktime 1, SIG_INPUTS |

Example (rows 2): `["P2PK",{"nonce":"aa","data":"02…11","tags":[["locktime","1"],["locktime","9999999999"],["refund","02…33"],["sigflag","SIG_ALL"]]}]`

Impact: a bidder places a winning bid, then immediately swaps the same proofs back to themselves at the mint. They can win any auction without paying, or block every auction with unbacked high bids. The seller's payout then fails as already spent. Found at the parser level on both sides; a full end-to-end exploit was not run.

Fix: a strict secret parser in the validators. Reject duplicate keys (case-insensitively) and unknown keys in the secret body; require exactly one `locktime`, one `refund`, one `sigflag` tag and no `pubkeys`/`n_sigs` tags; reject any repeated tag. Better still, require the secret to be byte-identical to a canonical re-serialisation. Add these four secrets as regression tests.

## A2 High: known vulnerabilities in Go dependencies

govulncheck: 11 vulnerabilities reachable from our code in 4 modules.
- `cometbft` v1.0.0: GO-2025-3442 (malicious peer makes a node stuck in blocksync) and GO-2025-3443 (malicious peer stalls the network). Fixed in v1.0.1. These matter as soon as validators talk over the internet.
- `golang.org/x/net` v0.32.0: four HTTP/2 server issues (GO-2026-6603/6611/6612/6617), fixed in v0.60.0.
- `google.golang.org/grpc` v1.68.1: four issues incl. GO-2026-4762 authorisation bypass, fixed in v1.83.1 or later.
- `klauspost/compress` v1.17.11: GO-2026-6865 panic, fixed in v1.20.2.

Fix: upgrade to the latest CometBFT v1.0.x and bump the others; rerun govulncheck in CI.

## A3 High: winning bid reclaimable after locktime

See threat model F2. The bidder may set locktime to hard end + 30 s; payout is only triggered from the seller's browser. Fix: margin in days, and a payout that does not need the seller online.

## A4 Medium: Nostr hex case is not canonical

`Event.Verify` (`chain/nostr.go`) accepts upper-case hex in `pubkey` and `id`. A Go test confirmed:
- the same key signs valid events with a different `pubkey` string, so `ev.Pubkey == au.Seller` (seller cannot bid) and the "already highest bidder" check can be bypassed;
- anyone can replay someone's listing with an upper-cased `id`; it verifies and is stored as a new auction under the original seller's name.

Fix: require lowercase hex for `id`, `pubkey` and `sig` (as NIP-01 does), or normalise before any comparison or map key.

## A5 Medium: listing image URL inserted unescaped

`web/src/main.js` line 371 builds `<img src="${src}">` from the seller-controlled `image` field (up to 500 characters) without `esc()`. A listing can inject attributes and markup into every viewer's page. The Suite's CSP (`script-src 'self'` plus a hash, no `unsafe-inline`) blocks script execution, but style and markup injection remain (UI spoofing), and `serve.sh` has no CSP, so locally it is full XSS that can read keys.

Fix: escape the value, accept only `https:` or same-origin paths in the client, and validate the field on chain.

## A6 Medium: SIG_ALL message omits amounts

Nutshell 0.20.2 signs `secrets || B_` only. Anyone relaying the swap (the gateway's `/mint/` proxy, nginx) can change output amounts or keyset ids without breaking the FROST signature. This is not theft: the relay cannot unblind, but the bidder can end up with proofs they cannot use. Nutshell 0.21.0 signs `secret||C` per input and `amount||B_` per output (`cashu/core/nuts/nut11.py`).

Fix: move to Nutshell 0.21.0 and update `releasePolicy`, the client and the e2e tests to the new message.

## A7 Medium: mint Python dependencies

pip-audit on `mint/requirements.txt`: 34 advisories in starlette 0.46.2 (most), cryptography 43.0.3, h11 0.14.0, ecdsa 0.19.2, setuptools 75.9.1 and wheel 0.41.3. The mint listens on loopback, but `/mint/` is public through the gateway, so starlette and h11 issues are reachable. Fix: re-pin with Nutshell 0.21.0 and the fixed versions.

## A8 Low: crypto-bigint timing (upstream)

cargo audit: RUSTSEC-2026-0387 (timing variability) in crypto-bigint 0.5.5, via k256 0.13.4 in frost-secp256k1-tr 3.0.0; atomic-polyfill unmaintained (warning). The helper runs as a local process, so remote timing is hard, but it handles key shares. Track a frost-secp256k1-tr release on a fixed k256.

## A9 Low: HTTP timeouts

gosec G112: the gateway and validator `http.Server`s set no `ReadHeaderTimeout`/`ReadTimeout`. nginx shields the gateway today; validators' endpoints will need them once reachable from other machines.

## A10 Low: small hygiene

- `sum += pr.Amount` (bids) and output sums use unchecked int64 addition. Not exploitable for gain (overflow means more value locked than claimed), but use checked sums.
- Validator logs are created 0644 (`chain/main.go`); make them 0600.

## A11 Info: demo stop/start route

`/api/admin/validator/N/stop|start` is for the demo only and will not be in the live build. Until then it is reachable on `auctions.chiefmonkey.art`. Recommend a build flag so it cannot ship by accident.

## Checked and fine

- Fuzzing: `parseP2PK`/`proofY`, `decodeTx`, `applyCreate`/`applyBid`/`verifyDLEQ` with arbitrary content: about 1.2 million inputs, no panics (`chain/fuzz_test.go`).
- FROST flow: nonces single-use, deleted before signing, 1-minute expiry; a validator signs only the message it committed to; the Rust library checks the signer's own commitment; the coordinator verifies the aggregate before returning it.
- Release authorisation: each validator checks status from its own state and a BIP-340 signature by the bidder's or seller's wallet key over the exact outputs; outputs restricted to the pinned keyset and must sum to the escrow.
- DLEQ against the genesis keyset, duplicate and reused proofs rejected, `MaxProofs` 64.
- gosec G703 (static path) and G115 (rune to byte) are false positives: `filepath.Clean` on a rooted path, and the cast only runs for runes below 0x20.
- npm audit: 0 vulnerabilities in the shipped front end.
- Other HTML templates escape user text with `esc()`; IDs are verified hex.
- Suite: services bind loopback, DynamicUser with `IPAddressAllow=localhost`, strict CSP, `img-src 'self' data: blob:` (no external tracking images).

## Before validators move to separate servers

- [ ] A1 and A2 fixed first (both become remotely exploitable by other operators or peers).
- [ ] CometBFT: `AddrBookStrict=true`, `AllowDuplicateIP=false`, keep PEX off, persistent peers by node ID, firewall p2p to the other validators' addresses only; RPC stays on loopback.
- [ ] `/frost/commit` and `/frost/sign` reachable only by the coordinator over an authenticated, encrypted channel (mutual TLS or WireGuard), with timeouts (A9) and per-bid session limits.
- [ ] Real distributed key ceremony: each operator generates their share on their own machine; today `frostDKG` runs all four parties in one process.
- [ ] Gateway reads state from at least two validators and compares app hashes, instead of trusting the first that answers.
- [ ] Time sync (NTP) on every validator; block time drives auction ends and locktimes.

## Not covered

No review of the FROST, Coco or cashu-ts libraries themselves; no end-to-end run of the A1 exploit; no load or long-running network-partition tests; browser key storage only reviewed at the surface. These belong in the independent audit.
