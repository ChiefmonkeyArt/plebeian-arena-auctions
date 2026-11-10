# ADR 0002: Strict lock parsing, Nutshell 0.21 and a 24-hour lock margin

Status: accepted (v0.3.0)

## Context

The internal audit (docs/SECURITY_AUDIT_2026-11-10.md) found that the validators (Go `encoding/json`: case-insensitive keys, last duplicate wins) and the mint (Nutshell: exact keys, first tag wins) could read one bid lock two ways (A1). A bidder could win while the mint let them take the sats back. Nutshell 0.20.2's SIG_ALL message also left output amounts unsigned (A6), its pinned Python dependencies carried 34 advisories (A7), and the 30-second lock margin let a winning bidder reclaim before most sellers would collect (A3).

## Decision

- Validators accept only locks they can read unambiguously: exact keys `nonce`, `data`, `tags`, each once; no escapes; valid UTF-8; no repeated tags; one-value `locktime`/`sigflag`/`n_sigs`; lowercase hex keys. Anything else is refused, even when Nutshell would accept it.
- The mint moves to Nutshell 0.21.0. Validators, client and tests use its SIG_ALL message: `secret||C` per input, then `amount||B_` per output.
- `arena init -lock-margin` defaults to 86400 s. Tests pass a short margin.
- Chains carry a `FORMAT` marker (now `3`); `arena init -if-needed` wipes and re-initialises any chain without it, because v0.2.0 state was accepted under the looser rules and its keyset IDs predate Nutshell 0.21.
- The validator stop/start route is off unless the gateway runs with `-demo-controls`.

## Consequences

- Hand-built secrets that are valid NUT-10 but unusual are rejected; Coco and cashu-ts produce the canonical form, so normal bids are unaffected.
- Upgrading from v0.2.0 resets the fake-sats chain and mint keyset; old fake sats are void.
- With a 24-hour margin a rejected-bid reclaim waits a day. A payout that does not need the seller's browser is still open (threat model F2).
- Nutshell 0.21 imports its Breez Spark backend eagerly; we ship a stub `breez_sdk_spark` module rather than the Rust SDK, since the FakeWallet backend never uses it.
