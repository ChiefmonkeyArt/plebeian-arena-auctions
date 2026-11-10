# ADR 0001: FROST group-key escrow and Coco wallet

Status: accepted (v0.2.0)

## Context

v0.1.0 locked each bid with native Cashu NUT-11 multisig: P2PK to V1 plus V2–V4 as extra pubkeys, `n_sigs=3`. The token exposed all four validator keys, and every release carried three signatures. The browser wallet was plain cashu-ts with proofs in localStorage. The proposed stack named FROST and Coco.

## Decision

- The four validators run a FROST 3-of-4 key ceremony (`frost-secp256k1-tr` 3.0.0, Taproot/BIP-340) at `arena init`. Each keeps only its own share. Genesis records the group key and public shares.
- Bids lock to the group key only, `SIG_ALL`, with the bidder as refund key after locktime. The validator ABCI app rejects any other lock.
- Release is two rounds: `/frost/commit` (each validator checks the release policy, then returns a single-use nonce commitment) and `/frost/sign` (each signs only the exact message it agreed to). The gateway aggregates and verifies the signature before returning it.
- FROST runs in a small Rust helper (`bin/arena-frost`, JSON over stdin/stdout) called by the Go node, because the reference FROST implementation is Rust.
- The browser wallet is Coco (`@cashu/coco-core` 2.0.0, IndexedDB), one manager per identity. Minting imports the paid quote into Coco to work around Nutshell 0.20 not updating the quote's timestamp.
- All code is written fresh for this repo; nothing from PlebeianApp/market is copied or changed.

## Consequences

- To the mint, an escrow looks like an ordinary single-key P2PK lock; validator identities are not exposed in tokens.
- On one host the operator can read all four shares. Real trust separation requires validators on separate machines.
- Existing v0.1.0 chains are not compatible and must be re-initialised (fake sats only).
