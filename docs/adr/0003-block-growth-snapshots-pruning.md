---
status: proposed
---

# ADR 0003: Block growth, state snapshots and pruning

The chain makes a block every second, even when nothing happens, keeps every block forever, and rebuilds its state by replaying from genesis on every restart. That is fine for a demo and does not scale. We propose:

- **Make blocks only when needed:** a slow heartbeat, plus a "close" transaction so auctions still end on time.
- **Save the state to disk:** a validator restarts from its latest snapshot instead of replaying the whole chain.
- **Delete old blocks:** once they are covered by a snapshot and an archived ledger.
- **Offer snapshots to new validators:** they can join quickly once the validators run on separate servers.

## Context

As of v0.3.0 (`chain/node.go`, `chain/app.go`):

- `CreateEmptyBlocks = true` with `TimeoutCommit = 1s`. That makes about 86,400 blocks a day, and each of the four validators stores every one. The live chain was at height 1,664 about 28 minutes after the v0.3.0 deploy.
- Block time is the auction clock. `FinalizeBlock` calls `closeDue(blockTime)`, so an auction only changes to `closed` in the first block whose time is at or after `EndAt`. Empty blocks are what make closes happen on time.
- The state lives only in memory. `Info` reports `LastBlockHeight: 0`, so CometBFT replays every block from genesis on start. Restart time and memory grow with history.
- Nothing is pruned. `Commit` returns no `RetainHeight`, the tx indexer is the default `kv`, and ABCI responses are kept.
- The state grows too, not just the blocks:
  - `Auctions`, `Bids` and `UsedY` are never trimmed (`Rejections` is capped at 50).
  - Each bid stores its proofs, up to 64 per bid.
- Each Suite install runs its own separate chain. This ADR does not change that.

## Decision

### 1. Blocks on demand, with a heartbeat

- `CreateEmptyBlocks = true` and `CreateEmptyBlocksInterval = 60s`. With no transactions, the chain makes one block a minute instead of 60.
- **The close transaction:** a new, unsigned, fixed-format "close" transaction (not a Nostr event) says "close what is due".
  - CheckTx accepts it only if some auction is still `open` and its `EndAt` has already passed on the validator's last block time. Otherwise it is refused, so it cannot be used for spam.
  - Accepted ones go into the mempool and trigger a block. FinalizeBlock then runs `closeDue` as it does today.
  - The gateway sends one when an open auction's `EndAt` passes. Any validator may also send one from its own timer, so a dead gateway cannot stall closes.
- **Correctness does not depend on this.** A bid in a block whose time is at or after `EndAt` is already rejected, so a late close only delays the status change; it cannot change the winner. Refunds and payouts need `closed`, so close latency is bounded by the close transaction, with the heartbeat as a fallback.
- **Expected effect:** about 1,440 blocks a day at idle, plus one block per burst of activity, instead of 86,400.

### 2. State snapshots on disk

- Every `SnapshotEvery` blocks (default 1,000) and on clean shutdown, a validator writes its committed state to `vN/data/app-state/<height>.json`. Each file holds the canonical JSON that `hash()` covers, plus the height and app hash. Writes are atomic: a temp file, `fsync`, then rename.
- `Info` returns the newest snapshot's height and app hash. CometBFT then replays only the blocks after it.
- On load, the validator recomputes the app hash and compares it with the stored hash and with the block header at that height. If they differ, it refuses to start (it does not quietly replay).
- It keeps the last 2 snapshots.

### 3. State sync for new validators

- The validators implement the ABCI snapshot calls (`ListSnapshots`, `LoadSnapshotChunk`, `OfferSnapshot`, `ApplySnapshotChunk`) over the snapshots from step 2, in 1 MiB chunks, using a format number tied to `chainFormat`.
- A validator joining on a new server (CometBFT `statesync.enable`, with trusted RPC servers set to the other validators' RPCs, and a trust height and hash from an operator) gets a snapshot that CometBFT checks against a verified block header (light client). It does not take any one peer's word for it.
- The genesis file is still shared out of band, as it is today.

### 4. Pruning, after archiving

- `Commit` returns `RetainHeight = latestSnapshotHeight − RetainBlocks` (default `RetainBlocks` = 100,000, about 2 to 4 weeks at the new rate). CometBFT deletes blocks below that.
- Before blocks are pruned, the gateway appends every transaction in them to a ledger archive: `ledger/<chain-id>.jsonl`, one line per tx with height, block time, kind, event id and result. This is the readable "printout" and the dispute trail. It is far smaller than blocks with commits and signatures.
- Both are configurable: `-retain-blocks` (0 means keep everything, for anyone who wants a full archive node) and `-snapshot-every`.
- `TxIndex.Indexer = "null"`, because nothing queries it; the gateway reads state and the ledger archive. `Storage.DiscardABCIResponses = true`.

### 5. Trimming the state

- A closed auction, and all its bids, move from live state into the ledger archive once every bid on it is settled (refunded or paid out) or its locktime has passed. Settled means a validator has co-signed the release, which is recorded in a new deterministic `Settled` mark set by a "settle" transaction from the coordinator.
- `UsedY` (one 32-byte entry per proof ever escrowed) is never pruned. Validators accept bids by DLEQ without asking the mint whether proofs are spent. Forgetting a used proof would let a spent proof be offered again as a fake bid.

## Considered options

- **Keep empty blocks every second.** This is simple and gives the most exact closes, but it means about 86,400 blocks a day per validator forever. Rejected.
- **Turn empty blocks off completely.** Closes would wait for the next bid or listing. Refunds and payouts would stall on quiet lots. Rejected.
- **Close on wall-clock time inside each validator, not block time.** That isn't deterministic: validators would disagree about state and the app hash would split. Rejected.
- **Make empty blocks only while an auction is open.** CometBFT has no per-block switch. A close transaction gives the same result within the existing rules.
- **Never prune, only snapshot.** Restarts would be fast but disk would still grow without limit. Kept as an option (`-retain-blocks 0`), not the default.
- **Prune with no archive.** This would lose the bid history that disputes and audits need. Rejected.
- **Keep the state in a database such as IAVL or Pebble.** That gives proofs per key and incremental writes, but it is a large dependency and a rewrite of `State`. Not needed at this size; reconsider if the state grows beyond tens of MB.

## Consequences

- **Format change.** `chainFormat` goes to `4`. The Suite's `arena init -if-needed` re-creates older chains (fake sats, as before).
- **New moving parts:** the close transaction, the settle transaction, snapshot files and the ledger archive. Each needs tests, at least:
  - a close happens within a few seconds of `EndAt` while the chain is idle;
  - a restart from a snapshot ends at the same app hash as a replay from genesis;
  - a corrupted snapshot is refused;
  - a validator started with state sync agrees with the others;
  - after pruning, the ledger archive still has every bid and payout.
- **The heartbeat sets the worst-case close delay** if the close transaction path fails: 60 s. The UI already counts down on the client.
- **The ledger archive is now a record users care about.** It goes in the Suite's backups next to the mint database.
- **Disk and memory use become roughly flat** for a node with steady traffic. Suite `MemoryMax=768M` should stay comfortable. Measure real block sizes on the VPS after the change instead of estimating.
- **Separate servers come first.** This ADR does not block moving the validators to separate servers on Wednesday. State sync (step 3) is what makes adding the next validator fast.

## Related

- ADR 0004 (v0.3.1) already shrinks what browsers download each poll, using a slim view and 304 replies. This ADR still governs what validators store.
