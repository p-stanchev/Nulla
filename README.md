# Nulla

Nulla is a privacy-first Proof-of-Work blockchain written in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

**Status:** consensus is locked (MTP, difficulty clamp, PoW vectors, genesis), persistence is live (sled-backed ChainDB), and header-first P2P v0 exists with heaviest-work fork choice. Wallets and rich CLI are intentionally deferred.

---

## What Works Today

- **Consensus:** BLAKE3-based PoW (v0), compact difficulty, median-time-past(11) with ±2h drift guard, deterministic rewards with tail emission, hardcoded genesis, and golden PoW serialization vectors across multiple heights.
- **ChainStore / ChainDB:** sled-backed storage for headers, blocks, index entries `{hash,height,prev,bits,time,cumulative_work}`, and best tip. Restart-safe with recovery coverage.
- **Fork Choice:** heaviest cumulative work with deterministic tie-breaker; difficulty-drop clamp enforced on every acceptance path; single validation entrypoint (no bypass routes).
- **P2P v0 (header-first):** version/verack, ping/pong, getheaders/headers, locators, fork handling, and restart safety. Dev-only easy PoW lives behind the `dev-pow` feature for tests and vector generation.
- **Node:** minimal devnet loop and ChainStore integration. Wiring `P2pEngine` as the sole ingress and adding block downloads for the best chain are the next milestones.

---

## Project Layout

- `crates/nulla-core` — protocol types, hashing, serialization.
- `crates/nulla-consensus` — PoW, difficulty, header/block validation.
- `crates/nulla-state` — commitment tree, nullifier set, state transitions.
- `crates/nulla-node` — node runtime, ChainStore integration, devnet loop.
- `crates/nulla-p2p` — header-first networking engine (messages, locators, fork handling).
- `crates/nulla-wallet`, `crates/nulla-zk` — stubs for future wallet and zk work.

Each crate owns a single responsibility; there are no circular dependencies.

---

## Running and Testing

Prereqs: Rust stable (1.75+). Linux/macOS/WSL recommended.

- Run the node (devnet loop + sled ChainDB in the working directory):
  ```bash
  cargo run -p nulla-node
  ```
- Full test suite:
  ```bash
  cargo test --workspace
  ```
- P2P and vector tests with the dev-only easy PoW switch:
  ```bash
  cargo test --features dev-pow --package nulla-p2p
  cargo test --features dev-pow --package nulla-node
  ```
`dev-pow` is strictly for testing/vector generation and is not consensus.

---

## Near-Term Plan (strict order)

1) Wire `P2pEngine` into the node so all inbound headers flow through the single validation entrypoint and ChainDB; avoid ad-hoc networking paths.
2) Add block download for the best chain only (`getblock`/`block`), with strict header↔block consistency checks; persist bodies via ChainDB.
3) Add a small policy layer (non-consensus): default max reorg depth, peer ban/score, basic rate limits.
4) Freeze testnet params and tag `v0.1.0-testnet` once block sync is stable.
5) Wallet CLI after the above (keygen, address encoding, scan/send), not before.

---

## Emission (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Disclaimer

This code is experimental and unaudited. Do not use it for real funds.
