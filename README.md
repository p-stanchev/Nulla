<p align="center">
  <img src="assets/nulla-256.png" alt="Nulla logo" width="140">
</p>

# Nulla

Nulla is a privacy-first Proof-of-Work blockchain written in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

---

## Status

- Consensus locked: genesis, tail emission v1, MTP(11) + ±2h drift, difficulty clamp, PoW vectors.
- Persisted ChainStore: sled-backed headers/blocks/index + best tip, restart-safe.
- P2P v0: TCP, version/verack, ping/pong, getheaders/headers, header-first heaviest-work selection.
- Block download: best-chain-only path with strict header↔block checks scaffolded.
- Policy layer: reorg depth cap, peer scoring/bans, basic rate limits (non-consensus).
- Wallet: out of scope until testnet sync is stable.

---

## What Works Today

- **Consensus:** BLAKE3-based PoW (v0), compact difficulty, median-time-past(11), tail emission, hardcoded genesis, multi-height PoW serialization vectors.
- **ChainStore / ChainDB:** sled-backed storage for headers, blocks, index entries `{hash,height,prev,bits,time,cumulative_work}`, and best tip with recovery coverage.
- **Fork Choice:** heaviest cumulative work with deterministic tie-breaker; difficulty-drop clamp enforced everywhere; single validation entrypoint (no bypass).
- **P2P v0 (header-first):** TCP transport, locators, fork handling, restart safety. Dev-only easy PoW lives behind the `dev-pow` feature for tests/vector generation.
- **Node:** devnet miner loop wired through ChainStore and P2pEngine; block download restricted to the best chain.

---

## Project Layout

- `crates/nulla-core` — protocol types, hashing, serialization.
- `crates/nulla-consensus` — PoW, difficulty, header/block validation.
- `crates/nulla-state` — commitment tree, nullifier set, state transitions.
- `crates/nulla-node` — node runtime, ChainStore integration, devnet loop.
- `crates/nulla-p2p` — networking engine (TCP header-first, locators, fork handling).
- `crates/nulla-wallet`, `crates/nulla-zk` — stubs for future wallet and zk work.

Each crate owns a single responsibility; there are no circular dependencies.

---

## Run

Env:
- `NULLA_LISTEN` (default `127.0.0.1:18444`)
- `NULLA_PEERS` (comma-separated `host:port` list to dial)
- Chain DBs live in the working directory: `nulla.chain.db`, `nulla.p2p.db`

Examples (two local nodes):
```bash
# Node A (listen on default)
cargo run -p nulla-node

# Node B (custom port, connect to A)
NULLA_LISTEN=127.0.0.1:18445 \
NULLA_PEERS=127.0.0.1:18444 \
cargo run -p nulla-node
```

---

## Testing

```bash
cargo test --workspace
cargo test --workspace --features dev-pow
```

`dev-pow` is strictly for testing/vector generation and is not consensus.

---

## Roadmap (next)

1) Finalize block sync persistence across restarts (headers + bodies).
2) Tag `v0.1.0-testnet` once block sync is stable.
3) Only then start wallet CLI work (keygen, address encoding, scan/send).

---

## Emission (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Disclaimer

This code is experimental and unaudited. Do not use it for real funds.
