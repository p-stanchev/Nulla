# Nulla

Nulla is an experimental, privacy-first Proof-of-Work blockchain built from scratch in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

**Status:** early development / devnet prototype. There is no mainnet, wallet, mempool, or networking yet.

---

## Current Capabilities

- **Proof of Work:** BLAKE3-based PoW (v0) with Bitcoin-style compact difficulty targets.
- **Ledger State:** Append-only commitment Merkle tree plus a nullifier set to prevent double-spends.
- **Tokenomics:** Deterministic block subsidy with Monero-style tail emission for persistent miner incentives.
- **Consensus Checks:** Enforces exactly one coinbase per block and validates claimed subsidy/fees against state.
- **Node:** Minimal, single-node devnet miner that deterministically produces blocks (no mempool or network).

---

## Project Layout

- `crates/nulla-core` — canonical protocol types, hashing, serialization.
- `crates/nulla-consensus` — PoW validation, compact difficulty, header validation.
- `crates/nulla-state` — commitment tree, nullifier set, and state transitions.
- `crates/nulla-node` — minimal node + devnet miner.
- `crates/nulla-p2p`, `crates/nulla-zk`, `crates/nulla-wallet` — placeholders for upcoming networking, zk verification, and wallet support.

Each crate owns a single responsibility; there are no circular dependencies.

---

## Emission Schedule (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Run the Devnet Miner

### Requirements
- Rust 1.75+ (stable)
- Linux, macOS, or WSL recommended

### Build and run

```bash
cargo run -p nulla-node
```

Expected output (hashes will differ):

```
Starting Nulla minimal miner
Block    0 | hash=... | commitments=1 | subsidy=800000000 | fees=0
Block    1 | hash=... | commitments=2 | subsidy=800000000 | fees=0
Block    2 | hash=... | commitments=3 | subsidy=800000000 | fees=0
```

Blocks are produced deterministically about once per second in this devnet loop.

---

## Roadmap (next steps)

1) Mempool and regular transactions  
2) Persistent storage  
3) RPC interface  
4) P2P networking  
5) zk proof integration (private amounts)  
6) KAWPOW PoW fork (GPU-oriented)

---

## Disclaimer

This code is experimental and not audited. Do not use it for real funds.
