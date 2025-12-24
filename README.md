# Nulla

**Nulla** is an experimental, privacy-focused Proof-of-Work blockchain built from scratch in Rust.

The project is designed with:
- private-by-default UTXOs (commitments + nullifiers)
- deterministic consensus rules
- long-term security via **tail emission**
- clean separation between core protocol, consensus, state, and node logic

> ⚠️ Status: **early development / devnet prototype**  
> No mainnet, no wallets, no networking yet.

---

## ✨ Features (current)

- **Proof of Work**
  - Canonical BLAKE3-based PoW (v0)
  - Bitcoin-style compact difficulty (`bits`)
- **Ledger State**
  - Append-only commitment Merkle tree
  - Nullifier set to prevent double-spends
- **Tokenomics**
  - Tail emission model (Monero-style)
  - Deterministic block subsidy enforced by consensus
- **Strict Consensus Enforcement**
  - Exactly one coinbase per block
  - Subsidy + fee claims verified in state
- **Minimal Miner**
  - Single-node devnet miner
  - Deterministic block production

---

## 🧱 Project Structure

crates/
├── nulla-core # Protocol types, hashing, serialization
├── nulla-consensus # PoW, difficulty, header validation
├── nulla-state # Commitment tree, nullifier set, state transitions
└── nulla-node # Minimal node + miner (single-node devnet)

yaml
Copy code

Each crate has a **single responsibility** and no circular dependencies.

---

## 🪙 Emission Schedule (v1)

- Block time: **60 seconds**
- Initial subsidy: **8 NULLA**
- Halving every ~4 years
- Tail emission: **0.1 NULLA / block forever**

This ensures long-term miner incentives without relying on fees alone.

---

## ▶️ Running the Devnet Miner

### Requirements
- Rust 1.75+ (stable)
- Linux / macOS / WSL recommended

### Build & run

```bash
cargo run -p nulla-node
You should see output like:

bash
Copy code
Starting Nulla minimal miner…
Block    0 | hash=… | commitments=1 | subsidy=800000000 | fees=0
Block    1 | hash=… | commitments=2 | subsidy=800000000 | fees=0
Block    2 | hash=… | commitments=3 | subsidy=800000000 | fees=0
```

## 🛣️ Roadmap

### Planned next steps (in order):
- Mempool + regular transactions
- Persistent storage
- RPC interface
- P2P networking
- zk proof integration (fully private amounts)
- KAWPOW PoW fork (GPU-oriented)

## ⚠️ Disclaimer

This code is experimental and not audited.
Do not use it for real funds.