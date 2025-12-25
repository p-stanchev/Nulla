<p align="center">
  <img src="assets/nulla-256.png" alt="Nulla logo" width="140">
</p>

# Nulla

Nulla is a privacy-first Proof-of-Work blockchain written in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

---

## Status

- Consensus locked: genesis, tail emission v1, MTP(11) with +/-2h drift, difficulty clamp, PoW vectors, transparent P2PKH txs (coinbase pays a transparent output).
- Persisted ChainStore: sled-backed headers/blocks/index/UTXOs + best tip; restart-safe with body reconciliation.
- P2P v0: TCP header-first sync (version/verack, ping/pong, getheaders/headers), heaviest-work selection.
- Block download: best-chain-only path with strict header<->block checks.
- Policy layer: reorg depth cap, peer scoring/bans, basic rate limits (non-consensus).
- Wallet: transparent CLI (keygen/address/encrypted storage/rescan/balance/list/send) via node RPC.
- Mempool: transparent tx acceptance wired to ChainStore UTXO view; miner includes mempool txs.

---

## What Works Today

- **Consensus:** BLAKE3-based PoW (v0), compact difficulty, median-time-past(11), tail emission, hardcoded genesis, multi-height PoW serialization vectors.
- **ChainStore / ChainDB:** sled-backed storage for headers, blocks, index entries `{hash,height,prev,bits,time,cumulative_work}`, UTXO index (including coinbase), and best tip with recovery coverage.
- **Fork Choice:** heaviest cumulative work with deterministic tie-breaker; difficulty-drop clamp enforced everywhere; single validation entrypoint (no bypass).
- **P2P v0 (header-first):** TCP transport, locators, fork handling, restart safety. Dev-only easy PoW lives behind the `dev-pow` feature for tests/vector generation.
- **Node:** devnet miner loop wired through ChainStore and P2pEngine; block download restricted to the best chain.

---

## Project Layout

- `crates/nulla-core` - protocol types, hashing, serialization.
- `crates/nulla-consensus` - PoW, difficulty, header/block validation.
- `crates/nulla-state` - commitment tree, nullifier set, state transitions.
- `crates/nulla-node` - node runtime, ChainStore integration, devnet loop.
- `crates/nulla-p2p` - networking engine (TCP header-first, locators, fork handling).
- `crates/nulla-wallet` - transparent wallet scaffold (CLI).
- `crates/nulla-zk` - zk stubs for future shielded transfers.

Each crate owns a single responsibility; there are no circular dependencies.

---

## Getting Started (beginner friendly)

Node
- Start a node (mining to your address):  
  `cargo run -p nulla-node -- --miner-address <Base58 addr>`
- Defaults: listen `0.0.0.0:18444`, db `./nulla.chain.db`, reorg-cap `100`.  
  Env fallbacks: `NULLA_LISTEN`, `NULLA_PEERS`, `NULLA_DB`, `NULLA_REORG_CAP`, `NULLA_MINER_ADDRESS`.
- RPC (local only by default): `NULLA_RPC_LISTEN=127.0.0.1:18445` (default), `NULLA_RPC_AUTH_TOKEN` optional.

Wallet (talks to node via RPC; does **not** open the node DB)
- Init: `cargo run -p nulla-wallet -- init`
- Show address: `cargo run -p nulla-wallet -- addr`
- Rescan (node must be running): `cargo run -p nulla-wallet -- rescan`
- Check balance: `cargo run -p nulla-wallet -- balance`
- Send: `cargo run -p nulla-wallet -- send --to <addr> --amount <atoms> --fee <atoms>`
- Wallet flags: `--wallet-db` (default `nulla.wallet.db`), `--rpc` (default `127.0.0.1:18445`), `--rpc-auth-token` (if node requires it).

Two-node example (header sync)
```bash
# Node A (default listen)
cargo run -p nulla-node

# Node B (custom port, connect to A)
NULLA_LISTEN=127.0.0.1:18445 \
NULLA_PEERS=127.0.0.1:18444 \
cargo run -p nulla-node
```

---

## Testnet Flow (quick checklist)

1) Start node with your miner address.  
2) Wallet `init` → `rescan` (node running).  
3) Mine a block → wallet balance increases (coinbase UTXO is transparent).  
4) Wallet `send` → mine again → tx confirmed.  
5) Repeat; restart nodes to confirm persistence.

Notes:
- Tx relay is local-only for now (no P2P tx gossip yet).
- No zk, no pools, no explorers, no Stratum yet.

---

## Testing

```bash
cargo test --workspace
cargo test --workspace --features dev-pow
```

`dev-pow` is strictly for testing/vector generation and is not consensus.

---

## Roadmap (next)

1) Add P2P tx relay (local RPC already exists).
2) Tag `v0.1.0-testnet`.
3) Explore zk/shielded transfers only after wallet + relay are solid.

---

## Emission (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Disclaimer

This code is experimental and unaudited. Do not use it for real funds.
