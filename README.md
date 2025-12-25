<p align="center">
  <img src="assets/nulla-256.png" alt="Nulla logo" width="140">
</p>

# Nulla

Nulla is a privacy-first Proof-of-Work blockchain written in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

---

## Status

- Consensus locked: genesis, tail emission v1, MTP(11) with +/-2h drift, difficulty clamp, PoW vectors, transparent P2PKH txs now in consensus (coinbase pays a transparent output).
- Persisted ChainStore: sled-backed headers/blocks/index/UTXOs + best tip; restart-safe with body reconciliation.
- P2P v0: TCP header-first sync (version/verack, ping/pong, getheaders/headers), heaviest-work selection.
- Block download: best-chain-only path with strict header<->block checks.
- Policy layer: reorg depth cap, peer scoring/bans, basic rate limits (non-consensus).
- Wallet: transparent scaffold landed (keygen/address/encrypted storage/scan CLI); sending/relay next.
- Mempool: transparent tx acceptance wired to ChainStore UTXO view (node-only API for now).

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

## Run

Env:
- CLI flags (primary): `--listen` (default `0.0.0.0:18444`), `--peers`, `--db` (default `./nulla.chain.db`), `--reorg-cap` (default `100`, policy-only).
- Env fallbacks: `NULLA_LISTEN`, `NULLA_PEERS`, `NULLA_DB`, `NULLA_REORG_CAP`. Resolution order: flag > env > default.
- Chain DBs live in the working directory by default: `nulla.chain.db`, plus `nulla.p2p.db` for P2P metadata.
- Mining address: `--miner-address` (Base58Check, prefix 0x35) or `NULLA_MINER_ADDRESS`. If unset, rewards burn to a null hash.
- Wallet rescan expects exclusive access to the chain DB (stop the node during a full rescan, or run against a snapshot).

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

## Testnet

- Two nodes: use the run examples above; expose `--listen 0.0.0.0:18444` on at least one node so others can dial.
- Connecting peers: pass `--peers ip:port,...` (or `NULLA_PEERS`) to seed connections.
- Mining (solo, devnet loop): run `cargo run -p nulla-node` to produce deterministic blocks; PoW remains consensus-valid (dev-pow is test-only).
- Wallet status: transparent wallet exists (init/addr/balance/list/rescan/send). Mining produces transparent UTXOs the wallet can see; tx relay to peers is still minimal.
- Known limitations: no zk yet, no explorers, no Stratum; focus is on sync/restart correctness and fork handling.

---

## Testing

```bash
cargo test --workspace
cargo test --workspace --features dev-pow
```

`dev-pow` is strictly for testing/vector generation and is not consensus.

---

## Roadmap (next)

1) Wire wallet sending/signing and node mempool/tx relay to complete wallet -> node -> block roundtrip.
2) Tag `v0.1.0-testnet` once tx relay is stable.
3) Begin zk primitives only after wallet + relay are solid.

---

## Emission (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Disclaimer

This code is experimental and unaudited. Do not use it for real funds.
