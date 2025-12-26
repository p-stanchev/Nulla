<p align="center">
  <img src="assets/nulla-256.png" alt="Nulla logo" width="140">
</p>

# Nulla

Nulla is a privacy-first Proof-of-Work blockchain written in Rust. It targets private-by-default UTXOs (commitments + nullifiers), deterministic consensus rules, and long-term security via tail emission.

---

## Status

- Consensus locked: genesis, tail emission v1, MTP(11) with +/-2h drift, LWMA difficulty targeting 60s (window 60) with per-block drop clamp, PoW vectors, transparent P2PKH txs (coinbase pays a transparent output).
- Chain identity locked: chain ID `0`, magic `NUL0`, address prefix `0x35`.
- Persisted ChainStore: sled-backed headers/blocks/index/UTXOs + best tip; restart-safe with body reconciliation.
- P2P v0: TCP header-first sync (version/verack, ping/pong, getheaders/headers), heaviest-work selection.
- Block download: best-chain-only path with strict header<->block checks.
- Policy layer: reorg depth cap, peer scoring/bans, basic rate limits (non-consensus).
- Wallet: transparent CLI (keygen/address/encrypted storage/rescan/balance/list/send) via node RPC.
- Mempool/Fees: transparent tx acceptance wired to ChainStore UTXO view; base fee enforced; miner includes mempool txs.
- Sync + mining gating: mining/mempool work waits until the node catches the best peer height; `--no-mine`/`NULLA_NO_MINE` for follower/seed mode.
- Networking bootstrap: seeds supported via `--seeds`/`NULLA_SEEDS` fallback when no explicit `--peers`.
- RPC helpers: `get_balance`/`get_utxos` accept address or pubkey hash; submit/validate/chain info unchanged.
- P2P tx relay: inv/get_tx/tx wired through the single mempool validation path.\n- Optional seed URL: --seed-url/NULLA_SEED_URL fetches a JSON list of peers from a VPS/bootstrap endpoint.\n- Fork mitigation: initial-sync gate + follower mode reduce accidental forks; consensus still resolves forks via heaviest work (forks cannot be eliminated entirely in PoW).

---

## What Works Today

- **Consensus:** BLAKE3-based PoW (v0), compact difficulty, median-time-past(11), tail emission, hardcoded genesis, multi-height PoW serialization vectors.
- **ChainStore / ChainDB:** sled-backed storage for headers, blocks, index entries `{hash,height,prev,bits,time,cumulative_work}`, UTXO index (including coinbase), and best tip with recovery coverage.
- **Fork Choice:** heaviest cumulative work with deterministic tie-breaker; difficulty-drop clamp enforced everywhere; single validation entrypoint (no bypass).
- **P2P v0 (header-first):** TCP transport, locators, fork handling, restart safety. Dev-only easy PoW lives behind the `dev-pow` feature for tests/vector generation.
- **Node:** devnet miner loop wired through ChainStore and P2pEngine; LWMA difficulty targeting 60s with drop clamp; block download restricted to the best chain.
- **Mempool/Fees:** transparent tx acceptance with base fee policy; txs reannounced over P2P.

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

Node (must be running for wallet operations)
- Start + mine to your address (PowerShell/cmd):  
  `cargo run -p nulla-node -- --miner-address <Base58 addr>`
- Defaults (mainnet-ready): listen `0.0.0.0:27444`, db `./nulla.chain.db`, reorg-cap `100`.  
  Env fallbacks: `NULLA_LISTEN`, `NULLA_PEERS`, `NULLA_SEEDS`, `NULLA_DB`, `NULLA_REORG_CAP`, `NULLA_MINER_ADDRESS`, `NULLA_NO_MINE`.
- RPC: `NULLA_RPC_LISTEN=127.0.0.1:27445` (default), `NULLA_RPC_AUTH_TOKEN` optional.
- Seeds: `NULLA_SEEDS` (comma-separated `host:port`), used if no explicit `--peers` provided.
- Sync/roles: mining and mempool processing stay off until local height catches the best peer height (initial-sync gate). Use `--no-mine`/`NULLA_NO_MINE` for follower/seed nodes.
- Difficulty: LWMA(60) targeting 60s with per-block drop clamp (consensus).

Wallet (RPC-only; does **not** open the node DB)
- Init: `cargo run -p nulla-wallet -- init`
- Show address: `cargo run -p nulla-wallet -- addr`
- Rescan UTXOs (node running):  
  `cargo run -p nulla-wallet -- rescan`
- Balance: `cargo run -p nulla-wallet -- balance`
- Send (base fee added automatically):  
  `cargo run -p nulla-wallet -- send --to <addr> --amount <atoms>`
- Common flags: `--wallet-db <path>` (default `nulla.wallet.db`), `--rpc <addr>` (default `127.0.0.1:27445`), `--rpc-auth-token <token>` if the node requires it.
- Command syntax: keep a single `--` between cargo and wallet args; do **not** place an extra `--` before the subcommand (e.g., `cargo run -p nulla-wallet -- --wallet-db my.db rescan`).

Two-node example (header + block + tx relay)
```bash
# Node A (default listen 27444, RPC 27445)
cargo run -p nulla-node

# Node B (custom listen/RPC, connect to A)
NULLA_LISTEN=127.0.0.1:27446 \
NULLA_PEERS=127.0.0.1:27444 \
NULLA_RPC_LISTEN=127.0.0.1:27447 \
cargo run -p nulla-node
```

Multi-node walkthrough: see `docs/multinode.md` for full P2P+wallet steps.
Mainnet prep notes: see `docs/mainnet-plan.md` (chain ID 0, policy, launch checklist).

---

## Testnet Flow (quick checklist)

1) Start node with your miner address.
2) Wallet `init` + `addr`, then `rescan` (node running).
3) Mine a block -> wallet balance increases (transparent coinbase UTXO).
4) Wallet `send --to <addr> --amount <atoms>` -> mine again -> tx confirmed.
5) Repeat; restart nodes to confirm persistence.

### Common gotchas (send/rescan/mine)
- No balance after send: keep the node running and mine at least one block; then rescan the receiver wallet.
- UnknownInput: rescan the sender wallet, ensure the node is running, and that the miner is paying to the same wallet you are spending from.
- Wrong miner address: start the node with the address shown by `cargo run -p nulla-wallet -- --wallet-db <db> addr`.
- RPC refused: start the node first (default RPC 127.0.0.1:27445), or pass `--rpc <addr>`/`--rpc-auth-token <token>`.
- Command syntax: only one `--` between cargo and wallet args, e.g. `cargo run -p nulla-wallet -- --wallet-db my.db rescan`.

Notes:
- Tx relay uses P2P inv/get_tx/tx; wallets still talk to the local node via RPC.
- No zk, no pools, no explorers, no Stratum yet.
## Testing

```bash
cargo test --workspace
cargo test --workspace --features dev-pow
```

`dev-pow` is strictly for testing/vector generation and is not consensus.

---

## Roadmap (next)

1) Harden tx relay + fee policy (base fee already enforced; add ordering/limits).
2) GUI wallet (Tauri) consuming the existing RPCs (balance/utxos/submit_tx).
3) Tag `v0.3.0-testnet`, then consider mainnet freeze; zk/shielded transfers come after stable transparent layer.

---

## Emission (v1)

- Block time: 60 seconds
- Initial subsidy: 8 NULLA
- Halving every ~4 years (2,102,400 blocks)
- Tail emission: 0.1 NULLA per block indefinitely

---

## Disclaimer

This code is experimental and unaudited. Do not use it for real funds.



