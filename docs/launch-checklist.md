# Nulla Genesis Launch Checklist (Policy Only, No Consensus Changes)

## Pre-launch (48h before genesis)
- Seeds: run all three seeds continuously (45.155.53.102/112/126:27444). Verify:
  - Seeds interconnect with each other.
  - Fresh node syncs from any single seed.
  - Restarting a seed does not stall headers.
- Mining ops: prepare at least one dedicated miner with `--mine --miner-address <addr>`; confirm it syncs first (can_mine=true via RPC).
- Ports: ensure P2P port 27444 is open/forwarded on seeds/miners; RPC stays bound to localhost (127.0.0.1:27445).
- Tag: create `v1.0.0-genesis` from clean checkout; no consensus diffs after.

## Release discipline (day of tag)
- Build binaries once from the tag:
  - `cargo build --release -p nulla-node -p nulla-wallet`
  - Publish SHA256 sums.
- Publish chain params:
  - Chain ID 0, magic NUL0, ports: P2P 27444, RPC 27445
  - Genesis hash/roots/nonce (from code constants)
  - Seeds: 45.155.53.102/112/126:27444
  - Fee/mempool caps: min relay fee > 0; pool caps 5k txs or ~5MB; fee-rate eviction
  - P2P caps: msg 1MB, max 64 headers, 1024 inv_tx, 32 block req, ~200 msgs/sec/peer
  - Mining gate: opt-in `--mine`; requires peers >=3, height within 1 of best peer, ~90s stability
  - NAT: optional `--nat` for UPnP attempt
  - No premine/dev tax

## Launch messaging (Genesis week)
- Frame as “experimental mainnet”:
  - Low hash rate expected
  - Short reorgs possible early
  - No backward-compat guarantee before v1.1
- Encourage followers to run `--no-mine` unless they are an approved miner.
- Encourage miners to peer with multiple seeds and wait for can_mine=true before mining.

## Immediate post-launch (v1.0.x hardening, no consensus changes)
- Better peer scoring / orphan handling
- Improved logs/metrics for ops
- Seed operator checklist / add community seed

## Commands (reference)
- Seed/follower: `cargo run -p nulla-node -- --no-mine --nat --listen 0.0.0.0:27444 --seeds 45.155.53.102:27444,45.155.53.112:27444,45.155.53.126:27444`
- Miner: `cargo run -p nulla-node -- --mine --miner-address <addr> --peers 45.155.53.102:27444,45.155.53.112:27444,45.155.53.126:27444`
- Check mining readiness: node RPC `{"method":"get_chain_info"}` returns can_mine / mining_block_reason.
- Optional: add `--gossip` to enable non-critical addr/getaddr exchange (capped, filtered to public IPs).
