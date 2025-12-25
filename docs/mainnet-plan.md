# Mainnet Prep (draft)

Chain identity (locked)
- Chain ID: `0` (numeric, stringified on wire)
- Magic bytes: `NUL0` (`[0x4e, 0x55, 0x4c, 0x30]`)
- Address prefix: `0x35` (Base58Check)

Operational policy
- RPC: bind to localhost, require auth token; do not expose publicly
- P2P: open only the P2P port on seed/validator nodes; firewall everything else
- Fee policy: fixed base fee (node mempool enforces; wallet auto-adds)
- Mempool: drop txs spending missing inputs on tip change; consider adding a size cap for production
- Default ports: P2P `0.0.0.0:27444`, RPC `127.0.0.1:27445`
- Seed nodes: configure publicly reachable peers on 27444; nodes use `--seeds` or `NULLA_SEEDS` if no explicit peers

Launch checklist
- Lock genesis hash/params and seed node list
- Run 3-node soak (A mines, B sends, C joins late) for several hours; watch relay, reorg, and persistence
- Tag release after soak: `v0.2.x-testnet` → plan `v1.0.0-mainnet`

GUI (Tauri) surface
- RPC methods: `get_balance` (address/pubkey_hash), `get_utxos`, `submit_tx`, `validate_address`, `get_chain_info`
- Screens: overview (balance/height/status), receive (address + QR), send (to/amount, auto fee), activity (recent txs)
- Keep GUI thin; no direct DB access; talk to node RPC only

Sync/consistency guarantees
- Genesis hash/nonce/merkle roots are hardcoded; alternative genesis is rejected.
- Chain ID `0`, magic `NUL0`, address prefix `0x35` are fixed; nodes with different constants will fork and be rejected.
- Header-first sync + heaviest-work fork choice + difficulty/MTP checks ensure convergence on the best chain.
- Tx relay uses `InvTx/GetTx/Tx`; blocks use headers/blocks; invalid/unknown data is dropped.
- Ensure all nodes run the same release tag (no mixed constants) and expose only P2P ports; keep RPC localhost + auth.
