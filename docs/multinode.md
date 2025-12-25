# Multi-node quickstart (local LAN/localhost)

This is the minimal setup to run two nodes and verify tx relay + wallet sync. Adjust ports/paths as needed.

## Node A (defaults)
- Start and mine to wallet A:
  ```
  cargo run -p nulla-node -- --miner-address <addrA>
  ```
  - P2P listen: `0.0.0.0:18444`
  - RPC: `127.0.0.1:18445`
  - DBs: `nulla.chain.db`, `nulla.chain.p2p.db`

## Node B (custom ports/DBs, connect to A)
- Set env vars then start:
  ```
  $env:NULLA_LISTEN="0.0.0.0:18446"
  $env:NULLA_PEERS="<A_ip>:18444"        # A’s P2P address/port
  $env:NULLA_DB="nulla.chain.b.db"
  $env:NULLA_P2P_DB="nulla.chain.p2p.b.db"
  $env:NULLA_RPC_LISTEN="127.0.0.1:18447"
  cargo run -p nulla-node -- --miner-address <addrB>
  ```
  Ensure ports 18444/18446 are reachable between machines.

## Wallets
- Use RPC of the node you’re targeting:
  - Node A RPC: `--rpc 127.0.0.1:18445`
  - Node B RPC: `--rpc 127.0.0.1:18447`
- Refresh before checking balance/send:
  ```
  cargo run -p nulla-wallet -- --wallet-db walletA.db --rpc 127.0.0.1:18445 rescan
  cargo run -p nulla-wallet -- --wallet-db walletA.db --rpc 127.0.0.1:18445 balance
  ```

## Send/relay check
1) Fund wallet A by mining on node A.
2) Submit tx via node A RPC:
   ```
   cargo run -p nulla-wallet -- --wallet-db walletA.db --rpc 127.0.0.1:18445 send --to <addrB> --amount 10000
   ```
3) Mine a block (A or B).  
4) On wallet B (talking to node B): `rescan` then `balance` → should show the received UTXO without manual submit.

## Notes
- Keep RPC bound to localhost for safety; only expose P2P ports between nodes.
- Wallet auto-adds the base fee; there is no `--fee` flag anymore.
- If you see `UnknownInput`, rescan the sending wallet and ensure the node is running and mining to that wallet’s address. 
