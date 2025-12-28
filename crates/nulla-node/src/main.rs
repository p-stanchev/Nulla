#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod mempool;
mod rpc;

use clap::Parser;
use reqwest::blocking;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use bs58::decode as b58decode;
use mempool::{Mempool, SubmitError as MempoolSubmitError};
#[allow(unused_imports)]
use nulla_consensus::validate_block_with_prev_bits;
use nulla_core::{
    block_header_hash, txid, Amount, Block, BlockHeader, Commitment, Hash32, Transaction,
    TransactionKind, ADDRESS_PREFIX, CHAIN_ID, GENESIS_BITS, GENESIS_HASH_BYTES, GENESIS_NONCE,
    GENESIS_TIMESTAMP, NETWORK_MAGIC, PROTOCOL_VERSION,
};
use nulla_node::chain_store::{ChainDb, ChainStore};
use nulla_p2p::net::{Message, P2pEngine, Policy, RelayConfig};
use nulla_state::{block_subsidy, LedgerState};
use rand::Rng;

/// Extremely easy difficulty for devnet (currently unused; retained for debug).
#[allow(dead_code)]
const DEVNET_BITS: u32 = GENESIS_BITS;

/// Node configuration resolved from CLI/env/defaults.
#[derive(Parser, Debug)]
#[command(name = "nulla-node", version)]
struct Config {
    /// Listen address for P2P
    #[arg(long = "listen")]
    listen: Option<String>,
    /// Peers to dial, comma separated host:port list
    #[arg(long = "peers")]
    peers: Option<String>,
    /// Seed peers (fallback if no explicit peers), comma separated host:port list
    #[arg(long = "seeds")]
    seeds: Option<String>,
    /// HTTP(S) URL that returns a JSON array of seed addresses (["host:port", ...])
    #[arg(long = "seed-url")]
    seed_url: Option<String>,
    /// Enable mining (opt-in). Default: off.
    #[arg(long = "mine")]
    mine: bool,
    /// Disable mining (follower/seed mode). Overrides --mine.
    #[arg(long = "no-mine")]
    no_mine: bool,
    /// Optional HTTP bootstrap endpoint (seed only), e.g. 0.0.0.0:8080
    #[arg(long = "bootstrap-listen")]
    bootstrap_listen: Option<String>,
    /// Optional TCP relay listener (seed only), e.g. 0.0.0.0:28500
    #[arg(long = "relay-listen")]
    relay_listen: Option<String>,
    /// Optional TCP relay target (where to forward relay connections), e.g. 1.2.3.4:27444
    #[arg(long = "relay-target")]
    relay_target: Option<String>,
    /// Enable automatic relay capability and accept relay slots (requires --relay-cap).
    #[arg(long = "relay-auto")]
    relay_auto: bool,
    /// Maximum relay slots to serve (required when --relay-auto is set).
    #[arg(long = "relay-cap")]
    relay_cap: Option<u32>,
    /// Request a relay slot when connecting outbound (for NAT’d nodes).
    #[arg(long = "request-relay")]
    request_relay: bool,
    /// Attempt NAT-PMP/UPnP port mapping for the listen port (opt-in).
    #[arg(long = "nat")]
    nat: bool,
    /// Optional node role shortcut: miner | follower | seed
    #[arg(long = "role")]
    role: Option<String>,
    /// Enable addr gossip (optional; default off).
    #[arg(long = "gossip")]
    gossip: bool,
    /// Disable addr gossip (override; default on).
    #[arg(long = "no-gossip")]
    no_gossip: bool,
    /// Path to ChainDB (sled)
    #[arg(long = "db")]
    db: Option<PathBuf>,
    /// Policy reorg cap (non-consensus)
    #[arg(long = "reorg-cap")]
    reorg_cap: Option<u64>,
    /// Miner payout address (Base58Check, prefix 0x35). Defaults to burn if not set.
    #[arg(long = "miner-address")]
    miner_address: Option<String>,
    /// Allow mining even when local height is behind best peer (unsafe; testing only).
    #[arg(long = "mine-while-behind")]
    mine_while_behind: bool,
}

fn main() {
    // Initialize logging so P2P/ops messages show up (env: RUST_LOG=info by default).
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .try_init();

    println!("Starting Nulla minimal miner");
    println!(
        "Chain ID: {CHAIN_ID} | magic: {:?} | addr_prefix: 0x{:x}",
        NETWORK_MAGIC, ADDRESS_PREFIX
    );

    let cfg = resolve_config(Config::parse());
    println!("Mining rewards sent to: {}", cfg.miner_addr_b58);
    if cfg.listen.ip().is_loopback() {
        eprintln!(
            "warn: inbound disabled (listen on {}). Use a public IP/port forward for peers.",
            cfg.listen
        );
    }
    if cfg.relay_auto && cfg.relay_cap == 0 {
        eprintln!("warn: --relay-auto requires --relay-cap; relay remains disabled");
    }
    if cfg.nat_enabled {
        maybe_open_nat(&cfg.listen);
    }

    // -----------------
    // Genesis block (height 0) and DB setup
    // -----------------
    let genesis = build_genesis();
    let genesis_header = genesis.header.clone();
    let db_path = cfg.db_path.clone();
    let chain_db = Arc::new(ChainDb::open(&db_path).expect("open chain db"));
    chain_db.ensure_genesis(&genesis).expect("insert genesis");

    // -----------------
    // P2P wiring (authoritative ingress)
    // -----------------
    let relay_cfg = RelayConfig {
        node_id: cfg.node_id,
        request_relay: cfg.request_relay,
        provide_relay: cfg.relay_auto && cfg.relay_cap > 0,
        relay_cap: cfg.relay_cap,
    };
    let mut p2p = P2pEngine::with_policy(
        &cfg.p2p_db_path,
        genesis_header,
        Policy {
            max_reorg_depth: Some(cfg.reorg_cap),
            ban_threshold: 3,
        },
        relay_cfg,
    )
    .expect("p2p init");
    p2p.set_advertised_port(cfg.listen.port());
    // Prioritize user-supplied peers and seeds in the dialer table so we keep retrying them
    // even if gossip is off or the addresses are non-public (e.g., LAN testing).
    let mut dial_roots = cfg.peers.clone();
    dial_roots.extend(cfg.seeds.clone());
    if !dial_roots.is_empty() {
        p2p.add_static_peers(dial_roots);
    }
    p2p.enable_gossip(cfg.gossip_enabled);
    if cfg.gossip_enabled {
        println!("Gossip-lite enabled (non-critical)");
    } else {
        println!("Gossip disabled by config");
    }
    {
        let db = Arc::clone(&chain_db);
        p2p.set_block_callback(move |block| db.store_block_if_index_matches(block));
    }
    let p2p = Arc::new(Mutex::new(p2p));
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    let listener = TcpListener::bind(cfg.listen).expect("bind p2p socket");
    let _server = P2pEngine::serve_incoming(Arc::clone(&p2p), listener);

    if let Some(addr) = cfg.bootstrap_listen {
        println!("Bootstrap HTTP endpoint on {addr}");
        start_bootstrap_server(Arc::clone(&p2p), addr);
    }
    if let (Some(listen), Some(target)) = (cfg.relay_listen, cfg.relay_target) {
        println!("Relay proxy listening on {listen}, forwarding to {target}");
        start_relay_proxy(listen, target);
    }

    // Compute best chain and missing bodies, then request them on connect.
    let (_best_tip, best_chain, missing) = compute_best_chain_and_missing(&chain_db);
    // Prefer explicit peers; if none, fall back to seeds.
    let connect_list = if cfg.peers.is_empty() {
        cfg.seeds.clone()
    } else {
        cfg.peers.clone()
    };
    for peer in connect_list {
        let _ = P2pEngine::connect_and_sync(Arc::clone(&p2p), peer, missing.clone());
    }
    {
        let p2p_for_dial = Arc::clone(&p2p);
        let missing_getblocks = missing.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(10));
            // Try more peers more often; per-peer backoff still applies inside the engine.
            let targets = {
                let mut eng = p2p_for_dial.lock().expect("p2p dial");
                eng.next_dial_targets(8, Duration::from_secs(10))
            };
            for addr in targets {
                let _ = P2pEngine::connect_and_sync(
                    Arc::clone(&p2p_for_dial),
                    addr,
                    missing_getblocks.clone(),
                );
            }
        });
    }
    // Poll for missing bodies to arrive.
    wait_for_missing(&chain_db, &best_chain, Duration::from_secs(2));

    // Build ChainStore once bodies are reconciled.
    let chain = ChainStore::load_or_init_with_db((*chain_db).clone(), genesis.clone())
        .expect("valid genesis/db");
    let chain = Arc::new(Mutex::new(chain));
    let rpc_listen = env::var("NULLA_RPC_LISTEN")
        .ok()
        .unwrap_or_else(|| "127.0.0.1:27445".to_string());
    let rpc_auth = env::var("NULLA_RPC_AUTH_TOKEN").ok();
    {
        let chain_for_cb = Arc::clone(&chain);
        p2p.lock().expect("p2p").set_block_callback(move |block| {
            let mut chain = chain_for_cb.lock().expect("chain lock");
            let h = block_hash(block);
            if chain.entry(&h).is_none() {
                chain.insert_block(block.clone()).map_err(|e| e)?;
            }
            Ok(())
        });
    }
    let is_syncing = Arc::new(AtomicBool::new(true));
    let mining_ready = Arc::new(AtomicBool::new(false));
    let mining_block_reason: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    {
        let chain_for_cb = Arc::clone(&chain);
        let mem_for_cb = Arc::clone(&mempool);
        let mut guard = p2p.lock().expect("p2p");
        guard.set_has_tx(move |txid| {
            let pool = mem_for_cb.lock().expect("mempool");
            pool.has_tx(txid)
        });
        let mem_for_lookup = Arc::clone(&mempool);
        guard.set_lookup_tx(move |txid| {
            let pool = mem_for_lookup.lock().expect("mempool");
            pool.get_tx(txid)
        });
        let mem_for_tx = Arc::clone(&mempool);
        let net_for_tx = Arc::clone(&p2p);
        let sync_flag = Arc::clone(&is_syncing);
        guard.set_tx_callback(move |tx| {
            if sync_flag.load(Ordering::Relaxed) {
                // Drop txs during initial sync to avoid churn.
                return Ok(());
            }
            let chain = chain_for_cb.lock().expect("chain lock");
            let mut pool = mem_for_tx.lock().expect("mempool");
            let txid = pool
                .submit_tx(&*chain, tx.clone())
                .map_err(|e| format!("{:?}", e))?;
            // Re-announce to other peers.
            let net = net_for_tx.lock().expect("p2p net");
            net.broadcast(Message::InvTx(vec![txid]));
            Ok(())
        });
    }
    let _ = rpc::serve_rpc(
        &rpc_listen,
        rpc_auth,
        Arc::clone(&chain),
        Arc::clone(&mempool),
        Arc::clone(&p2p),
        Arc::clone(&mining_ready),
        Arc::clone(&mining_block_reason),
    );
    println!("RPC listening on {rpc_listen}");

    // -----------------
    // Main mining loop (gated on sync/mining_enabled)
    // -----------------
    let mut height = 1u64;
    let mut mining_gate_active = true;
    // Non-consensus: allow solo mining; adjust stability wait for faster start.
    let min_peers_for_mining = 0usize;
    let sync_stable_secs = 30u64;
    let mut sync_stable_since: Option<std::time::Instant> = None;
    let mut last_block_reason: Option<String> = None;
    let mut last_gate_log = Instant::now();
    let mut last_progress_log = Instant::now();
    loop {
        let best_height = { chain.lock().expect("chain lock").best_entry().height };
        let (peer_height, peer_count) = {
            let guard = p2p.lock().expect("p2p");
            (guard.best_peer_height(), guard.peer_count())
        };
        let syncing = best_height < peer_height;
        is_syncing.store(syncing, Ordering::Relaxed);

        // Track stability window.
        if !syncing && best_height >= peer_height {
            if sync_stable_since.is_none() {
                sync_stable_since = Some(std::time::Instant::now());
            }
        } else {
            sync_stable_since = None;
        }

    // Mining readiness policy (non-consensus).
    let mut block_reason: Option<String> = None;
    if !cfg.mining_enabled {
        block_reason = Some("mining disabled (no --mine)".into());
    } else if peer_count < min_peers_for_mining {
        block_reason = Some(format!(
                "waiting for peers (have {}, need >= {})",
                peer_count, min_peers_for_mining
            ));
        } else if best_height < peer_height && !cfg.mine_while_behind {
            block_reason = Some(format!(
                "waiting for chain catch-up (need equal height; local {}, best peer {})",
                best_height, peer_height
            ));
            // Emit a simple progress indicator while catching up.
            let now = Instant::now();
            if now.saturating_duration_since(last_progress_log) >= Duration::from_secs(1) {
                let pct = if peer_height == 0 {
                    0.0
                } else {
                    (best_height as f64 / peer_height as f64).min(1.0) * 100.0
                };
                let bar = render_progress_bar(24, pct / 100.0);
                println!(
                    "Syncing chain: {} / {} ({:.1}%) {}",
                    best_height, peer_height, pct, bar
                );
                last_progress_log = now;
            }
        } else if let Some(since) = sync_stable_since {
            if since.elapsed().as_secs() < sync_stable_secs {
                block_reason = Some(format!(
                    "waiting for sync stability ({}s/{}s)",
                    since.elapsed().as_secs(),
                    sync_stable_secs
                ));
            }
        } else {
            block_reason = Some("sync not stable yet".into());
        }

        if let Some(reason) = block_reason {
            mining_ready.store(false, Ordering::Relaxed);
            if let Ok(mut r) = mining_block_reason.lock() {
                *r = Some(reason.clone());
            }
            let now = Instant::now();
            if last_block_reason.as_ref() != Some(&reason)
                || now.saturating_duration_since(last_gate_log) >= Duration::from_secs(30)
            {
                println!("Mining paused: {reason}");
                last_block_reason = Some(reason);
                last_gate_log = now;
            }
            // Reset gate so we log "Mining enabled" when conditions clear.
            mining_gate_active = true;
            thread::sleep(Duration::from_millis(200));
            continue;
        } else if mining_gate_active {
            println!(
                "Mining enabled: height {}, peers {}, best peer {}",
                best_height, peer_count, peer_height
            );
            mining_gate_active = false;
            last_block_reason = None;
            mining_ready.store(true, Ordering::Relaxed);
            if let Ok(mut r) = mining_block_reason.lock() {
                *r = None;
            }
        }

        // Drain any locally submitted transactions (file dropbox).
        drain_local_submissions(&cfg.db_path, &chain, &mempool);

        // Drop any mempool txs that no longer have valid inputs on the best chain.
        {
            let chain_guard = chain.lock().expect("chain lock");
            let mut pool = mempool.lock().expect("mempool");
            pool.purge_conflicts_with_new_tip(&*chain_guard);
        }

        // Gather txs from mempool (no ordering/limits yet).
        let txs_from_pool = {
            let pool = mempool.lock().expect("mempool");
            pool.pending()
        };
        let fee_sum: Amount = txs_from_pool.iter().fold(Amount::zero(), |acc, tx| {
            acc.checked_add(tx.fee).unwrap_or(acc)
        });
        let subsidy = block_subsidy(height);

        let coinbase = coinbase_tx(height, fee_sum, subsidy, cfg.miner_pubkey_hash);
        let mut txs = Vec::with_capacity(1 + txs_from_pool.len());
        txs.push(coinbase);
        txs.extend_from_slice(&txs_from_pool);
        let (block_for_p2p, state_commitments, best_height, best_hash) = {
            let mut chain_lock = chain.lock().expect("chain lock");
            let prev = chain_lock.best_hash();
            let prev_bits = chain_lock.best_bits();
            let mtp = chain_lock
                .median_time_past(prev)
                .expect("mtp available for non-genesis");

            let next_bits = chain_lock.next_bits();
            let block = build_block(prev, prev_bits, mtp, &chain_lock, txs, next_bits);
            let block_for_store = block.clone();

            chain_lock
                .insert_block(block)
                .expect("block must validate and attach");
            let state = chain_lock.rebuild_state();
            let best = chain_lock.best_entry();

            (
                block_for_store,
                state.commitment_len(),
                best.height,
                chain_lock.best_hash(),
            )
        };

        // Advertise to peers using the single entrypoint.
        {
            let mut p2p_guard = p2p.lock().expect("p2p");
            let _ =
                p2p_guard.handle_message(0, Message::Headers(vec![block_for_p2p.header.clone()]));
            let _ = p2p_guard.handle_message(0, Message::Block(block_for_p2p));
        }

        println!(
            "Block {:>4} | hash={} | height={} | commitments={}",
            best_height, best_hash, best_height, state_commitments
        );

        thread::sleep(Duration::from_secs(1));
        height = height.saturating_add(1);
    }
}

/// Build and mine the deterministic genesis block.
fn build_genesis() -> Block {
    let height0 = 0u64;
    // Genesis rewards are sent to burn address; regular blocks use configured miner address.
    let coinbase0 = coinbase_tx(height0, Amount::zero(), block_subsidy(height0), [0u8; 20]);
    let txs = vec![coinbase0];

    let state = LedgerState::new();
    let commitment_root = state.preview_root_after(&txs).expect("state preview");

    #[allow(unused_mut)]
    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev: Hash32::zero(),
        tx_merkle_root: tx_merkle_root(&txs),
        commitment_root,
        timestamp: GENESIS_TIMESTAMP,
        bits: GENESIS_BITS,
        nonce: GENESIS_NONCE,
    };

    #[cfg(feature = "dev-pow")]
    let genesis = Block {
        header: header.clone(),
        txs: txs.clone(),
    };

    #[cfg(not(feature = "dev-pow"))]
    let genesis = loop {
        let candidate = Block {
            header: header.clone(),
            txs: txs.clone(),
        };

        if validate_block_with_prev_bits(GENESIS_BITS, None, &candidate).is_ok() {
            break candidate;
        }

        header.nonce = header.nonce.wrapping_add(1);
    };

    let hash = block_hash(&genesis);
    let expected = Hash32::from(GENESIS_HASH_BYTES);
    assert_eq!(hash, expected, "genesis hash must match hardcoded constant");

    let mut state = LedgerState::new();
    apply_and_print(height0, &mut state, &genesis);
    genesis
}

/// Build and mine a block.
fn build_block(
    prev_hash: Hash32,
    _prev_bits: u32,
    _median_time_past: u64,
    chain: &ChainStore,
    txs: Vec<Transaction>,
    bits: u32,
) -> Block {
    let commitment_root = chain
        .preview_commitment_root(prev_hash, &txs)
        .expect("state preview must succeed");

    #[allow(unused_mut)]
    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev: prev_hash,
        tx_merkle_root: tx_merkle_root(&txs),
        commitment_root,
        // Timestamp must be: max(current_time, MTP + 1)
        // This prevents both time-warp attacks and mining failures when genesis is in the future.
        timestamp: {
            let now = current_time();
            let min_time = _median_time_past.saturating_add(1);
            now.max(min_time)
        },
        bits,
        nonce: 0,
    };

    #[cfg(feature = "dev-pow")]
    {
        let _ = (_prev_bits, _median_time_past);
        return Block { header, txs };
    }

    #[cfg(not(feature = "dev-pow"))]
    let (prev_bits, median_time_past) = (_prev_bits, _median_time_past);

    #[cfg(not(feature = "dev-pow"))]
    loop {
        let candidate = Block {
            header: header.clone(),
            txs: txs.clone(),
        };

        if validate_block_with_prev_bits(prev_bits, Some(median_time_past), &candidate).is_ok() {
            return candidate;
        }

        header.nonce = header.nonce.wrapping_add(1);
    }
}

/// Apply a block to state and print status.
fn apply_and_print(height: u64, state: &mut LedgerState, block: &Block) {
    state
        .apply_block(height, block)
        .expect("block must apply cleanly");

    let hash = block_hash(block);

    let coinbase = &block.txs[0];
    println!(
        "Block {:>4} | hash={} | commitments={} | subsidy={} | fees={}",
        height,
        hash,
        state.commitment_len(),
        coinbase.claimed_subsidy.atoms(),
        coinbase.claimed_fees.atoms()
    );
}

/// Deterministic devnet coinbase transaction (unique per height).
///
/// Pre-zk v0: we cannot verify amounts inside commitments yet, so coinbase carries
/// explicit claims (subsidy + fee total). State enforces these exactly.
fn coinbase_tx(height: u64, fees: Amount, subsidy: Amount, miner_pk_hash: [u8; 20]) -> Transaction {
    Transaction {
        version: PROTOCOL_VERSION,
        kind: TransactionKind::Coinbase,
        transparent_inputs: vec![],
        transparent_outputs: vec![nulla_core::TransparentOutput {
            value: subsidy.checked_add(fees).unwrap_or(Amount::zero()),
            pubkey_hash: miner_pk_hash,
        }],
        anchor_root: Hash32::zero(),
        nullifiers: vec![],
        outputs: vec![coinbase_commitment(height)],
        fee: Amount::zero(),
        claimed_subsidy: subsidy,
        claimed_fees: fees,
        proof: vec![],
        memo: vec![],
    }
}

/// Height-unique commitment for coinbase output.
fn coinbase_commitment(height: u64) -> Commitment {
    let mut bytes = [0u8; 32];
    bytes[8..16].copy_from_slice(&height.to_le_bytes());
    Commitment(bytes)
}

/// Compute transaction merkle root using a proper Merkle tree construction.
///
/// Uses a binary tree with hash(left || right) for internal nodes.
/// This prevents transaction reordering and cancellation attacks that
/// would be possible with XOR-based schemes.
fn tx_merkle_root(txs: &[Transaction]) -> Hash32 {
    if txs.is_empty() {
        return Hash32::zero();
    }

    // Collect leaf hashes (txids).
    let mut hashes: Vec<Hash32> = txs
        .iter()
        .map(|tx| txid(tx).expect("txid must succeed"))
        .collect();

    // Build Merkle tree bottom-up.
    while hashes.len() > 1 {
        let mut next_level = Vec::new();

        for i in (0..hashes.len()).step_by(2) {
            if i + 1 < hashes.len() {
                // Hash pair: H(left || right)
                let combined = merkle_parent_hash(&hashes[i], &hashes[i + 1]);
                next_level.push(combined);
            } else {
                // Odd number of nodes: duplicate the last hash (Bitcoin-style).
                let combined = merkle_parent_hash(&hashes[i], &hashes[i]);
                next_level.push(combined);
            }
        }

        hashes = next_level;
    }

    hashes[0]
}

/// Compute the parent hash for a Merkle tree node.
fn merkle_parent_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"NULLA::MERKLE::V0");
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    Hash32(out)
}

/// Compute a block hash from its header.
fn block_hash(block: &Block) -> Hash32 {
    block_header_hash(&block.header).expect("header hash must succeed")
}

#[allow(dead_code)]
fn submit_tx_to_node(
    chain: &Arc<Mutex<ChainStore>>,
    mempool: &Arc<Mutex<Mempool>>,
    p2p: Option<&Arc<Mutex<P2pEngine>>>,
    tx: Transaction,
) -> Result<Hash32, MempoolSubmitError> {
    let chain_guard = chain.lock().expect("chain lock");
    let mut pool = mempool.lock().expect("mempool lock");
    let txid = pool.submit_tx(&*chain_guard, tx)?;
    if let Some(net) = p2p {
        let guard = net.lock().expect("p2p");
        guard.broadcast(Message::InvTx(vec![txid]));
    }
    Ok(txid)
}

fn decode_address(addr: &str) -> Result<[u8; 20], String> {
    let bytes = b58decode(addr).into_vec().map_err(|e| e.to_string())?;
    if bytes.len() != 1 + 20 + 4 {
        return Err("invalid address length".into());
    }
    if bytes[0] != ADDRESS_PREFIX {
        return Err("invalid address prefix".into());
    }
    let (payload, checksum) = bytes.split_at(1 + 20);
    let mut expected = [0u8; 4];
    expected.copy_from_slice(&checksum4(payload));
    if expected != checksum[0..4] {
        return Err("checksum mismatch".into());
    }
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&payload[1..]);
    Ok(h160)
}

fn checksum4(data: &[u8]) -> [u8; 4] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    let mut out = [0u8; 4];
    h.finalize_xof().fill(&mut out);
    out
}

fn drain_local_submissions(
    db_path: &PathBuf,
    chain: &Arc<Mutex<ChainStore>>,
    mempool: &Arc<Mutex<Mempool>>,
) {
    let submit_dir = db_path.join("tx-submissions");
    if let Err(e) = fs::create_dir_all(&submit_dir) {
        eprintln!("warn: cannot create submission dir: {e}");
        return;
    }
    let entries = match fs::read_dir(&submit_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("tx") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let tx: Transaction = match borsh::BorshDeserialize::try_from_slice(&bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let res = submit_tx_to_node(chain, mempool, None, tx);
        if res.is_ok() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Current UNIX time (seconds).
fn current_time() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}

/// Best-effort local IPv4 discovery for NAT mapping when listening on 0.0.0.0.
fn detect_local_ipv4() -> Option<std::net::Ipv4Addr> {
    // No packets are sent; connect() is used to ask the OS for the outbound interface.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(("8.8.8.8", 53)).ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}

fn render_progress_bar(width: usize, fraction: f64) -> String {
    let clamped = fraction.max(0.0).min(1.0);
    let filled = (clamped * width as f64).round() as usize;
    let mut out = String::with_capacity(width + 2);
    out.push('[');
    for i in 0..width {
        if i < filled {
            out.push('#');
        } else {
            out.push('.');
        }
    }
    out.push(']');
    out
}

/// Attempt to open the P2P listen port via UPnP/NAT-PMP (best-effort, opt-in).
fn maybe_open_nat(listen: &SocketAddr) {
    let external_port = listen.port();
    let internal_port = listen.port();
    let internal_ip = match listen.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        std::net::IpAddr::V4(_) => detect_local_ipv4(),
        std::net::IpAddr::V6(_) => {
            eprintln!("nat: IPv6 listen addr not supported for UPnP/NAT-PMP");
            return;
        }
    };
    let Some(internal_ip) = internal_ip else {
        eprintln!("nat: could not determine a local IPv4 address; skipping UPnP/NAT-PMP");
        return;
    };
    println!(
        "nat: attempting port map for {} -> {}:{}",
        external_port, internal_ip, internal_port
    );
    // Try UPnP via igd.
    match igd::search_gateway(Default::default()) {
        Ok(gw) => {
            let internal = std::net::SocketAddrV4::new(internal_ip, internal_port);
            match gw.add_port(
                igd::PortMappingProtocol::TCP,
                external_port,
                internal,
                3600,
                "nulla-node",
            ) {
                Ok(_) => println!("nat: UPnP port map established on {}", external_port),
                Err(e) => eprintln!("nat: UPnP port map failed: {e}"),
            }
        }
        Err(e) => eprintln!("nat: gateway search failed: {e}"),
    }
}

fn resolve_config(cli: Config) -> ResolvedConfig {
    let listen = cli
        .listen
        .or_else(|| env::var("NULLA_LISTEN").ok())
        .unwrap_or_else(|| "0.0.0.0:27444".to_string())
        .parse()
        .expect("invalid listen address");

    let peers_raw = cli
        .peers
        .or_else(|| env::var("NULLA_PEERS").ok())
        .unwrap_or_default();
    let peers = peers_raw
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| s.trim().parse().ok())
        .collect::<Vec<_>>();

    // Track whether the user explicitly provided seeds (env or CLI). An empty string should
    // disable the baked-in defaults, so we only fall back to hardcoded seeds if nothing was
    // specified at all.
    let seeds_env = env::var("NULLA_SEEDS");
    let seeds_provided = cli.seeds.is_some() || seeds_env.is_ok();
    let seeds_raw = cli.seeds.or_else(|| seeds_env.ok()).unwrap_or_default();
    let mut seeds = seeds_raw
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| s.trim().parse().ok())
        .collect::<Vec<_>>();
    // If no seeds/peers are provided, fall back to default public seeds.
    if !seeds_provided && seeds.is_empty() && peers.is_empty() {
        for s in &[
            "45.155.53.102:27444",
            "45.155.53.112:27444",
            "45.155.53.126:27444",
        ] {
            if let Ok(addr) = s.parse() {
                seeds.push(addr);
            }
        }
    }
    // Optional seed URL fetch (JSON array of strings).
    if let Some(url) = cli.seed_url.or_else(|| env::var("NULLA_SEED_URL").ok()) {
        if let Ok(resp) = blocking::get(&url).and_then(|r| r.error_for_status()) {
            if let Ok(list) = resp.json::<Vec<String>>() {
                for entry in list {
                    if let Ok(addr) = entry.parse() {
                        seeds.push(addr);
                    } else {
                        eprintln!("warn: skipping invalid seed from URL: {entry}");
                    }
                }
            } else {
                eprintln!("warn: could not parse seed list from {url}");
            }
        } else {
            eprintln!("warn: failed to fetch seeds from {url}");
        }
    }

    let bootstrap_listen = cli
        .bootstrap_listen
        .or_else(|| env::var("NULLA_BOOTSTRAP_LISTEN").ok())
        .and_then(|s| s.parse().ok());
    let relay_listen = cli
        .relay_listen
        .or_else(|| env::var("NULLA_RELAY_LISTEN").ok())
        .and_then(|s| s.parse().ok());
    let relay_target = cli
        .relay_target
        .or_else(|| env::var("NULLA_RELAY_TARGET").ok())
        .and_then(|s| s.parse().ok());
    let relay_auto = cli.relay_auto || env::var("NULLA_RELAY_AUTO").is_ok();
    let relay_cap = cli
        .relay_cap
        .or_else(|| {
            env::var("NULLA_RELAY_CAP")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0);
    let request_relay = cli.request_relay || env::var("NULLA_REQUEST_RELAY").is_ok();

    // Drop any self-references to avoid self-dial/loopback attempts.
    let listen_addr = listen;
    let peers = peers
        .into_iter()
        .filter(|p| p != &listen_addr)
        .collect::<Vec<_>>();
    let seeds = seeds
        .into_iter()
        .filter(|s| s != &listen_addr)
        .collect::<Vec<_>>();

    let db_path = cli
        .db
        .or_else(|| env::var("NULLA_DB").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("nulla.chain.db"));
    let mut p2p_db_path = db_path.clone();
    p2p_db_path.set_extension("p2p.db");

    let reorg_cap = cli
        .reorg_cap
        .or_else(|| {
            env::var("NULLA_REORG_CAP")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(100);

    let (miner_pubkey_hash, miner_addr_b58) = if let Some(addr) = cli
        .miner_address
        .or_else(|| env::var("NULLA_MINER_ADDRESS").ok())
    {
        let h = decode_address(&addr).expect("invalid miner address");
        (h, addr)
    } else {
        eprintln!("warn: miner address not set; coinbase will burn rewards");
        ([0u8; 20], format!("burn({:02x}...)", ADDRESS_PREFIX))
    };

    // mining opt-in: --mine or NULLA_MINE; disabled if --no-mine or NULLA_NO_MINE
    // Role shortcuts: seed/follower => no mining, miner => mining unless explicitly disabled.
    let role = cli.role.as_deref().map(|r| r.to_ascii_lowercase());
    let mut mining_enabled = cli.mine || env::var("NULLA_MINE").is_ok();
    if let Some(r) = role.as_deref() {
        match r {
            "seed" | "follower" => mining_enabled = false,
            "miner" => mining_enabled = true,
            other => eprintln!("warn: unknown role '{other}', ignoring"),
        }
    }
    if cli.no_mine || env::var("NULLA_NO_MINE").is_ok() {
        mining_enabled = false;
    }

    // gossip default on; allow disable via flag/env.
    let mut gossip_enabled = true;
    if cli.no_gossip || env::var("NULLA_NO_GOSSIP").is_ok() {
        gossip_enabled = false;
    } else if cli.gossip || env::var("NULLA_GOSSIP").is_ok() {
        gossip_enabled = true;
    }

    ResolvedConfig {
        listen,
        peers,
        seeds,
        bootstrap_listen,
        relay_listen,
        relay_target,
        relay_auto,
        relay_cap,
        request_relay,
        db_path,
        p2p_db_path,
        reorg_cap,
        miner_pubkey_hash,
        miner_addr_b58,
        mining_enabled,
        mine_while_behind: cli.mine_while_behind || env::var("NULLA_MINE_WHILE_BEHIND").is_ok(),
        nat_enabled: cli.nat || env::var("NULLA_NAT").is_ok(),
        gossip_enabled,
        node_id: {
            let mut id = [0u8; 32];
            rand::thread_rng().fill(&mut id);
            Hash32::from(id)
        },
    }
}

struct ResolvedConfig {
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    seeds: Vec<SocketAddr>,
    bootstrap_listen: Option<SocketAddr>,
    relay_listen: Option<SocketAddr>,
    relay_target: Option<SocketAddr>,
    relay_auto: bool,
    relay_cap: u32,
    request_relay: bool,
    db_path: PathBuf,
    p2p_db_path: PathBuf,
    reorg_cap: u64,
    miner_pubkey_hash: [u8; 20],
    miner_addr_b58: String,
    mining_enabled: bool,
    mine_while_behind: bool,
    nat_enabled: bool,
    gossip_enabled: bool,
    node_id: Hash32,
}

fn compute_best_chain_and_missing(db: &ChainDb) -> (Hash32, Vec<Hash32>, Vec<Hash32>) {
    let best = db
        .best_tip_by_work()
        .expect("best tip lookup")
        .unwrap_or_else(|| Hash32::from(GENESIS_HASH_BYTES));
    let chain = db.chain_from_tip(best).expect("chain walk");
    let missing = db.missing_blocks_on_chain(&chain).expect("missing check");
    (best, chain, missing)
}

fn wait_for_missing(db: &ChainDb, chain: &[Hash32], timeout: Duration) {
    let start = std::time::Instant::now();
    loop {
        let missing = db.missing_blocks_on_chain(chain).unwrap_or_default();
        if missing.is_empty() || start.elapsed() >= timeout {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn start_bootstrap_server(
    p2p: Arc<Mutex<P2pEngine>>,
    listen: SocketAddr,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = match TcpListener::bind(listen) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bootstrap: failed to bind {listen}: {e}");
                return;
            }
        };
        loop {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let req_line = String::from_utf8_lossy(&buf);
                let ok = req_line.starts_with("GET /peers");
                if !ok {
                    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length:0\r\n\r\n");
                    continue;
                }
                let addrs: Vec<String> = {
                    let eng = p2p.lock().ok();
                    if let Some(eng) = eng {
                        let mut set = HashSet::new();
                        for p in eng.peers_snapshot() {
                            set.insert(p.addr);
                        }
                        for a in eng.addr_book_snapshot() {
                            set.insert(a);
                        }
                        set.into_iter().take(512).map(|a| a.to_string()).collect()
                    } else {
                        Vec::new()
                    }
                };
                let body = serde_json::to_vec(&addrs).unwrap_or_else(|_| b"[]".to_vec());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body);
            }
        }
    })
}

/// Very simple TCP relay/proxy: accepts connections on `listen`, connects to `target`, and pipes bytes.
/// Intended for seed-only use to help a few NAT'd peers; not a consensus component.
fn start_relay_proxy(listen: SocketAddr, target: SocketAddr) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = match TcpListener::bind(listen) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("relay: failed to bind {listen}: {e}");
                return;
            }
        };
        for inbound in listener.incoming().flatten() {
            let target_addr = target;
            thread::spawn(move || {
                match TcpStream::connect(target_addr) {
                    Ok(mut outbound) => {
                        if let (Ok(mut inbound_r), Ok(mut inbound_w)) =
                            (inbound.try_clone(), inbound.try_clone())
                        {
                            if let Ok(mut outbound_w) = outbound.try_clone() {
                                // pipe inbound -> outbound
                                let t1 = thread::spawn(move || {
                                    let _ = std::io::copy(&mut inbound_r, &mut outbound_w);
                                });
                                // pipe outbound -> inbound
                                let _ = std::io::copy(&mut outbound, &mut inbound_w);
                                let _ = t1.join();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("relay: failed to connect to target {target_addr}: {e}");
                    }
                }
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dev-pow")]
    use nulla_consensus::{bits_to_target, target_to_bits};
    use serde_json::json;
    use tempfile;
    #[cfg(feature = "dev-pow")]
    use tempfile::tempdir;

    #[test]
    fn genesis_hash_matches_constant() {
        let genesis = build_genesis();
        let hash = block_hash(&genesis);
        let expected = Hash32::from(GENESIS_HASH_BYTES);
        assert_eq!(hash, expected, "update GENESIS_HASH_BYTES");
    }

    #[test]
    #[cfg(feature = "dev-pow")]
    fn print_genesis_hash_for_debug() {
        let genesis = build_genesis();
        let hash = block_hash(&genesis);
        println!("genesis_hash={hash:?}");
    }

    #[test]
    #[cfg(not(feature = "dev-pow"))]
    fn print_genesis_hash_and_nonce_for_debug() {
        let genesis = build_genesis();
        let hash = block_hash(&genesis);
        println!(
            "genesis_hash={hash:?} nonce={} tx_merkle_root={:?} commitment_root={:?}",
            genesis.header.nonce, genesis.header.tx_merkle_root, genesis.header.commitment_root
        );
    }

    #[test]
    #[ignore]
    fn print_pow_vectors() {
        let genesis = build_genesis();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let mut chain = ChainStore::load_or_init(&path, genesis.clone()).unwrap();
        let mut vectors = Vec::new();

        let mut push_vec = |name: &str, block: &Block, height: u64| {
            let ser = borsh::to_vec(&block.header).expect("borsh");
            let hash = block_hash(block);
            let v = json!({
                "name": name,
                "header": {
                    "version": block.header.version,
                    "prev": hex::encode(block.header.prev.as_bytes()),
                    "tx_merkle_root": hex::encode(block.header.tx_merkle_root.as_bytes()),
                    "commitment_root": hex::encode(block.header.commitment_root.as_bytes()),
                    "timestamp": block.header.timestamp,
                    "bits": block.header.bits,
                    "nonce": block.header.nonce,
                    "height": height
                },
                "serialized_hex": hex::encode(&ser),
                "header_hash_hex": hex::encode(hash.as_bytes()),
            });
            vectors.push(v);
        };

        push_vec("genesis", &genesis, 0);

        let mut _state = chain.rebuild_state();
        for height in 1u64..=12 {
            let coinbase = coinbase_tx(height, Amount::zero(), block_subsidy(height), [0u8; 20]);
            let prev = chain.best_hash();
            let prev_bits = chain.best_bits();
            let mtp = chain.median_time_past(prev).unwrap_or(GENESIS_TIMESTAMP);
            let mut block = build_block(prev, prev_bits, mtp, &chain, vec![coinbase], DEVNET_BITS);
            block.header.timestamp = GENESIS_TIMESTAMP + height;
            chain.insert_block(block.clone()).unwrap();
            _state = chain.rebuild_state();
            if height == 1 {
                push_vec("height1", &block, height);
            }
            if height == 12 {
                push_vec("height12", &block, height);
            }
        }

        println!("{}", serde_json::to_string_pretty(&json!(vectors)).unwrap());
    }

    #[cfg(feature = "dev-pow")]
    mod chain_integration {
        use super::*;

        fn new_chain(genesis: Block) -> (ChainStore, tempfile::TempDir) {
            let dir = tempdir().unwrap();
            let path = dir.path().join("db");
            let chain = ChainStore::load_or_init(&path, genesis).unwrap();
            (chain, dir)
        }

        fn build_child(chain: &ChainStore, prev: Hash32, bits: u32, height: u64) -> Block {
            let prev_entry = chain.entry(&prev).unwrap();
            let prev_bits = prev_entry.block.header.bits;
            let mtp = chain.median_time_past(prev).unwrap();
            let coinbase = coinbase_tx(height, Amount::zero(), block_subsidy(height), [0u8; 20]);
            let mut block = build_block(prev, prev_bits, mtp, chain, vec![coinbase], bits);
            block.header.timestamp = prev_entry.block.header.timestamp + 1;
            block
        }

        #[test]
        fn clamp_rejects_high_height() {
            let genesis = build_genesis();
            let (mut chain, _tmp) = new_chain(genesis);

            let prev_bits = chain.best_bits();
            let prev_target = bits_to_target(prev_bits).unwrap();
            let too_easy_target = &prev_target * 2u32;
            let too_easy_bits = target_to_bits(&too_easy_target).unwrap();

            let block = build_child(&chain, chain.best_hash(), too_easy_bits, 1);
            let err = chain.insert_block(block).expect_err("clamp must reject");
            assert!(
                err.contains("InvalidTarget"),
                "expected clamp rejection, got {err}"
            );
            assert_eq!(chain.best_entry().height, 0);
        }

        #[test]
        fn shorter_higher_work_beats_longer_lower_work() {
            let genesis = build_genesis();
            let (mut chain, _tmp) = new_chain(genesis);
            let prev_bits = chain.best_bits();
            let prev_target = bits_to_target(prev_bits).unwrap();

            // Easier (within clamp) branch: 2 blocks.
            let easy_target = &prev_target * 120u32 / 100u32;
            let easy_bits = target_to_bits(&easy_target).unwrap();
            let a1 = build_child(&chain, chain.best_hash(), easy_bits, 1);
            chain.insert_block(a1.clone()).unwrap();
            let a1_hash = block_hash(&a1);
            let a2 = build_child(&chain, a1_hash, easy_bits, 2);
            chain.insert_block(a2.clone()).unwrap();

            // Harder branch: 1 block but much more work.
            let hard_target = &prev_target / 2u32;
            let hard_bits = target_to_bits(&hard_target).unwrap();
            let b1 = build_child(&chain, Hash32::from(GENESIS_HASH_BYTES), hard_bits, 1);
            let b1_hash = block_hash(&b1);
            chain.insert_block(b1).unwrap();

            assert_eq!(chain.best_hash(), b1_hash, "harder but shorter must win");

            // Tie-break deterministic: add another block with same work; lower hash wins.
            let c1 = build_child(&chain, Hash32::from(GENESIS_HASH_BYTES), hard_bits, 1);
            let c1_hash = block_hash(&c1);
            chain.insert_block(c1).unwrap();
            assert_eq!(
                chain.best_hash(),
                if c1_hash.as_bytes() < b1_hash.as_bytes() {
                    c1_hash
                } else {
                    b1_hash
                }
            );
        }

        #[test]
        fn reorg_rebuilds_state() {
            let genesis = build_genesis();
            let (mut chain, _tmp) = new_chain(genesis);
            let prev_bits = chain.best_bits();
            let prev_target = bits_to_target(prev_bits).unwrap();
            let hard_target = &prev_target / 2u32;
            let hard_bits = target_to_bits(&hard_target).unwrap();

            // Build two competing branches.
            let easy_target = &prev_target * 120u32 / 100u32;
            let easy_bits = target_to_bits(&easy_target).unwrap();
            let a1 = build_child(&chain, chain.best_hash(), easy_bits, 1);
            chain.insert_block(a1.clone()).unwrap();
            let a2 = build_child(&chain, block_hash(&a1), easy_bits, 2);
            chain.insert_block(a2).unwrap();

            // Harder single-block branch should reorg.
            let b1 = build_child(&chain, Hash32::from(GENESIS_HASH_BYTES), hard_bits, 1);
            chain.insert_block(b1).unwrap();

            let state = chain.rebuild_state();
            assert_eq!(
                state.commitment_len(),
                2,
                "best chain (genesis + b1) must be applied"
            );
        }
    }
}
