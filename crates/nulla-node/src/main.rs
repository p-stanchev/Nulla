#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod chain_store;

use std::env;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chain_store::ChainStore;
#[allow(unused_imports)]
use nulla_consensus::validate_block_with_prev_bits;
use nulla_core::{
    block_header_hash, txid, Amount, Block, BlockHeader, Commitment, Hash32, Transaction,
    TransactionKind, ADDRESS_PREFIX, CHAIN_ID, GENESIS_BITS, GENESIS_HASH_BYTES, GENESIS_NONCE,
    GENESIS_TIMESTAMP, NETWORK_MAGIC, PROTOCOL_VERSION,
};
use nulla_state::{block_subsidy, LedgerState};
use nulla_p2p::net::{Message, P2pEngine};

/// Extremely easy difficulty for devnet.
const DEVNET_BITS: u32 = GENESIS_BITS;

fn main() {
    println!("Starting Nulla minimal miner");
    println!(
        "Chain ID: {CHAIN_ID} | magic: {:?} | addr_prefix: 0x{:x}",
        NETWORK_MAGIC, ADDRESS_PREFIX
    );

    // -----------------
    // Genesis block (height 0)
    // -----------------
    let genesis = build_genesis();
    let genesis_header = genesis.header.clone();
    let db_path = PathBuf::from("nulla.chain.db");
    let chain = ChainStore::load_or_init(&db_path, genesis.clone()).expect("valid genesis/db");
    let chain = Arc::new(Mutex::new(chain));

    // -----------------
    // P2P wiring (authoritative ingress)
    // -----------------
    let p2p_path = PathBuf::from("nulla.p2p.db");
    let mut p2p = P2pEngine::new(&p2p_path, genesis_header).expect("p2p init");
    {
        let chain_for_cb = Arc::clone(&chain);
        p2p.set_block_callback(move |block| {
            let mut chain = chain_for_cb.lock().expect("chain lock");
            let h = block_hash(block);
            if chain.entry(&h).is_none() {
                chain.insert_block(block.clone()).map_err(|e| e)?;
            }
            Ok(())
        });
    }
    let p2p = Arc::new(Mutex::new(p2p));

    let listen_addr: SocketAddr = env::var("NULLA_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:18444".to_string())
        .parse()
        .expect("valid listen address");
    let listener = TcpListener::bind(listen_addr).expect("bind p2p socket");
    let _server = P2pEngine::serve_incoming(Arc::clone(&p2p), listener);

    if let Ok(peers) = env::var("NULLA_PEERS") {
        for peer in peers.split(',').filter(|s| !s.is_empty()) {
            if let Ok(addr) = peer.parse::<SocketAddr>() {
                let _ = P2pEngine::connect_and_sync(Arc::clone(&p2p), addr);
            }
        }
    }

    // -----------------
    // Main mining loop
    // -----------------
    for height in 1u64.. {
        // v0 devnet: no mempool yet, only coinbase.
        let fees = Amount::zero();
        let subsidy = block_subsidy(height);

        let coinbase = coinbase_tx(height, fees, subsidy);
        let (block_for_p2p, state_commitments, best_height, best_hash) = {
            let mut chain_lock = chain.lock().expect("chain lock");
            let prev = chain_lock.best_hash();
            let prev_bits = chain_lock.best_bits();
            let mtp = chain_lock
                .median_time_past(prev)
                .expect("mtp available for non-genesis");

            let block = build_block(prev, prev_bits, mtp, &chain_lock, vec![coinbase], DEVNET_BITS);
            let block_for_store = block.clone();

            chain_lock.insert_block(block).expect("block must validate and attach");
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
            let _ = p2p_guard.handle_message(0, Message::Headers(vec![block_for_p2p.header.clone()]));
            let _ = p2p_guard.handle_message(0, Message::Block(block_for_p2p));
        }

        println!(
            "Block {:>4} | hash={} | height={} | commitments={}",
            best_height,
            best_hash,
            best_height,
            state_commitments
        );

        thread::sleep(Duration::from_secs(1));
    }
}

/// Build and mine the deterministic genesis block.
fn build_genesis() -> Block {
    let height0 = 0u64;
    let coinbase0 = coinbase_tx(height0, Amount::zero(), block_subsidy(height0));
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
    assert_eq!(
        hash, expected,
        "genesis hash must match hardcoded constant"
    );

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
        timestamp: current_time(),
        bits,
        nonce: 0,
    };

    #[cfg(feature = "dev-pow")]
    {
        let _ = (_prev_bits, _median_time_past);
        return Block {
            header,
            txs,
        };
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
fn coinbase_tx(height: u64, fees: Amount, subsidy: Amount) -> Transaction {
    Transaction {
        version: PROTOCOL_VERSION,
        kind: TransactionKind::Coinbase,
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

/// Compute a simple tx merkle root (devnet v0).
fn tx_merkle_root(txs: &[Transaction]) -> Hash32 {
    if txs.is_empty() {
        return Hash32::zero();
    }

    let mut acc = Hash32::zero();
    for tx in txs {
        let h = txid(tx).expect("txid must succeed");
        acc = xor_hash(acc, h);
    }
    acc
}

/// Compute a block hash from its header.
fn block_hash(block: &Block) -> Hash32 {
    block_header_hash(&block.header).expect("header hash must succeed")
}

/// Current UNIX time (seconds).
fn current_time() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}

/// XOR-combine two 32-byte hashes.
fn xor_hash(a: Hash32, b: Hash32) -> Hash32 {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
    }
    Hash32(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile;
    #[cfg(feature = "dev-pow")]
    use nulla_consensus::{bits_to_target, target_to_bits};
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
            let coinbase = coinbase_tx(height, Amount::zero(), block_subsidy(height));
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
            let coinbase = coinbase_tx(height, Amount::zero(), block_subsidy(height));
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
