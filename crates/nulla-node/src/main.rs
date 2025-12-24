#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use std::thread;
use std::time::Duration;

use nulla_core::{
    block_header_hash, txid, Amount, Block, BlockHeader, Commitment, Hash32, Transaction,
    TransactionKind, PROTOCOL_VERSION,
};
use nulla_consensus::validate_block_consensus;
use nulla_state::{block_subsidy, LedgerState};

/// Extremely easy difficulty for devnet.
const DEVNET_BITS: u32 = 0x207fffff;

fn main() {
    println!("Starting Nulla minimal miner…");

    let mut state = LedgerState::new();

    // -----------------
    // Genesis block
    // -----------------
    let height0 = 0u64;
    let coinbase0 = coinbase_tx(height0, Amount::zero(), block_subsidy(height0));

    let genesis = build_block(Hash32::zero(), &state, vec![coinbase0], DEVNET_BITS);
    apply_and_print(height0, &mut state, &genesis);
    let mut prev_hash = block_hash(&genesis);

    // -----------------
    // Main mining loop
    // -----------------
    for height in 1u64.. {
        // v0 devnet: no mempool yet, only coinbase.
        let fees = Amount::zero();
        let subsidy = block_subsidy(height);

        let coinbase = coinbase_tx(height, fees, subsidy);
        let block = build_block(prev_hash, &state, vec![coinbase], DEVNET_BITS);

        apply_and_print(height, &mut state, &block);
        prev_hash = block_hash(&block);

        thread::sleep(Duration::from_secs(1));
    }
}

/// Build and mine a block.
fn build_block(prev: Hash32, state: &LedgerState, txs: Vec<Transaction>, bits: u32) -> Block {
    let commitment_root = state
        .preview_root_after(&txs)
        .expect("state preview must succeed");

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev,
        tx_merkle_root: tx_merkle_root(&txs),
        commitment_root,
        timestamp: current_time(),
        bits,
        nonce: 0,
    };

    loop {
        let candidate = Block {
            header: header.clone(),
            txs: txs.clone(),
        };

        if validate_block_consensus(&candidate).is_ok() {
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
/// Pre-zk v0: we can’t verify amounts inside commitments yet, so coinbase carries
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
