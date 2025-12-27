// Utility to mine the new genesis block for 2026-01-01
use nulla_core::*;
use nulla_state::LedgerState;
use nulla_consensus::bits_to_target;
use num_bigint::BigUint;

fn main() {
    println!("Mining genesis block for January 1st, 2026...");
    println!("Target timestamp: {} ({})", GENESIS_TIMESTAMP, "2026-01-01 00:00:00 UTC");

    let txs = vec![coinbase_tx(0, Amount::from_atoms(800_000_000))];
    let state = LedgerState::new();
    let commitment_root = state.preview_root_after(&txs).expect("preview genesis root");

    let tx_merkle_root = tx_merkle_root_for_genesis(&txs);

    println!("tx_merkle_root: {}", hex::encode(tx_merkle_root.as_bytes()));
    println!("commitment_root: {}", hex::encode(commitment_root.as_bytes()));

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev: Hash32::zero(),
        tx_merkle_root,
        commitment_root,
        timestamp: GENESIS_TIMESTAMP,
        bits: GENESIS_BITS,
        nonce: 0,
    };

    let target = bits_to_target(GENESIS_BITS).expect("valid bits");
    println!("Mining with difficulty bits: 0x{:08x}", GENESIS_BITS);
    println!("Target: {}", hex::encode(target.to_bytes_be()));
    println!("\nMining... (this may take a few minutes)\n");

    let start = std::time::Instant::now();
    let mut attempts = 0u64;

    loop {
        header.nonce = attempts;

        if let Ok(hash) = block_header_hash(&header) {
            let hash_bytes = hash.as_bytes();
            let hash_int = BigUint::from_bytes_be(hash_bytes);

            if hash_int <= target {
                println!("\n✓ Found valid genesis block!");
                println!("Nonce: {}", header.nonce);
                println!("Hash: {}", hex::encode(hash_bytes));
                println!("Time: {:.2}s", start.elapsed().as_secs_f64());
                println!("Hashrate: {:.2} H/s", attempts as f64 / start.elapsed().as_secs_f64());

                println!("\n==================================================");
                println!("Update crates/nulla-core/src/constants.rs with:");
                println!("==================================================\n");
                println!("pub const GENESIS_NONCE: u64 = {};", header.nonce);
                println!("pub const GENESIS_HASH_BYTES: [u8; HASH32_LEN] = [");
                for (i, byte) in hash_bytes.iter().enumerate() {
                    if i % 15 == 0 {
                        print!("    ");
                    }
                    print!("0x{:02x},", byte);
                    if (i + 1) % 15 == 0 && i < hash_bytes.len() - 1 {
                        println!();
                    } else if i < hash_bytes.len() - 1 {
                        print!(" ");
                    }
                }
                println!("\n];");
                break;
            }
        }

        attempts += 1;
        if attempts % 100_000 == 0 {
            print!("\rAttempts: {} ({:.2} H/s)    ", attempts, attempts as f64 / start.elapsed().as_secs_f64());
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
        }
    }
}

fn coinbase_tx(height: u64, subsidy: Amount) -> Transaction {
    Transaction {
        version: PROTOCOL_VERSION,
        kind: TransactionKind::Coinbase,
        transparent_inputs: vec![],
        transparent_outputs: vec![TransparentOutput {
            value: subsidy,
            pubkey_hash: [0u8; 20], // Burn address for genesis
        }],
        anchor_root: Hash32::zero(),
        nullifiers: vec![],
        outputs: vec![coinbase_commitment(height)],
        fee: Amount::zero(),
        claimed_subsidy: subsidy,
        claimed_fees: Amount::zero(),
        proof: vec![],
        memo: vec![],
    }
}

fn coinbase_commitment(height: u64) -> Commitment {
    let mut bytes = [0u8; 32];
    bytes[8..16].copy_from_slice(&height.to_le_bytes());
    Commitment(bytes)
}

fn tx_merkle_root_for_genesis(txs: &[Transaction]) -> Hash32 {
    if txs.is_empty() {
        return Hash32::zero();
    }
    let mut out = [0u8; 32];
    for tx in txs {
        let id = txid(tx).expect("txid");
        for i in 0..32 {
            out[i] ^= id.as_bytes()[i];
        }
    }
    Hash32(out)
}
