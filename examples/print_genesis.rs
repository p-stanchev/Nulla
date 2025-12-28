// Print genesis block details
use nulla_core::*;
use nulla_state::LedgerState;

fn main() {
    let txs = vec![coinbase_tx(0, Amount::from_atoms(800_000_000))];
    let state = LedgerState::new();
    let commitment_root = state.preview_root_after(&txs).expect("preview genesis root");

    let tx_merkle_root = tx_merkle_root_for_genesis(&txs);

    println!("tx_merkle_root: {}", hex::encode(tx_merkle_root.as_bytes()));
    println!("commitment_root: {}", hex::encode(commitment_root.as_bytes()));
}

fn coinbase_tx(height: u64, subsidy: Amount) -> Transaction {
    Transaction {
        version: PROTOCOL_VERSION,
        kind: TransactionKind::Coinbase,
        transparent_inputs: vec![],
        transparent_outputs: vec![TransparentOutput {
            value: subsidy,
            pubkey_hash: [0u8; 20],
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

    let mut hashes: Vec<Hash32> = txs
        .iter()
        .map(|tx| txid(tx).expect("txid"))
        .collect();

    while hashes.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..hashes.len()).step_by(2) {
            if i + 1 < hashes.len() {
                let combined = merkle_parent_hash(&hashes[i], &hashes[i + 1]);
                next_level.push(combined);
            } else {
                let combined = merkle_parent_hash(&hashes[i], &hashes[i]);
                next_level.push(combined);
            }
        }
        hashes = next_level;
    }

    hashes[0]
}

fn merkle_parent_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"NULLA::MERKLE::V0");
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    Hash32(out)
}
