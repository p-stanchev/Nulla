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
    let mut acc = Hash32::zero();
    for tx in txs {
        let h = txid(tx).expect("txid");
        acc = xor_hash(acc, h);
    }
    acc
}

fn xor_hash(a: Hash32, b: Hash32) -> Hash32 {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
    }
    Hash32(out)
}
