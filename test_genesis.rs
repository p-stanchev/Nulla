use nulla_core::*;
use nulla_state::LedgerState;

fn main() {
    let txs = vec![coinbase_tx(0, Amount::from_atoms(800_000_000))];
    let state = LedgerState::new();
    let commitment_root = state.preview_root_after(&txs).expect("preview");
    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev: Hash32::zero(),
        tx_merkle_root: Hash32::zero(),
        commitment_root,
        timestamp: GENESIS_TIMESTAMP,
        bits: GENESIS_BITS,
        nonce: GENESIS_NONCE,
    };
    let genesis = Block { header, txs };
    let hash = block_header_hash(&genesis.header).expect("hash");
    
    println!("Generated genesis hash: {}", hex::encode(hash.as_bytes()));
    println!("Expected genesis hash:  {}", hex::encode(&GENESIS_HASH_BYTES));
    println!("Match: {}", hash.as_bytes() == &GENESIS_HASH_BYTES);
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
        outputs: vec![Commitment::zero()],
        fee: Amount::zero(),
        claimed_subsidy: subsidy,
        claimed_fees: Amount::zero(),
        proof: vec![],
        memo: height.to_le_bytes().to_vec(),
    }
}
