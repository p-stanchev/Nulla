use nulla_consensus::{
    bits_to_target, target_to_bits, tip_is_better, validate_block_with_prev_bits, work_from_bits,
};
use nulla_core::{Amount, Block, BlockHeader, Commitment, Hash32, Transaction, TransactionKind, PROTOCOL_VERSION};
use time::OffsetDateTime;

fn coinbase(height: u64) -> Transaction {
    Transaction {
        version: PROTOCOL_VERSION,
        kind: TransactionKind::Coinbase,
        transparent_inputs: vec![],
        transparent_outputs: vec![],
        anchor_root: Hash32::zero(),
        nullifiers: vec![],
        outputs: vec![Commitment::zero()],
        fee: Amount::zero(),
        claimed_subsidy: Amount::from_atoms(height),
        claimed_fees: Amount::zero(),
        proof: vec![],
        memo: vec![],
    }
}

fn make_block(prev: Hash32, bits: u32, timestamp: u64) -> Block {
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            prev,
            tx_merkle_root: Hash32::zero(),
            commitment_root: Hash32::zero(),
            timestamp,
            bits,
            nonce: 0,
        },
        txs: vec![coinbase(timestamp)],
    }
}

fn mine_valid(mut block: Block, prev_bits: u32, mtp: u64) -> Block {
    for _ in 0..1_000_000u64 {
        if validate_block_with_prev_bits(prev_bits, Some(mtp), &block).is_ok() {
            return block;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    panic!("failed to mine test block");
}

#[test]
fn clamp_rejects_easier_fork_even_if_higher() {
    let prev_bits = 0x207f_ffff;
    let prev_hash = Hash32([1u8; 32]);
    let now =  OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;

    // Violates clamp by doubling target.
    let too_easy_target = bits_to_target(prev_bits).unwrap() * 2u32;
    let too_easy_bits = target_to_bits(&too_easy_target).unwrap();
    let bad_block = make_block(prev_hash, too_easy_bits, now);
    let err = validate_block_with_prev_bits(prev_bits, Some(now.saturating_sub(1)), &bad_block)
        .expect_err("must fail clamp");
    assert!(matches!(err, nulla_consensus::ConsensusError::InvalidTarget));

    // Valid block within clamp.
    let ok_target = bits_to_target(prev_bits).unwrap() * 120u32 / 100u32;
    let ok_bits = target_to_bits(&ok_target).unwrap();
    let ok_block = make_block(prev_hash, ok_bits, now);
    let mined = mine_valid(ok_block, prev_bits, now.saturating_sub(1));
    validate_block_with_prev_bits(prev_bits, Some(now.saturating_sub(1)), &mined)
        .expect("within clamp + pow");
}

#[test]
fn heaviest_work_wins_and_tie_breaks_by_hash() {
    let easy_work = work_from_bits(0x207f_ffff).unwrap();
    let hard_work = work_from_bits(0x1e00_ffff).unwrap(); // harder -> more work

    let hash_low = Hash32([0u8; 32]);
    let hash_high = Hash32([1u8; 32]);

    // Harder chain wins even if "shorter".
    assert!(tip_is_better(&hard_work, &hash_high, &easy_work, &hash_low));

    // Equal work: lowest hash wins.
    assert!(tip_is_better(&easy_work, &hash_low, &easy_work, &hash_high));
}
