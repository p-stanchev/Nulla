// Consensus-critical. Changes require spec update + tests.
//! Consensus validation helpers for blocks and headers.
//!
//! This module does not touch chain state (UTXO/commitments) and does not
//! implement difficulty adjustment. It only validates self-contained
//! header properties and proof-of-work.

use crate::difficulty::enforce_max_difficulty_drop;
use crate::error::ConsensusError;
use crate::pow::validate_pow;
use nulla_core::{Block, BlockHeader, Hash32, PROTOCOL_VERSION};
#[allow(unused_imports)]
use time::OffsetDateTime;

const MAX_FUTURE_DRIFT_SECS: u64 = 2 * 60 * 60;
const MTP_WINDOW: usize = 11;

/// Validate basic header invariants plus timestamp rules (MTP + drift).
pub fn validate_header_sanity(
    header: &BlockHeader,
    median_time_past: Option<u64>,
) -> Result<(), ConsensusError> {
    if header.version != PROTOCOL_VERSION {
        return Err(ConsensusError::InvalidHeader("unsupported header version"));
    }

    // Timestamp must be non-zero.
    if header.timestamp == 0 {
        return Err(ConsensusError::InvalidHeader("timestamp must be non-zero"));
    }

    // Genesis is permitted to have an arbitrary fixed timestamp; skip MTP/drift.
    if header.prev != Hash32::zero() {
        // Enforce MTP rule.
        let mtp = median_time_past.ok_or(ConsensusError::InvalidHeader(
            "missing median-time-past for non-genesis",
        ))?;
        if header.timestamp <= mtp {
            return Err(ConsensusError::InvalidHeader("timestamp below MTP"));
        }

        // Absolute future-drift bound.
        #[cfg(feature = "dev-pow")]
        let now = header.timestamp;

        #[cfg(not(feature = "dev-pow"))]
        let now = OffsetDateTime::now_utc()
            .unix_timestamp()
            .max(0) as u64;

        if !is_timestamp_within_drift(header.timestamp, now, MAX_FUTURE_DRIFT_SECS) {
            return Err(ConsensusError::InvalidHeader(
                "timestamp too far from local time",
            ));
        }
    }

    // Difficulty bits must decode to a valid target.
    // This also rejects negative/zero targets.
    let _ = crate::difficulty::bits_to_target(header.bits)?;

    Ok(())
}

/// Validate header sanity plus difficulty drop clamp against the previous target.
pub fn validate_header_with_prev_bits(
    prev_bits: u32,
    median_time_past: Option<u64>,
    header: &BlockHeader,
) -> Result<(), ConsensusError> {
    enforce_max_difficulty_drop(prev_bits, header.bits)?;
    validate_header_sanity(header, median_time_past)
}

/// Validate a block's consensus rules that do not require chain state.
///
/// Checks:
/// - block structural sanity (via core)
/// - header sanity (version, timestamp bounds, valid bits)
/// - proof-of-work
pub fn validate_block_consensus(block: &Block) -> Result<(), ConsensusError> {
    block
        .validate_sanity()
        .map_err(|_| ConsensusError::InvalidHeader("block sanity failed"))?;

    let mtp = if block.header.prev == Hash32::zero() {
        None
    } else {
        return Err(ConsensusError::InvalidHeader(
            "missing median-time-past for non-genesis",
        ));
    };

    validate_header_sanity(&block.header, mtp)?;
    validate_pow(&block.header)?;

    Ok(())
}

/// Validate a block with previous `bits`, enforcing drop clamp before PoW.
pub fn validate_block_with_prev_bits(
    prev_bits: u32,
    median_time_past: Option<u64>,
    block: &Block,
) -> Result<(), ConsensusError> {
    block
        .validate_sanity()
        .map_err(|_| ConsensusError::InvalidHeader("block sanity failed"))?;

    enforce_max_difficulty_drop(prev_bits, block.header.bits)?;
    validate_header_sanity(&block.header, median_time_past)?;
    validate_pow(&block.header)?;

    Ok(())
}

/// Check if a candidate timestamp is within an absolute drift window.
///
/// Pure helper (no system clock access) for future median-time enforcement.
pub fn is_timestamp_within_drift(candidate: u64, reference: u64, max_drift_secs: u64) -> bool {
    let delta = if candidate >= reference {
        candidate - reference
    } else {
        reference - candidate
    };
    delta <= max_drift_secs
}

/// Compute Median-Time-Past over the last up-to-11 timestamps.
pub fn median_time_past(timestamps: &[u64]) -> Option<u64> {
    if timestamps.is_empty() {
        return None;
    }
    let start = timestamps.len().saturating_sub(MTP_WINDOW);
    let mut buf: Vec<u64> = timestamps[start..].iter().copied().collect();
    buf.sort_unstable();
    let mid = buf.len() / 2;
    Some(buf[mid])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nulla_core::{
        Amount, Block, BlockHeader, Commitment, Hash32, Transaction, TransactionKind,
        PROTOCOL_VERSION,
    };

    fn coinbase(height: u64) -> Transaction {
        Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Coinbase,
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![Commitment::zero()],
            fee: Amount::zero(),
            claimed_subsidy: Amount::from_atoms(height), // dummy unique value
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        }
    }

    fn block_with_timestamp(ts: u64) -> Block {
        Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                prev: Hash32([1u8; 32]),
                tx_merkle_root: Hash32::zero(),
                commitment_root: Hash32::zero(),
                timestamp: ts,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![coinbase(ts)],
        }
    }

    #[test]
    fn timestamp_drift_within_window() {
        let now = 1_000_000u64;
        let drift = 2 * 60 * 60; // 2 hours
        assert!(is_timestamp_within_drift(now + drift, now, drift));
        assert!(is_timestamp_within_drift(now - drift, now, drift));
    }

    #[test]
    fn timestamp_drift_outside_window() {
        let now = 1_000_000u64;
        let drift = 2 * 60 * 60; // 2 hours
        assert!(!is_timestamp_within_drift(now + drift + 1, now, drift));
        assert!(!is_timestamp_within_drift(now.saturating_sub(drift + 1), now, drift));
    }

    #[test]
    #[cfg(not(feature = "dev-pow"))]
    fn header_validation_order_timestamp_before_pow() {
        let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        let future_ts = now + MAX_FUTURE_DRIFT_SECS + 10;
        let block = block_with_timestamp(future_ts);

        let err =
            validate_block_with_prev_bits(0x207f_ffff, Some(now), &block).expect_err("must fail drift");
        assert!(matches!(
            err,
            ConsensusError::InvalidHeader("timestamp too far from local time")
        ));
    }

    #[test]
    fn mtp_enforced() {
        let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        let block = block_with_timestamp(now);
        let mtp = Some(now + 1);
        let err = validate_header_sanity(&block.header, mtp).expect_err("mtp must fail");
        assert!(matches!(
            err,
            ConsensusError::InvalidHeader("timestamp below MTP")
        ));

        let ok_mtp = Some(now.saturating_sub(1));
        validate_header_sanity(&block.header, ok_mtp).expect("above mtp");
    }

    #[test]
    fn median_time_past_windowed() {
        let ts: Vec<u64> = (0..20).collect();
        let mtp = median_time_past(&ts).expect("mtp");
        assert_eq!(mtp, 14); // median of last 11 timestamps [9..19]
    }
}
