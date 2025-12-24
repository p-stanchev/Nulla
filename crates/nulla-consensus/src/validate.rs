//! Consensus validation helpers for blocks and headers.
//!
//! This module does not touch chain state (UTXO/commitments) and does not
//! implement difficulty adjustment. It only validates self-contained
//! header properties and proof-of-work.

use crate::error::ConsensusError;
use crate::pow::validate_pow;
use nulla_core::{Block, BlockHeader, PROTOCOL_VERSION};

/// Validate basic header invariants that are independent of chain state.
///
/// This intentionally avoids timestamp window logic and difficulty adjustment,
/// which are chain-context rules. It only checks for internal consistency.
pub fn validate_header_sanity(header: &BlockHeader) -> Result<(), ConsensusError> {
    if header.version != PROTOCOL_VERSION {
        return Err(ConsensusError::InvalidHeader("unsupported header version"));
    }

    // Timestamp must be non-zero (genesis can still be 0 if you decide; v0 rejects 0 for hygiene).
    if header.timestamp == 0 {
        return Err(ConsensusError::InvalidHeader("timestamp must be non-zero"));
    }

    // Difficulty bits must decode to a valid target.
    // This also rejects negative/zero targets.
    let _ = crate::difficulty::bits_to_target(header.bits)?;

    Ok(())
}

/// Validate a block's consensus rules that do not require chain state.
///
/// Checks:
/// - block structural sanity (via core)
/// - header sanity (version, timestamp non-zero, valid bits)
/// - proof-of-work
pub fn validate_block_consensus(block: &Block) -> Result<(), ConsensusError> {
    block
        .validate_sanity()
        .map_err(|_| ConsensusError::InvalidHeader("block sanity failed"))?;

    validate_header_sanity(&block.header)?;
    validate_pow(&block.header)?;

    Ok(())
}
