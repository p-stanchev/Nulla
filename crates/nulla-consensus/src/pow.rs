// Consensus-critical. Changes require spec update + tests.
//! Proof-of-work hashing.
//!
//! Nulla v0 defines PoW as the canonical block header hash computed by `nulla-core`
//! (BLAKE3 over a domain-separated Borsh-encoded `BlockHeader`).
//!
//! The PoW condition is:
//!     header_hash_as_u256 <= target(bits)

#[cfg(not(feature = "dev-pow"))]
use crate::difficulty::{bits_to_target, hash_meets_target};
use crate::error::ConsensusError;
use nulla_core::{block_header_hash, BlockHeader};

/// Compute the canonical PoW hash for a header (32 bytes, big-endian).
pub fn pow_hash(header: &BlockHeader) -> Result<[u8; 32], ConsensusError> {
    let h = block_header_hash(header).map_err(|_| ConsensusError::InvalidHeader("hashing failed"))?;
    Ok(*h.as_bytes())
}

/// Validate proof-of-work for a header (hash <= target(bits)).
pub fn validate_pow(header: &BlockHeader) -> Result<(), ConsensusError> {
    #[cfg(feature = "dev-pow")]
    {
        let _ = header;
        // Test-only bypass to speed vector generation; real consensus must not enable this.
        return Ok(());
    }

    #[cfg(not(feature = "dev-pow"))]
    {
        let target = bits_to_target(header.bits)?;
        let h = pow_hash(header)?;
        if !hash_meets_target(&h, &target) {
            return Err(ConsensusError::InsufficientPoW);
        }
        Ok(())
    }
}
