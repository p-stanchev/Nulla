// Consensus-critical. Changes require spec update + tests.
//! Work calculation helpers (heaviest-chain selection).

use crate::difficulty::bits_to_target;
use crate::error::ConsensusError;
use nulla_core::Hash32;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Compute per-block work from compact `bits`.
///
/// Work is defined as `work = floor((2^256) / (target + 1))`.
pub fn work_from_bits(bits: u32) -> Result<BigUint, ConsensusError> {
    let target = bits_to_target(bits)?;
    if target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }

    let two_256 = BigUint::one() << 256u32;
    Ok(&two_256 / (&target + BigUint::one()))
}

/// Return true if tip A is strictly better (heavier) than tip B, tie-breaking on hash.
pub fn tip_is_better(a_work: &BigUint, a_hash: &Hash32, b_work: &BigUint, b_hash: &Hash32) -> bool {
    if a_work != b_work {
        a_work > b_work
    } else {
        a_hash.as_bytes() < b_hash.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_monotonic_vs_target() {
        let easy = work_from_bits(0x207f_ffff).unwrap();
        let harder = work_from_bits(0x1e00_ffff).unwrap();
        assert!(harder > easy, "harder target must yield more work");
    }

    #[test]
    fn tip_comparison() {
        let h1 = Hash32([0u8; 32]);
        let h2 = Hash32([1u8; 32]);
        let w1 = work_from_bits(0x207f_ffff).unwrap();
        let w2 = work_from_bits(0x1e00_ffff).unwrap();

        assert!(tip_is_better(&w2, &h2, &w1, &h1));
        assert!(!tip_is_better(&w1, &h2, &w2, &h1));

        // Tie breaks on hash (lower hash wins).
        assert!(tip_is_better(&w1, &h1, &w1, &h2));
    }
}
