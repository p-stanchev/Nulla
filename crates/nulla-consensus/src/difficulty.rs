// Consensus-critical. Changes require spec update + tests.
//! Difficulty target utilities.
//!
//! Nulla v0 uses a Bitcoin-style "compact" encoding in `BlockHeader.bits`.
//! This encodes a 256-bit target as: `bits = (exponent << 24) | mantissa`
//! where mantissa is 3 bytes. The target is interpreted as:
//!
//! - exponent = (bits >> 24) as u8
//! - mantissa = bits & 0x007fffff (we reject sign bit)
//!
//! Then: target = mantissa * 2^(8*(exponent-3))
//!
//! This module provides strict, consensus-safe conversions without floats.

use crate::error::ConsensusError;
use nulla_core::{MAX_TARGET_INCREASE_DEN, MAX_TARGET_INCREASE_NUM};
use num_bigint::BigUint;
use num_traits::Zero;

/// Decode compact `bits` to a full target (`BigUint`).
///
/// Rejects encodings that are negative, overflow-prone, or represent zero.
pub fn bits_to_target(bits: u32) -> Result<BigUint, ConsensusError> {
    let exponent = ((bits >> 24) & 0xff) as u8;
    let mantissa = bits & 0x00ff_ffff;

    // Reject negative targets (sign bit set in mantissa).
    if (bits & 0x0080_0000) != 0 {
        return Err(ConsensusError::InvalidBits);
    }

    if mantissa == 0 {
        return Err(ConsensusError::InvalidTarget);
    }

    let mant = BigUint::from(mantissa as u64);

    // Compute: mantissa * 2^(8*(exponent-3))
    let target = if exponent <= 3 {
        // Right shift when exponent < 3
        let shift = 8u32 * (3u32 - exponent as u32);
        mant >> shift
    } else {
        let shift = 8u32 * (exponent as u32 - 3u32);
        mant << shift
    };

    if target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }

    Ok(target)
}

/// Encode a target (`BigUint`) into compact `bits`.
///
/// This is primarily useful for testing and for a future difficulty adjustment module.
/// The encoding is normalized to match Bitcoin-style compact behavior.
pub fn target_to_bits(target: &BigUint) -> Result<u32, ConsensusError> {
    if target.is_zero() {
        return Err(ConsensusError::InvalidTarget);
    }

    // Big-endian bytes without leading zeros.
    let mut bytes = target.to_bytes_be();
    // exponent is number of bytes.
    let mut exponent = bytes.len() as u32;

    // Mantissa is first 3 bytes of the target (or padded).
    let mut mantissa: u32;

    if bytes.len() >= 3 {
        mantissa = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    } else {
        // Pad to 3 bytes.
        while bytes.len() < 3 {
            bytes.push(0);
        }
        mantissa = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    }

    // If mantissa's highest bit is set, shift it right by 8 and increase exponent.
    if (mantissa & 0x0080_0000) != 0 {
        mantissa >>= 8;
        exponent = exponent
            .checked_add(1)
            .ok_or(ConsensusError::InvalidBits)?;
    }

    // Compose bits (no sign bit, mantissa is 23 bits).
    mantissa &= 0x00ff_ffff;
    if mantissa == 0 {
        return Err(ConsensusError::InvalidBits);
    }

    if exponent > 255 {
        return Err(ConsensusError::InvalidBits);
    }

    Ok((exponent << 24) | mantissa)
}

/// Compare a 32-byte hash value (big-endian) with a target.
/// Returns `true` if `hash <= target`.
pub fn hash_meets_target(hash_be: &[u8; 32], target: &BigUint) -> bool {
    let h = BigUint::from_bytes_be(hash_be);
    h <= *target
}

/// Enforce a bounded per-block difficulty drop (target increase).
///
/// `max_increase = prev_target * MAX_TARGET_INCREASE_NUM / MAX_TARGET_INCREASE_DEN`.
/// Returns an error if `next_target` exceeds that bound.
pub fn enforce_max_difficulty_drop(prev_bits: u32, next_bits: u32) -> Result<(), ConsensusError> {
    let prev_target = bits_to_target(prev_bits)?;
    let next_target = bits_to_target(next_bits)?;

    let max_increase = (&prev_target * MAX_TARGET_INCREASE_NUM) / MAX_TARGET_INCREASE_DEN;
    if next_target > max_increase {
        return Err(ConsensusError::InvalidTarget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConsensusError;

    #[test]
    fn rejects_zero_or_negative_targets() {
        assert!(matches!(
            bits_to_target(0),
            Err(ConsensusError::InvalidTarget)
        ));

        // Sign bit set in mantissa -> invalid bits.
        let sign_bit = 0x2080_0000u32;
        assert!(matches!(
            bits_to_target(sign_bit),
            Err(ConsensusError::InvalidBits)
        ));
    }

    #[test]
    fn roundtrip_bits_target() {
        // Use a canonical compact form (Bitcoin mainnet-style easiest target).
        let bits = 0x1d00_ffffu32;
        let target = bits_to_target(bits).expect("decode");
        let encoded = target_to_bits(&target).expect("encode");
        assert_eq!(encoded, bits);
        let decoded = bits_to_target(encoded).expect("decode again");
        assert_eq!(decoded, target);
    }

    #[test]
    fn zero_hashrate_easiest_target_passes() {
        // Max target should accept the smallest possible hash.
        let max_target = BigUint::from_bytes_be(&[0xff; 32]);
        assert!(hash_meets_target(&[0u8; 32], &max_target));

        // Tiny target should reject a large hash.
        let min_target = BigUint::from(1u32);
        assert!(!hash_meets_target(&[0xff; 32], &min_target));
    }

    #[test]
    fn difficulty_drop_clamped() {
        let prev_bits = 0x207f_ffffu32;
        let prev_target = bits_to_target(prev_bits).expect("prev");

        // Create a target 2x easier (>25% increase), encode to bits.
        let too_easy_target = &prev_target * 2u32;
        let too_easy_bits = target_to_bits(&too_easy_target).expect("encode");
        assert!(enforce_max_difficulty_drop(prev_bits, too_easy_bits).is_err());

        // Create a target within the 25% bound (increase by 20%).
        let allowed_target = (&prev_target * 120u32) / 100u32;
        let allowed_bits = target_to_bits(&allowed_target).expect("encode");
        enforce_max_difficulty_drop(prev_bits, allowed_bits).expect("within bound");
    }
}
