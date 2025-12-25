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

/// Compute the next difficulty target using a Linear Weighted Moving Average (LWMA).
///
/// Inputs must be ordered oldest -> newest. `window` should typically be
/// `DIFFICULTY_WINDOW` long but the function will operate on any length >= 2.
///
/// `max_target` caps the easiest allowable target (e.g., genesis target).
pub fn next_bits_lwma(
    window: &[(u64, u32)],
    target_secs: u64,
    max_target: &BigUint,
    ) -> Result<u32, ConsensusError> {
    if window.len() < 2 {
        return Err(ConsensusError::InvalidTarget);
    }

    // Sum the targets to derive an average target for the window.
    let mut sum_target = BigUint::zero();
    for &(_, bits) in window {
        sum_target += bits_to_target(bits)?;
    }
    let n = window.len() as u64;
    let avg_target = &sum_target / n;

    // Weighted sum of solvetimes, clamped to avoid outliers.
    let mut sum_weighted: u128 = 0;
    for (idx, pair) in window.windows(2).enumerate() {
        let prev_ts = pair[0].0;
        let cur_ts = pair[1].0;
        let raw = cur_ts.saturating_sub(prev_ts);
        let clamped = raw.clamp(1, target_secs.saturating_mul(6));
        let weight = (idx as u128) + 1; // weights 1..N-1
        sum_weighted = sum_weighted.saturating_add((clamped as u128).saturating_mul(weight));
    }

    // Normalization constant for LWMA: k = N*(N+1)*T/2
    let k = n.saturating_mul(n + 1).saturating_mul(target_secs) / 2;
    let k = k.max(1);

    let mut next_target =
        (&avg_target * BigUint::from(sum_weighted)) / BigUint::from(k);

    // Clamp to per-block drop bound and maximum/easiest target.
    let prev_bits = window.last().unwrap().1;
    let prev_target = bits_to_target(prev_bits)?;
    let max_increase = (&prev_target * MAX_TARGET_INCREASE_NUM) / MAX_TARGET_INCREASE_DEN;
    if next_target > max_increase {
        next_target = max_increase;
    }
    if next_target > *max_target {
        next_target = max_target.clone();
    }
    if next_target.is_zero() {
        next_target = BigUint::from(1u32);
    }

    target_to_bits(&next_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConsensusError;
    use nulla_core::{BLOCK_TIME_SECS, DIFFICULTY_WINDOW};

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

    #[test]
    fn lwma_stable_when_on_target() {
        let max_target = bits_to_target(0x207f_ffff).unwrap();
        let mut window = Vec::new();
        let mut ts = 1_700_000_000u64;
        for _ in 0..DIFFICULTY_WINDOW {
            window.push((ts, 0x207f_ffff));
            ts += BLOCK_TIME_SECS;
        }
        let next = next_bits_lwma(&window, BLOCK_TIME_SECS, &max_target).unwrap();
        let next_target = bits_to_target(next).unwrap();
        let prev_target = bits_to_target(0x207f_ffff).unwrap();
        // Allow small rounding drift but require near stability.
        let upper = (&prev_target * 105u32) / 100u32;
        let lower = (&prev_target * 95u32) / 100u32;
        assert!(
            next_target >= lower && next_target <= upper,
            "target should remain near-stable"
        );
    }

    #[test]
    fn lwma_hardens_on_fast_blocks() {
        let max_target = bits_to_target(0x207f_ffff).unwrap();
        let mut window = Vec::new();
        let mut ts = 1_700_000_000u64;
        for _ in 0..DIFFICULTY_WINDOW {
            window.push((ts, 0x207f_ffff));
            ts += BLOCK_TIME_SECS / 2; // twice as fast as target
        }
        let next_bits = next_bits_lwma(&window, BLOCK_TIME_SECS, &max_target).unwrap();
        let next_target = bits_to_target(next_bits).unwrap();
        let prev_target = bits_to_target(0x207f_ffff).unwrap();
        assert!(next_target < prev_target, "target should get harder");
    }

    #[test]
    fn lwma_respects_drop_clamp() {
        let prev_bits = 0x207f_ffffu32;
        let prev_target = bits_to_target(prev_bits).unwrap();
        let max_target = prev_target.clone();
        let mut window = Vec::new();
        let mut ts = 1_700_000_000u64;
        // Very slow blocks to try to force a big drop.
        for _ in 0..DIFFICULTY_WINDOW {
            window.push((ts, prev_bits));
            ts += BLOCK_TIME_SECS * 10;
        }
        let next_bits = next_bits_lwma(&window, BLOCK_TIME_SECS, &max_target).unwrap();
        let next_target = bits_to_target(next_bits).unwrap();
        let clamp = (&prev_target * MAX_TARGET_INCREASE_NUM) / MAX_TARGET_INCREASE_DEN;
        assert!(
            next_target <= clamp,
            "next target should be clamped to per-block drop bound"
        );
    }
}
