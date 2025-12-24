//! Crypto wrapper interfaces.
//!
//! Important: this crate intentionally does NOT implement novel cryptography.
//! It defines stable interfaces/types used by higher layers.
//!
//! The zk system, PRFs, and commitment scheme wiring lives in `nulla-zk`
//! and in audited dependencies.

use crate::constants::*;
use crate::serialization::hash32;
use crate::types::{Commitment, Hash32, Nullifier};

/// A domain-separated PRF for nullifier derivation (placeholder wiring).
///
/// v0 default: `nf = BLAKE3(DS_NULLIFIER || sk_bytes || rho_bytes)`
///
/// Higher layers should ensure `sk_bytes` and `rho_bytes` are fixed-length
/// and come from secure key material.
pub fn derive_nullifier(sk_bytes: &[u8], rho_bytes: &[u8]) -> Nullifier {
    let mut input = Vec::with_capacity(sk_bytes.len() + rho_bytes.len());
    input.extend_from_slice(sk_bytes);
    input.extend_from_slice(rho_bytes);

    let h = hash32(DS_NULLIFIER, &input);
    let mut out = [0u8; NULLIFIER_LEN];
    out.copy_from_slice(h.as_bytes());
    Nullifier(out)
}

/// A domain-separated commitment helper (placeholder wiring).
///
/// v0 default: `cm = BLAKE3(DS_COMMITMENT || payload)`
///
/// Real note commitments will be constructed in the zk layer; this function
/// exists for testing and for non-zk scaffolding.
pub fn commit_bytes(payload: &[u8]) -> Commitment {
    let h: Hash32 = hash32(DS_COMMITMENT, payload);
    let mut out = [0u8; COMMITMENT_LEN];
    out.copy_from_slice(h.as_bytes());
    Commitment(out)
}
