// Consensus-critical. Changes require spec update + tests.
//! Canonical serialization helpers.
//!
//! Rule: all consensus-critical objects are encoded with Borsh.
//! Do not use JSON or non-canonical formats for hashing/signing/consensus.

use crate::constants::*;
use crate::types::{BlockHeader, CoreError, Hash32, Transaction};
use borsh::to_vec;

/// Encode a value with canonical Borsh encoding.
pub fn to_bytes<T: borsh::BorshSerialize>(v: &T) -> Result<Vec<u8>, CoreError> {
    to_vec(v).map_err(|_| CoreError::InvalidValue("borsh serialization failed"))
}

/// Hash bytes with blake3 and return 32 bytes.
pub fn hash32(domain_sep: &[u8], bytes: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_sep);
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; HASH32_LEN];
    arr.copy_from_slice(out.as_bytes());
    Hash32(arr)
}

/// Canonical transaction id (txid) = BLAKE3(DS_TX || borsh(tx)).
pub fn txid(tx: &Transaction) -> Result<Hash32, CoreError> {
    let bytes = to_bytes(tx)?;
    if bytes.len() > MAX_TX_BYTES {
        return Err(CoreError::InvalidValue("tx exceeds MAX_TX_BYTES"));
    }
    Ok(hash32(DS_TX, &bytes))
}

/// Canonical block header hash = BLAKE3(DS_BLOCK_HEADER || borsh(header)).
pub fn block_header_hash(h: &BlockHeader) -> Result<Hash32, CoreError> {
    let bytes = to_bytes(h)?;
    Ok(hash32(DS_BLOCK_HEADER, &bytes))
}
