// Consensus-critical. Changes require spec update + tests.
//! Canonical protocol types for Nulla v0.
//!
//! This module defines all consensus-visible data structures and primitive
//! value types used across the protocol. All types here must remain
//! backward-compatible once released.

use crate::constants::*;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors related to parsing, validation, or construction of core protocol types.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Hex string had an unexpected byte length.
    #[error("invalid hex length: expected {expected} bytes, got {got} bytes")]
    InvalidHexLength {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes provided.
        got: usize,
    },

    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    /// Arithmetic overflow or underflow occurred.
    #[error("amount overflow or underflow")]
    AmountOverflow,

    /// A value violated protocol constraints.
    #[error("invalid value: {0}")]
    InvalidValue(&'static str),
}

/// Fixed-size 32-byte hash used throughout the protocol.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hash32(pub [u8; HASH32_LEN]);

impl Hash32 {
    /// Returns an all-zero hash.
    pub const fn zero() -> Self {
        Self([0u8; HASH32_LEN])
    }

    /// Returns the underlying byte array.
    pub const fn as_bytes(&self) -> &[u8; HASH32_LEN] {
        &self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl From<[u8; HASH32_LEN]> for Hash32 {
    fn from(value: [u8; HASH32_LEN]) -> Self {
        Self(value)
    }
}

impl From<Hash32> for [u8; HASH32_LEN] {
    fn from(value: Hash32) -> Self {
        value.0
    }
}

impl FromStr for Hash32 {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != HASH32_LEN {
            return Err(CoreError::InvalidHexLength {
                expected: HASH32_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; HASH32_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Block hash type.
pub type BlockHash = Hash32;

/// Transaction identifier type.
pub type TxId = Hash32;

/// Commitment to a private note (UTXO).
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Commitment(pub [u8; COMMITMENT_LEN]);

impl Commitment {
    /// Returns an all-zero commitment.
    pub const fn zero() -> Self {
        Self([0u8; COMMITMENT_LEN])
    }

    /// Returns the underlying byte array.
    pub const fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment({})", hex::encode(self.0))
    }
}

impl fmt::Display for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Commitment {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != COMMITMENT_LEN {
            return Err(CoreError::InvalidHexLength {
                expected: COMMITMENT_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; COMMITMENT_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Nullifier identifying a spent note.
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Nullifier(pub [u8; NULLIFIER_LEN]);

impl Nullifier {
    /// Returns an all-zero nullifier.
    pub const fn zero() -> Self {
        Self([0u8; NULLIFIER_LEN])
    }

    /// Returns the underlying byte array.
    pub const fn as_bytes(&self) -> &[u8; NULLIFIER_LEN] {
        &self.0
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullifier({})", hex::encode(self.0))
    }
}

impl fmt::Display for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for Nullifier {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != NULLIFIER_LEN {
            return Err(CoreError::InvalidHexLength {
                expected: NULLIFIER_LEN,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; NULLIFIER_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Amount expressed in the smallest unit ("atoms").
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Amount(pub u64);

impl Amount {
    /// Returns a zero amount.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Constructs an amount from atoms.
    pub const fn from_atoms(atoms: u64) -> Self {
        Self(atoms)
    }

    /// Returns the underlying atom value.
    pub const fn atoms(self) -> u64 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Amount) -> Result<Self, CoreError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(CoreError::AmountOverflow)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Amount) -> Result<Self, CoreError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(CoreError::AmountOverflow)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({} atoms)", self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} atoms", self.0)
    }
}

/// Transaction kind.
///
/// `Coinbase` is the only transaction type allowed to mint new supply.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransactionKind {
    /// Coinbase transaction (must be tx[0] of a block).
    Coinbase,
    /// Regular transaction (spends notes via nullifiers).
    Regular,
}

/// Public transaction container (v0).
///
/// Pre-zk note:
/// - Amounts inside commitments are not yet verifiable here.
/// - To enforce issuance now, coinbase carries explicit claimed values.
///   Later, once zk enforces value conservation, these claims can be removed.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    /// Protocol version for this transaction.
    pub version: u16,
    /// Transaction kind.
    pub kind: TransactionKind,

    /// Commitment tree root this transaction is anchored to (Regular only).
    pub anchor_root: Hash32,

    /// Nullifiers consumed by this transaction (Regular only).
    pub nullifiers: Vec<Nullifier>,

    /// Newly created note commitments.
    pub outputs: Vec<Commitment>,

    /// Public transaction fee, in atoms (Regular only).
    pub fee: Amount,

    /// Coinbase claimed subsidy (Coinbase only).
    pub claimed_subsidy: Amount,

    /// Coinbase claimed total fees included in the block (Coinbase only).
    pub claimed_fees: Amount,

    /// Zero-knowledge proof bytes (Regular only in v1; opaque for now).
    pub proof: Vec<u8>,

    /// Optional encrypted memo payload.
    pub memo: Vec<u8>,
}

impl Transaction {
    /// Performs basic structural validation.
    pub fn validate_sanity(&self) -> Result<(), CoreError> {
        if self.version != PROTOCOL_VERSION {
            return Err(CoreError::InvalidValue("unsupported transaction version"));
        }

        match self.kind {
            TransactionKind::Coinbase => {
                if !self.nullifiers.is_empty() {
                    return Err(CoreError::InvalidValue("coinbase must have no inputs"));
                }
                if self.anchor_root != Hash32::zero() {
                    return Err(CoreError::InvalidValue("coinbase anchor_root must be zero"));
                }
                if self.fee != Amount::zero() {
                    return Err(CoreError::InvalidValue("coinbase fee must be zero"));
                }
                if self.outputs.is_empty() {
                    return Err(CoreError::InvalidValue("coinbase must have >= 1 output"));
                }
                if self.outputs.len() > MAX_OUTPUTS_PER_TX {
                    return Err(CoreError::InvalidValue("too many outputs"));
                }
                Ok(())
            }
            TransactionKind::Regular => {
                if self.nullifiers.is_empty() {
                    return Err(CoreError::InvalidValue("transaction has no inputs"));
                }
                if self.nullifiers.len() > MAX_INPUTS_PER_TX {
                    return Err(CoreError::InvalidValue("too many inputs"));
                }
                if self.outputs.is_empty() {
                    return Err(CoreError::InvalidValue("transaction has no outputs"));
                }
                if self.outputs.len() > MAX_OUTPUTS_PER_TX {
                    return Err(CoreError::InvalidValue("too many outputs"));
                }
                if self.claimed_subsidy != Amount::zero() || self.claimed_fees != Amount::zero() {
                    return Err(CoreError::InvalidValue(
                        "regular tx must not carry coinbase claims",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Block header containing consensus-critical metadata.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockHeader {
    /// Protocol version.
    pub version: u16,
    /// Hash of the previous block.
    pub prev: BlockHash,
    /// Merkle root of transaction identifiers.
    pub tx_merkle_root: Hash32,
    /// Commitment tree root after this block.
    pub commitment_root: Hash32,
    /// Block timestamp (Unix seconds).
    pub timestamp: u64,
    /// Compact difficulty target.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u64,
}

/// Full block (header + transactions).
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Transactions included in this block.
    pub txs: Vec<Transaction>,
}

impl Block {
    /// Performs basic structural validation.
    pub fn validate_sanity(&self) -> Result<(), CoreError> {
        if self.header.version != PROTOCOL_VERSION {
            return Err(CoreError::InvalidValue("unsupported block version"));
        }
        if self.txs.is_empty() {
            return Err(CoreError::InvalidValue("block has no transactions"));
        }
        Ok(())
    }
}
