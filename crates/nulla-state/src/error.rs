//! State transition errors.

use thiserror::Error;

/// Errors produced by state validation or transitions.
#[derive(Debug, Error)]
pub enum StateError {
    /// Transaction failed basic sanity checks.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(&'static str),

    /// A nullifier was already present in the nullifier set.
    #[error("double spend detected")]
    DoubleSpend,

    /// Block header commitment root mismatch.
    #[error("commitment root mismatch")]
    CommitmentRootMismatch,

    /// Internal merkle tree error.
    #[error("merkle error: {0}")]
    Merkle(&'static str),
}
