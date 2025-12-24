//! Consensus error types.

use thiserror::Error;

/// Errors returned by consensus validation and difficulty conversion code.
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// Invalid compact target encoding in `bits`.
    #[error("invalid compact target bits")]
    InvalidBits,

    /// Target decoded to zero or otherwise unusable.
    #[error("invalid difficulty target")]
    InvalidTarget,

    /// Proof-of-work hash did not meet the required target.
    #[error("insufficient proof of work")]
    InsufficientPoW,

    /// Header fields violated basic consensus constraints.
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
}
