#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

//! Nulla state machine (v0).
//!
//! Responsibilities:
//! - Maintain the append-only commitment tree
//! - Maintain the nullifier set (spent tags)
//! - Apply transactions/blocks to mutate state
//!
//! v0 note: zk proofs are treated as opaque bytes. This crate does not verify
//! proofs; that will be integrated later via `nulla-zk`.

pub mod apply;
pub mod error;
pub mod merkle;
pub mod nullifier;
pub mod utxo;

pub use apply::*;
pub use error::*;
pub use merkle::*;
pub use nullifier::*;
pub use utxo::*;
