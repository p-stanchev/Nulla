#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

//! Nulla consensus rules for PoW blocks (v0).
//!
//! This crate is responsible for:
//! - block header hashing
//! - compact difficulty target encoding/decoding (Bitcoin-style `bits`)
//! - proof-of-work validation against the target
//!
//! It intentionally does **not** include networking, mempool policy, or state updates.

pub mod difficulty;
pub mod error;
pub mod pow;
pub mod validate;

pub use difficulty::*;
pub use error::*;
pub use pow::*;
pub use validate::*;
