//! State-facing note/UTXO helpers.
//!
//! Nulla uses commitment-based notes. On-chain we store only commitments;
//! the wallet holds openings. State tracks commitments and spent nullifiers.

use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use nulla_core::{Commitment, Hash32, Nullifier};

/// A compact representation of a note commitment as stored in state.
///
/// Currently this is just the commitment itself; the wrapper exists so the
/// state layer can evolve without changing external semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NoteCommitment {
    /// The commitment bytes.
    pub cm: Commitment,
}

impl From<Commitment> for NoteCommitment {
    fn from(cm: Commitment) -> Self {
        Self { cm }
    }
}

/// Commitment tree root type.
pub type CommitmentRoot = Hash32;

/// Nullifier set element type.
pub type SpentNullifier = Nullifier;
