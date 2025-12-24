//! Nullifier set.
//!
//! In v0 we use an in-memory hash set. Persistence will be provided by the node
//! layer via storage (RocksDB/LMDB etc.).
//!
//! Requirements:
//! - membership checks must be fast
//! - insertion must be cheap
//! - iteration order does not matter for consensus (only presence/absence)

use hashbrown::HashSet;

use nulla_core::Nullifier;

/// In-memory set of spent nullifiers.
#[derive(Clone, Debug, Default)]
pub struct NullifierSet {
    set: HashSet<Nullifier>,
}

impl NullifierSet {
    /// Create a new empty nullifier set.
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
        }
    }

    /// Returns `true` if the nullifier has already been seen.
    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.set.contains(nf)
    }

    /// Insert a nullifier.
    ///
    /// Returns `true` if the nullifier was newly inserted, `false` if it already existed.
    pub fn insert(&mut self, nf: Nullifier) -> bool {
        self.set.insert(nf)
    }

    /// Number of spent nullifiers tracked.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}
