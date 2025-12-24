//! Append-only Merkle tree for commitments.
//!
//! Design goals for v0:
//! - Deterministic across platforms
//! - Simple and safe (no incremental-proof machinery yet)
//! - Efficient enough for devnet/testnet
//!
//! We store only the necessary frontier ("peaks") for an append-only tree.
//! This supports O(log n) append and O(log n) root computation.
//!
//! Hash function: BLAKE3 with domain separators from `nulla-core`.

use hashbrown::HashMap;

use nulla_core::{hash32, Hash32};

/// Domain separator for merkle node hashing.
const DS_MERKLE_NODE: &[u8] = b"NULLA::MERKLE_NODE::V0";
/// Domain separator for merkle leaf hashing.
const DS_MERKLE_LEAF: &[u8] = b"NULLA::MERKLE_LEAF::V0";
/// Domain separator for merkle empty hashing.
const DS_MERKLE_EMPTY: &[u8] = b"NULLA::MERKLE_EMPTY::V0";

/// A Merkle tree leaf is a 32-byte value (commitment bytes).
pub type Leaf = [u8; 32];

/// An append-only Merkle tree with a cached frontier.
///
/// The tree supports:
/// - `push(leaf)`
/// - `root()`
///
/// This implementation uses a classic "frontier" approach:
/// - At each height, store the current subtree root if it is "filled".
#[derive(Clone, Debug)]
pub struct AppendOnlyMerkleTree {
    /// Number of leaves appended so far.
    len: u64,
    /// Frontier nodes keyed by height (0 = leaf level).
    ///
    /// If a height exists in the map, it represents a complete subtree root
    /// for the lower `2^height` leaves at the end of the current sequence.
    frontier: HashMap<u8, Hash32>,
}

impl AppendOnlyMerkleTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self {
            len: 0,
            frontier: HashMap::new(),
        }
    }

    /// Return number of leaves.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Return whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a new leaf value.
    ///
    /// Leaf hashing is domain-separated: `H_leaf = BLAKE3(DS_MERKLE_LEAF || leaf_bytes)`.
    pub fn push(&mut self, leaf: Leaf) {
        let mut node = hash32(DS_MERKLE_LEAF, &leaf);

        let mut height: u8 = 0;
        let mut idx = self.len;

        // While the current index is odd at this height, we have a left sibling
        // stored in frontier; combine and carry upward.
        while (idx & 1) == 1 {
            let left = self
                .frontier
                .remove(&height)
                .unwrap_or_else(|| empty_at(height));
            node = parent_hash(&left, &node);
            idx >>= 1;
            height = height.saturating_add(1);
        }

        // Store the carried node at this height.
        self.frontier.insert(height, node);
        self.len = self.len.saturating_add(1);
    }

    /// Compute the current Merkle root.
    ///
    /// Root is computed by folding frontier nodes from low to high with
    /// empty nodes where needed.
    pub fn root(&self) -> Hash32 {
        if self.len == 0 {
            return empty_at(0);
        }

        // Fold across heights. We need to combine subtree roots in order.
        // For heights without a frontier node, we use the empty hash at that height.
        //
        // We compute by scanning heights up to the highest frontier entry.
        let mut max_h: u8 = 0;
        for h in self.frontier.keys() {
            if *h > max_h {
                max_h = *h;
            }
        }

        let mut acc: Option<Hash32> = None;
        for h in 0..=max_h {
            let node = self.frontier.get(&h).copied().unwrap_or_else(|| empty_at(h));
            acc = Some(match acc {
                None => node,
                Some(prev) => parent_hash(&node, &prev),
            });
        }

        acc.unwrap_or_else(|| empty_at(0))
    }
}

impl Default for AppendOnlyMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute parent hash for two child nodes.
fn parent_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    hash32(DS_MERKLE_NODE, &bytes)
}

/// Compute the "empty" node hash at a given height.
///
/// This is deterministic and domain-separated, and lets us define roots for
/// incomplete levels.
fn empty_at(height: u8) -> Hash32 {
    // Height is included to avoid accidental reuse across levels.
    hash32(DS_MERKLE_EMPTY, &[height])
}
