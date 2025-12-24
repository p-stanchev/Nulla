//! State transition logic for Nulla v0.

use nulla_core::{
    Amount, Block, Commitment, Hash32, Transaction, TransactionKind, HALVING_INTERVAL_BLOCKS,
    INITIAL_SUBSIDY_ATOMS, TAIL_EMISSION_ATOMS,
};

use crate::error::StateError;
use crate::merkle::{AppendOnlyMerkleTree, Leaf};
use crate::nullifier::NullifierSet;
use crate::utxo::CommitmentRoot;

/// Ledger state for Nulla (v0).
///
/// Tracks:
/// - commitment Merkle tree (append-only)
/// - nullifier set (spent tags)
#[derive(Clone, Debug)]
pub struct LedgerState {
    tree: AppendOnlyMerkleTree,
    nullifiers: NullifierSet,
}

impl LedgerState {
    /// Create a new empty ledger state.
    pub fn new() -> Self {
        Self {
            tree: AppendOnlyMerkleTree::new(),
            nullifiers: NullifierSet::new(),
        }
    }

    /// Current commitment root.
    pub fn commitment_root(&self) -> CommitmentRoot {
        self.tree.root()
    }

    /// Current number of commitments in the tree.
    pub fn commitment_len(&self) -> u64 {
        self.tree.len()
    }

    /// Return whether a nullifier has already been spent.
    pub fn is_spent(&self, nf: &nulla_core::Nullifier) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Apply a single regular transaction to state.
    pub fn apply_regular_tx(&mut self, tx: &Transaction) -> Result<(), StateError> {
        tx.validate_sanity()
            .map_err(|_| StateError::InvalidTransaction("sanity validation failed"))?;

        if tx.kind != TransactionKind::Regular {
            return Err(StateError::InvalidTransaction("expected regular transaction"));
        }

        // Reject double-spends.
        for nf in &tx.nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(StateError::DoubleSpend);
            }
        }

        // Insert nullifiers (mark spent).
        for nf in &tx.nullifiers {
            self.nullifiers.insert(*nf);
        }

        // Append outputs to commitment tree.
        for cm in &tx.outputs {
            self.tree.push(commitment_to_leaf(*cm));
        }

        Ok(())
    }

    /// Apply a block to state at a given height and return the resulting commitment root.
    ///
    /// Enforces:
    /// - exactly one coinbase tx (tx[0])
    /// - subsidy follows tail-emission schedule
    /// - coinbase claimed_fees equals sum of fees of regular txs
    /// - coinbase has no inputs and fee == 0 (enforced by tx sanity)
    /// - header commitment_root matches computed result
    pub fn apply_block(&mut self, height: u64, block: &Block) -> Result<CommitmentRoot, StateError> {
        block
            .validate_sanity()
            .map_err(|_| StateError::InvalidTransaction("block sanity failed"))?;

        // Enforce coinbase in tx[0]
        let coinbase = block
            .txs
            .first()
            .ok_or(StateError::InvalidTransaction("block has no transactions"))?;

        coinbase
            .validate_sanity()
            .map_err(|_| StateError::InvalidTransaction("coinbase sanity failed"))?;

        if coinbase.kind != TransactionKind::Coinbase {
            return Err(StateError::InvalidTransaction("tx[0] must be coinbase"));
        }

        // Enforce subsidy + fee claims.
        let expected_subsidy = block_subsidy(height);
        if coinbase.claimed_subsidy != expected_subsidy {
            return Err(StateError::InvalidTransaction("coinbase subsidy mismatch"));
        }

        // Sum fees of regular txs.
        let mut fee_sum = Amount::zero();
        for tx in block.txs.iter().skip(1) {
            tx.validate_sanity()
                .map_err(|_| StateError::InvalidTransaction("tx sanity failed"))?;
            if tx.kind != TransactionKind::Regular {
                return Err(StateError::InvalidTransaction(
                    "only tx[0] may be coinbase",
                ));
            }
            fee_sum = fee_sum
                .checked_add(tx.fee)
                .map_err(|_| StateError::InvalidTransaction("fee sum overflow"))?;
        }

        if coinbase.claimed_fees != fee_sum {
            return Err(StateError::InvalidTransaction("coinbase fee claim mismatch"));
        }

        // Apply coinbase outputs (mint) to commitment tree.
        for cm in &coinbase.outputs {
            self.tree.push(commitment_to_leaf(*cm));
        }

        // Apply regular txs.
        for tx in block.txs.iter().skip(1) {
            self.apply_regular_tx(tx)?;
        }

        let root = self.commitment_root();
        if root != block.header.commitment_root {
            return Err(StateError::CommitmentRootMismatch);
        }

        Ok(root)
    }

    /// Compute what the commitment root *would be* after applying a set of txs,
    /// without mutating the current state (previews regular + coinbase outputs only).
    ///
    /// Note: this does not validate subsidy/fee claims because those depend on block height.
    pub fn preview_root_after(&self, txs: &[Transaction]) -> Result<Hash32, StateError> {
        let mut tmp = self.clone();

        for tx in txs {
            tx.validate_sanity()
                .map_err(|_| StateError::InvalidTransaction("tx sanity failed"))?;

            match tx.kind {
                TransactionKind::Coinbase => {
                    for cm in &tx.outputs {
                        tmp.tree.push(commitment_to_leaf(*cm));
                    }
                }
                TransactionKind::Regular => {
                    // Apply regular tx without coinbase rules.
                    tmp.apply_regular_tx(tx)?;
                }
            }
        }

        Ok(tmp.commitment_root())
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a commitment to a Merkle leaf representation (32 bytes).
fn commitment_to_leaf(cm: Commitment) -> Leaf {
    *cm.as_bytes()
}

/// Tail emission v1 block subsidy schedule.
pub fn block_subsidy(height: u64) -> Amount {
    let epochs = height / HALVING_INTERVAL_BLOCKS;

    // INITIAL_SUBSIDY_ATOMS / 2^epochs (capped when epochs is large).
    let shifted = if epochs >= 63 {
        0u64
    } else {
        INITIAL_SUBSIDY_ATOMS >> (epochs as u32)
    };

    let reward = if shifted < TAIL_EMISSION_ATOMS {
        TAIL_EMISSION_ATOMS
    } else {
        shifted
    };

    Amount::from_atoms(reward)
}
