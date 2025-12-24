//! Protocol-wide constants for Nulla v0.

/// Protocol semantic version (v0).
pub const PROTOCOL_VERSION: u16 = 0;

/// Length in bytes of a 32-byte hash.
pub const HASH32_LEN: usize = 32;

/// Length in bytes of a note commitment.
pub const COMMITMENT_LEN: usize = 32;

/// Length in bytes of a nullifier.
pub const NULLIFIER_LEN: usize = 32;

/// Number of atomic units per one Nulla.
///
/// 1 Nulla = 10^8 atoms.
pub const ATOMS_PER_NULLA: u64 = 100_000_000;

/// Maximum number of outputs allowed in a single transaction.
///
/// This is a DoS-prevention bound, not a protocol limitation.
pub const MAX_OUTPUTS_PER_TX: usize = 16;

/// Maximum number of inputs (nullifiers) allowed in a single transaction.
///
/// This is a DoS-prevention bound, not a privacy constraint.
pub const MAX_INPUTS_PER_TX: usize = 16;

/// Maximum serialized transaction size (in bytes) accepted by the mempool.
///
/// Transactions exceeding this size are rejected before verification.
pub const MAX_TX_BYTES: usize = 200_000;

/// Domain separator used when hashing block headers.
///
/// Prevents cross-domain hash collisions.
pub const DS_BLOCK_HEADER: &[u8] = b"NULLA::BLOCK_HEADER::V0";

/// Domain separator used when hashing transactions.
///
/// Prevents cross-domain hash collisions.
pub const DS_TX: &[u8] = b"NULLA::TX::V0";

/// Domain separator used when deriving note commitments.
///
/// Prevents cross-domain hash collisions.
pub const DS_COMMITMENT: &[u8] = b"NULLA::COMMITMENT::V0";

/// Domain separator used when deriving nullifiers.
///
/// Prevents cross-domain hash collisions.
pub const DS_NULLIFIER: &[u8] = b"NULLA::NULLIFIER::V0";

/// Block time target in seconds (economic / UX target).
pub const BLOCK_TIME_SECS: u64 = 60;

/// Number of blocks per halving interval (4 years at 60s blocks).
pub const HALVING_INTERVAL_BLOCKS: u64 = 2_102_400;

/// Initial block subsidy in atoms (8.0 NULLA).
pub const INITIAL_SUBSIDY_ATOMS: u64 = 8 * ATOMS_PER_NULLA;

/// Tail emission subsidy in atoms (0.1 NULLA).
pub const TAIL_EMISSION_ATOMS: u64 = ATOMS_PER_NULLA / 10;
