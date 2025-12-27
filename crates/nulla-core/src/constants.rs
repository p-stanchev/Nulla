// Consensus-critical. Changes require spec update + tests.
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

/// Chain identity string (mainnet). Use numeric "0" for on-wire messages.
pub const CHAIN_ID: &str = "0";

/// Network magic bytes (mainnet).
pub const NETWORK_MAGIC: [u8; 4] = *b"NUL0";

/// Address prefix (devnet placeholder; not yet used in wallet).
pub const ADDRESS_PREFIX: u8 = 0x35;

/// Genesis timestamp (Unix seconds, deterministic).
/// January 1st, 2026 00:00:00 UTC - Fresh start for mainnet
pub const GENESIS_TIMESTAMP: u64 = 1_767_225_600;

/// Genesis difficulty bits (devnet).
pub const GENESIS_BITS: u32 = 0x207f_ffff;

/// Genesis nonce (mined for 2026-01-01 genesis).
pub const GENESIS_NONCE: u64 = 1;

/// Genesis block hash (2026-01-01 mainnet) as raw bytes (big-endian).
pub const GENESIS_HASH_BYTES: [u8; HASH32_LEN] = [
    0x7c, 0x33, 0xb5, 0x40, 0xb5, 0xe2, 0x89, 0x6d, 0x9e, 0xaf, 0xd3, 0xed, 0xf4, 0x7a, 0x52,
    0x65, 0x87, 0x6c, 0xe9, 0x6d, 0xab, 0xb4, 0x2b, 0x84, 0xa1, 0x92, 0x9c, 0x9a, 0x84, 0xef,
    0x87, 0x00,
];

/// Maximum per-block target increase (difficulty drop) ratio numerator.
pub const MAX_TARGET_INCREASE_NUM: u32 = 125;
/// Maximum per-block target increase (difficulty drop) ratio denominator.
pub const MAX_TARGET_INCREASE_DEN: u32 = 100;

/// Block time target in seconds (economic / UX target).
pub const BLOCK_TIME_SECS: u64 = 60;

/// LWMA difficulty adjustment window (number of blocks).
pub const DIFFICULTY_WINDOW: usize = 60;

/// Number of blocks per halving interval (4 years at 60s blocks).
pub const HALVING_INTERVAL_BLOCKS: u64 = 2_102_400;

/// Initial block subsidy in atoms (8.0 NULLA).
pub const INITIAL_SUBSIDY_ATOMS: u64 = 8 * ATOMS_PER_NULLA;

/// Tail emission subsidy in atoms (0.1 NULLA).
pub const TAIL_EMISSION_ATOMS: u64 = ATOMS_PER_NULLA / 10;
