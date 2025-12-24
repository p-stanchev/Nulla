# Nulla Consensus (Authoritative)

This surface is frozen. Any change requires an explicit spec update plus tests.

## Chain Identity
- Chain ID: `nulla-devnet`
- Network magic (4 bytes): `NDVT`
- Address prefix: `0x35` (placeholder; wallet not live)
- Genesis:
  - Height: `0`
  - Timestamp: `1_700_000_000`
  - Bits: `0x207fffff`
  - Hash (big-endian): `12d14d284f38ed0adc35224cc5131301f5167ef71b1ba711c175bfaff19be87b`

Rules:
- Genesis `prev` must be all-zero.
- Nodes must reject any alternative genesis hash.

## Block Structure
Header fields (Borsh-encoded in this order):
1. `version: u16`
2. `prev: [u8; 32]` (parent block hash, big-endian)
3. `tx_merkle_root: [u8; 32]`
4. `commitment_root: [u8; 32]` (post-state root)
5. `timestamp: u64` (Unix seconds)
6. `bits: u32` (compact PoW target)
7. `nonce: u64`

Transactions:
- `txs[0]` is the sole coinbase; `txs[1..]` are Regular.
- Coinbase: zero inputs, zero fee, ≥1 outputs, must claim subsidy + total fees.

## Hashing / PoW Input
- Canonical encoding: Borsh.
- Hash function: BLAKE3.
- Transaction ID: `BLAKE3(DS_TX || borsh(tx))`, rejects if `borsh(tx) > MAX_TX_BYTES`.
- Block header hash / PoW hash: `BLAKE3(DS_BLOCK_HEADER || borsh(header))`.
- Endianness: header hash is compared as big-endian to the target.
- Test vectors: `tests/vectors/pow_header.json` (includes genesis).

## Proof of Work Target (compact `bits`)
- Encoding: Bitcoin-style compact target (`bits = (exponent << 24) | mantissa`), 3-byte mantissa.
- Rejections: sign bit set, mantissa == 0, exponent overflow, or target == 0.
- Interpretation: `target = mantissa * 2^(8*(exponent-3))` (big-endian).
- PoW condition: `hash(header) <= target(bits)`.
- Difficulty drop clamp: target may increase by at most **25%** per block (i.e., difficulty may drop by at most 20%). Nodes must enforce `next_target <= prev_target * 125/100` on every retarget step.

## Block Reward / Emission (v1)
Constants:
- `INITIAL_SUBSIDY = 8.0 NULLA = 800,000,000 atoms`
- `TAIL_EMISSION = 0.1 NULLA = 10,000,000 atoms`
- `HALVING_INTERVAL = 2,102,400 blocks (~4 years at 60s)`

Schedule (pure, deterministic):
- `epoch = height / HALVING_INTERVAL`
- `base = INITIAL_SUBSIDY >> epoch` (saturates to 0 if shift ≥ 63)
- `reward = max(base, TAIL_EMISSION)`
- Tail starts at `H_tail = 7 * HALVING_INTERVAL = 14,716,800` where `base` first falls below tail.

## Validation Order (must be adhered to)
1) Structural validity (block/tx sanity)
2) Timestamp validity: MTP(11) < timestamp <= now + 2h (genesis exempt)
3) Difficulty / target validity (bits decode, drop clamp vs previous target)
4) PoW hash check
5) Reward correctness (subsidy schedule + fee claims)

## Reorg Policy
- v0: follow the chain with the greatest accumulated work. No explicit max reorg depth is enforced in code.

## Consensus Invariants
- **Supply:** total issued supply ≤ geometric cap (all pre-tail halvings) + tail; no block may mint above schedule.
- **Tail activation:** reward transitions to tail at `H_tail` and never exceeds tail thereafter.
- **Monotonic subsidy:** before tail, reward never increases with height.
- **Difficulty floor:** targets must be positive; negative/zero targets are rejected.
- **Difficulty drop bound:** per-block target increase capped at 25%.

## Required Tests (coverage checklist)
- Reward at: genesis (h=0), pre-tail boundary (`H_tail - 1`), first tail block (`H_tail`), +1,000,000 into tail.
- Difficulty: invalid/zero/negative targets rejected; target increase above clamp rejected; easiest target accepts zero-hash; harder target rejects large hash.
- Timestamp: ±2h drift helper; invalid timestamp fails before PoW in validation order.
- Genesis: computed hash matches constant; alt genesis rejected.
- PoW input: header → hash test vectors (byte-exact) kept alongside code.

## Notes
- No networking, mempool, or storage rules are enforced yet; node is single-instance devnet.
- All consensus constants are compile-time; no runtime config flags are allowed.
