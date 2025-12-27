// Consensus-critical. Changes require spec update + tests.
//! Canonical serialization helpers.
//!
//! Rule: all consensus-critical objects are encoded with Borsh.
//! Do not use JSON or non-canonical formats for hashing/signing/consensus.

use crate::constants::*;
use crate::types::{
    Amount, BlockHeader, Commitment, CoreError, Hash32, Nullifier, OutPoint, Transaction,
    TransactionKind, TransparentOutput,
};
use borsh::to_vec;

/// Encode a value with canonical Borsh encoding.
pub fn to_bytes<T: borsh::BorshSerialize>(v: &T) -> Result<Vec<u8>, CoreError> {
    to_vec(v).map_err(|_| CoreError::InvalidValue("borsh serialization failed"))
}

/// Hash bytes with blake3 and return 32 bytes.
pub fn hash32(domain_sep: &[u8], bytes: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_sep);
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; HASH32_LEN];
    arr.copy_from_slice(out.as_bytes());
    Hash32(arr)
}

#[derive(borsh::BorshSerialize)]
struct CanonicalTransparentInput {
    prevout: OutPoint,
    pubkey: Vec<u8>,
}

#[derive(borsh::BorshSerialize)]
struct CanonicalTransaction {
    version: u16,
    kind: TransactionKind,
    transparent_inputs: Vec<CanonicalTransparentInput>,
    transparent_outputs: Vec<TransparentOutput>,
    anchor_root: Hash32,
    nullifiers: Vec<Nullifier>,
    outputs: Vec<Commitment>,
    fee: Amount,
    claimed_subsidy: Amount,
    claimed_fees: Amount,
    proof: Vec<u8>,
    memo: Vec<u8>,
}

fn canonical_tx_bytes(tx: &Transaction) -> Result<Vec<u8>, CoreError> {
    let canonical_inputs = tx
        .transparent_inputs
        .iter()
        .map(|i| CanonicalTransparentInput {
            prevout: i.prevout,
            pubkey: i.pubkey.clone(),
        })
        .collect();

    let canonical = CanonicalTransaction {
        version: tx.version,
        kind: tx.kind,
        transparent_inputs: canonical_inputs,
        transparent_outputs: tx.transparent_outputs.clone(),
        anchor_root: tx.anchor_root,
        nullifiers: tx.nullifiers.clone(),
        outputs: tx.outputs.clone(),
        fee: tx.fee,
        claimed_subsidy: tx.claimed_subsidy,
        claimed_fees: tx.claimed_fees,
        proof: tx.proof.clone(),
        memo: tx.memo.clone(),
    };
    to_bytes(&canonical)
}

/// Canonical transaction id (txid) = BLAKE3(DS_TX || borsh(tx without signatures)).
pub fn txid(tx: &Transaction) -> Result<Hash32, CoreError> {
    let bytes = canonical_tx_bytes(tx)?;
    if bytes.len() > MAX_TX_BYTES {
        return Err(CoreError::InvalidValue("tx exceeds MAX_TX_BYTES"));
    }
    Ok(hash32(DS_TX, &bytes))
}

/// Canonical block header hash = BLAKE3(DS_BLOCK_HEADER || borsh(header)).
pub fn block_header_hash(h: &BlockHeader) -> Result<Hash32, CoreError> {
    let bytes = to_bytes(h)?;
    Ok(hash32(DS_BLOCK_HEADER, &bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PROTOCOL_VERSION;
    use crate::types::{Nullifier, Transaction, TransactionKind, TransparentInput};

    #[test]
    fn txid_ignores_signatures() {
        let prev = OutPoint {
            txid: Hash32([1u8; HASH32_LEN]),
            vout: 0,
        };
        let input = TransparentInput {
            prevout: prev,
            sig: vec![0x01, 0x02, 0x03],
            pubkey: vec![0x02, 0xab, 0xcd],
        };
        let output = TransparentOutput {
            value: Amount::from_atoms(5),
            pubkey_hash: [0u8; 20],
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![input],
            transparent_outputs: vec![output],
            anchor_root: Hash32::zero(),
            nullifiers: vec![Nullifier::zero()],
            outputs: vec![Commitment::zero()],
            fee: Amount::from_atoms(1),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };

        let txid_a = txid(&tx).expect("txid");
        tx.transparent_inputs[0].sig = vec![0xff, 0x10];
        let txid_b = txid(&tx).expect("txid after sig change");
        assert_eq!(txid_a, txid_b, "signatures must not affect txid");

        tx.transparent_inputs[0].prevout.vout = 1;
        let txid_c = txid(&tx).expect("txid after prevout change");
        assert_ne!(txid_b, txid_c, "prevout changes must affect txid");
    }
}
