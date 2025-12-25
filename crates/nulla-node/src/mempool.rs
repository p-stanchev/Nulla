use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use k256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use k256::EncodedPoint;
use nulla_core::{
    txid, Amount, Hash32, OutPoint, Transaction, TransactionKind, TransparentInput, TransparentOutput,
};
use nulla_core::Hash32 as TxId;

pub trait ChainView {
    /// Returns (value, pubkey_hash) for an outpoint if unspent in best chain.
    fn lookup_outpoint(&self, out: &OutPoint) -> Option<(u64, [u8; 20])>;
}

#[derive(Debug)]
pub enum SubmitError {
    #[allow(dead_code)]
    InvalidFormat(&'static str),
    DuplicateTx,
    DuplicateInput,
    UnknownInput,
    AlreadySpent,
    InsufficientInputValue,
    BadSignature,
    TooLarge,
}

pub struct Mempool {
    txs: HashMap<TxId, Transaction>,
    spent: HashMap<OutPoint, TxId>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    pub fn submit_tx<C: ChainView>(
        &mut self,
        chain: &C,
        tx: Transaction,
    ) -> Result<TxId, SubmitError> {
        if tx.kind != TransactionKind::Regular {
            return Err(SubmitError::InvalidFormat("non-regular tx rejected"));
        }

        if tx.transparent_inputs.is_empty() || tx.transparent_outputs.is_empty() {
            return Err(SubmitError::InvalidFormat("empty inputs or outputs"));
        }

        // size check (rough, non-serialized)
        if tx.transparent_inputs.len() > 10_000 || tx.transparent_outputs.len() > 10_000 {
            return Err(SubmitError::TooLarge);
        }

        // duplicate input check
        let mut seen_inputs = HashSet::new();
        for inp in &tx.transparent_inputs {
            if !seen_inputs.insert(inp.prevout) {
                return Err(SubmitError::DuplicateInput);
            }
        }

        // outputs positive
        for o in &tx.transparent_outputs {
            if o.value == Amount::zero() {
                return Err(SubmitError::InvalidFormat("zero output value"));
            }
        }

        // Resolve inputs and value check
        let mut input_total = 0u64;
        let mut resolved_prevouts = Vec::new();
        for inp in &tx.transparent_inputs {
            if let Some((value, pk_hash)) = chain.lookup_outpoint(&inp.prevout) {
                if self.spent.contains_key(&inp.prevout) {
                    return Err(SubmitError::AlreadySpent);
                }
                input_total = input_total
                    .checked_add(value)
                    .ok_or(SubmitError::InsufficientInputValue)?;
                resolved_prevouts.push((value, pk_hash, &inp.pubkey, &inp.sig, &inp.prevout));
            } else {
                return Err(SubmitError::UnknownInput);
            }
        }

        let output_total: u64 = tx
            .transparent_outputs
            .iter()
            .map(|o| o.value.atoms())
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(SubmitError::InsufficientInputValue)?;

        let fee = tx.fee.atoms();

        if input_total < output_total.saturating_add(fee) {
            return Err(SubmitError::InsufficientInputValue);
        }

        // signature checks
        let sighash = tx_sighash(&tx, &resolved_prevouts);
        for (_value, pk_hash, pubkey, sig, _prevout) in resolved_prevouts {
            if !pubkey_hash_matches(pubkey, pk_hash) {
                return Err(SubmitError::BadSignature);
            }
            let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| SubmitError::BadSignature)?;
            let signature = Signature::from_der(sig).map_err(|_| SubmitError::BadSignature)?;
            vk.verify(&sighash, &signature)
                .map_err(|_| SubmitError::BadSignature)?;
        }

        let txid = txid(&tx).map_err(|_| SubmitError::InvalidFormat("txid"))?;
        if self.txs.contains_key(&txid) {
            return Err(SubmitError::DuplicateTx);
        }

        for inp in &tx.transparent_inputs {
            self.spent.insert(inp.prevout, txid);
        }
        self.txs.insert(txid, tx);
        Ok(txid)
    }

    #[allow(dead_code)]
    pub fn remove_mined(&mut self, mined: &[TxId]) {
        for id in mined {
            if let Some(tx) = self.txs.remove(id) {
                for inp in tx.transparent_inputs {
                    self.spent.remove(&inp.prevout);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn purge_conflicts_with_new_tip<C: ChainView>(&mut self, chain: &C) {
        // Simple approach: drop txs whose inputs are no longer available.
        let mut to_drop = Vec::new();
        for (txid, tx) in self.txs.iter() {
            for inp in &tx.transparent_inputs {
                if chain.lookup_outpoint(&inp.prevout).is_none() {
                    to_drop.push(*txid);
                    break;
                }
            }
        }
        self.remove_mined(&to_drop);
    }

    pub fn pending(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }
}

// Placeholder until transparent UTXO tracking is wired into ChainStore.
impl ChainView for nulla_node::chain_store::ChainStore {
    fn lookup_outpoint(&self, out: &OutPoint) -> Option<(u64, [u8; 20])> {
        self.utxo_lookup(out).map(|u| (u.value, u.pubkey_hash))
    }
}

fn pubkey_hash_matches(pubkey: &[u8], expected: [u8; 20]) -> bool {
    let mut h = Hasher::new();
    h.update(pubkey);
    let mut out = [0u8; 20];
    h.finalize_xof().fill(&mut out);
    out == expected
}

fn tx_sighash(tx: &Transaction, resolved_inputs: &[(u64, [u8; 20], &Vec<u8>, &Vec<u8>, &OutPoint)]) -> Vec<u8> {
    // Simple, deterministic sighash: version || inputs || outputs
    let mut data = Vec::new();
    data.extend_from_slice(&tx.version.to_le_bytes());
    data.extend_from_slice(&(tx.transparent_inputs.len() as u64).to_le_bytes());
    for (i, inp) in tx.transparent_inputs.iter().enumerate() {
        data.extend_from_slice(inp.prevout.txid.as_bytes());
        data.extend_from_slice(&inp.prevout.vout.to_le_bytes());
        // bind the prevout pubkey_hash into the sighash
        let (_, pk_hash, _, _, _) = resolved_inputs[i];
        data.extend_from_slice(&pk_hash);
    }
    data.extend_from_slice(&(tx.transparent_outputs.len() as u64).to_le_bytes());
    for o in &tx.transparent_outputs {
        data.extend_from_slice(&o.value.atoms().to_le_bytes());
        data.extend_from_slice(&o.pubkey_hash);
    }
    let mut h = Hasher::new();
    h.update(&data);
    h.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::elliptic_curve::rand_core::OsRng;
    use nulla_core::PROTOCOL_VERSION;

    struct FakeChain {
        utxos: HashMap<OutPoint, (u64, [u8; 20])>,
    }

    impl ChainView for FakeChain {
        fn lookup_outpoint(&self, out: &OutPoint) -> Option<(u64, [u8; 20])> {
            self.utxos.get(out).cloned()
        }
    }

    fn p2pkh_hash(pubkey: &[u8]) -> [u8; 20] {
        let mut h = Hasher::new();
        h.update(pubkey);
        let mut out = [0u8; 20];
        h.finalize_xof().fill(&mut out);
        out
    }

    fn sign_tx(
        sk: &SigningKey,
        tx: &Transaction,
        resolved: &[(u64, [u8; 20], &Vec<u8>, &Vec<u8>, &OutPoint)],
    ) -> Vec<u8> {
        let digest = tx_sighash(tx, resolved);
        let sig: Signature = sk.sign(&digest);
        sig.to_der().as_bytes().to_vec()
    }

    fn make_tx(sk: &SigningKey, prev: OutPoint, prev_value: u64) -> Transaction {
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: prev,
                pubkey: pubkey.clone(),
                sig: vec![],
            }],
            transparent_outputs: vec![TransparentOutput {
                value: Amount::from_atoms(prev_value - 1),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::zero(),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        let resolved = vec![(
            prev_value,
            pk_hash,
            &tx.transparent_inputs[0].pubkey,
            &tx.transparent_inputs[0].sig,
            &tx.transparent_inputs[0].prevout,
        )];
        let sig = sign_tx(sk, &tx, &resolved);
        tx.transparent_inputs[0].sig = sig;
        tx
    }

    #[test]
    fn accepts_valid_tx() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let prev = OutPoint {
            txid: Hash32::zero(),
            vout: 0,
        };
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        chain.utxos.insert(prev, (10, pk_hash));

        let tx = make_tx(&sk, prev, 10);
        let mut mempool = Mempool::new();
        let id = mempool.submit_tx(&chain, tx).expect("valid");
        assert!(mempool.txs.contains_key(&id));
    }

    #[test]
    fn rejects_unknown_input() {
        let sk = SigningKey::random(&mut OsRng);
        let prev = OutPoint {
            txid: Hash32::zero(),
            vout: 0,
        };
        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: prev,
                pubkey: Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes()),
                sig: vec![0u8; 1],
            }],
            transparent_outputs: vec![TransparentOutput {
                value: Amount::from_atoms(1),
                pubkey_hash: [0u8; 20],
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::zero(),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        let chain = FakeChain {
            utxos: HashMap::new(),
        };
        let mut mempool = Mempool::new();
        let err = mempool.submit_tx(&chain, tx).unwrap_err();
        matches!(err, SubmitError::UnknownInput);
    }

    #[test]
    fn rejects_duplicate_input() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let prev = OutPoint {
            txid: Hash32::zero(),
            vout: 0,
        };
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        chain.utxos.insert(prev, (10, pk_hash));

        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![
                TransparentInput {
                    prevout: prev,
                    pubkey: pubkey.clone(),
                    sig: vec![0u8; 1],
                },
                TransparentInput {
                    prevout: prev,
                    pubkey: pubkey.clone(),
                    sig: vec![0u8; 1],
                },
            ],
            transparent_outputs: vec![TransparentOutput {
                value: Amount::from_atoms(1),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::zero(),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        let mut mempool = Mempool::new();
        let err = mempool.submit_tx(&chain, tx).unwrap_err();
        matches!(err, SubmitError::DuplicateInput);
    }

    #[test]
    fn rejects_double_spend_in_mempool() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let prev = OutPoint {
            txid: Hash32::zero(),
            vout: 0,
        };
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        chain.utxos.insert(prev, (10, pk_hash));
        let mut mempool = Mempool::new();
        let tx1 = make_tx(&sk, prev, 10);
        mempool.submit_tx(&chain, tx1).unwrap();

        let tx2 = make_tx(&sk, prev, 10);
        let err = mempool.submit_tx(&chain, tx2).unwrap_err();
        matches!(err, SubmitError::AlreadySpent);
    }

    #[test]
    fn rejects_value_overflow() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let prev = OutPoint {
            txid: Hash32::zero(),
            vout: 0,
        };
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        chain.utxos.insert(prev, (5, pk_hash));

        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: prev,
                pubkey,
                sig: vec![0u8; 1],
            }],
            transparent_outputs: vec![TransparentOutput {
                value: Amount::from_atoms(10),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::zero(),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        let mut mempool = Mempool::new();
        let err = mempool.submit_tx(&chain, tx).unwrap_err();
        matches!(err, SubmitError::InsufficientInputValue);
    }
}
