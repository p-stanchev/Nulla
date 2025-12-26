use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use nulla_core::{txid, Amount, Hash32, OutPoint, Transaction, TransactionKind, TxId};

pub trait ChainView {
    /// Returns (value, pubkey_hash) for an outpoint if unspent in best chain.
    fn lookup_outpoint(&self, out: &OutPoint) -> Option<(u64, [u8; 20])>;
}

/// Node policy: minimum fee per transaction (atoms). Not consensus.
pub const BASE_FEE_ATOMS: u64 = 1000;
/// Node policy: max mempool size (count and total serialized bytes). Not consensus.
const MAX_MEMPOOL_TXS: usize = 5000;
const MAX_MEMPOOL_BYTES: usize = 5_000_000;

#[derive(Debug)]
pub enum SubmitError {
    #[allow(dead_code)]
    InvalidFormat(&'static str),
    DuplicateTx,
    DuplicateInput,
    UnknownInput,
    AlreadySpent,
    LowFee,
    InsufficientInputValue,
    BadSignature,
    TooLarge,
    PoolFull,
}

#[derive(Clone)]
struct MemEntry {
    tx: Transaction,
    size: usize,
    fee_rate: u64, // atoms per byte (floor)
}

pub struct Mempool {
    txs: HashMap<TxId, MemEntry>,
    spent: HashMap<OutPoint, TxId>,
    total_bytes: usize,
    max_txs: usize,
    max_bytes: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            spent: HashMap::new(),
            total_bytes: 0,
            max_txs: MAX_MEMPOOL_TXS,
            max_bytes: MAX_MEMPOOL_BYTES,
        }
    }

    /// Test-only helper to use smaller limits.
    #[cfg(test)]
    pub fn with_limits(max_txs: usize, max_bytes: usize) -> Self {
        Self {
            txs: HashMap::new(),
            spent: HashMap::new(),
            total_bytes: 0,
            max_txs,
            max_bytes,
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
        let ser = borsh::to_vec(&tx).map_err(|_| SubmitError::InvalidFormat("encode"))?;
        let size = ser.len();

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

        if fee < BASE_FEE_ATOMS {
            return Err(SubmitError::LowFee);
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

        // fee rate for eviction policy
        let rate = fee.checked_div(size as u64).unwrap_or(0).max(1);

        // If full, consider eviction of lowest fee-rate tx.
        if self.txs.len() >= self.max_txs || self.total_bytes + size > self.max_bytes {
            if let Some((lowest_id, lowest_rate, lowest_size)) = self.lowest_fee_rate() {
                if rate <= lowest_rate {
                    return Err(SubmitError::PoolFull);
                }
                // evict lowest
                if let Some(entry) = self.txs.remove(&lowest_id) {
                    self.total_bytes = self.total_bytes.saturating_sub(entry.size);
                    for inp in entry.tx.transparent_inputs {
                        self.spent.remove(&inp.prevout);
                    }
                } else {
                    // fallback to stored size
                    self.total_bytes = self.total_bytes.saturating_sub(lowest_size);
                }
            } else {
                return Err(SubmitError::PoolFull);
            }
        }
        for inp in &tx.transparent_inputs {
            self.spent.insert(inp.prevout, txid);
        }
        self.total_bytes = self.total_bytes.saturating_add(size);
        self.txs.insert(
            txid,
            MemEntry {
                tx,
                size,
                fee_rate: rate,
            },
        );
        Ok(txid)
    }

    #[allow(dead_code)]
    pub fn remove_mined(&mut self, mined: &[TxId]) {
        for id in mined {
            if let Some(entry) = self.txs.remove(id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.size);
                for inp in entry.tx.transparent_inputs {
                    self.spent.remove(&inp.prevout);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn purge_conflicts_with_new_tip<C: ChainView>(&mut self, chain: &C) {
        // Simple approach: drop txs whose inputs are no longer available.
        let mut to_drop = Vec::new();
        for (txid, entry) in self.txs.iter() {
            for inp in &entry.tx.transparent_inputs {
                if chain.lookup_outpoint(&inp.prevout).is_none() {
                    to_drop.push(*txid);
                    break;
                }
            }
        }
        self.remove_mined(&to_drop);
    }

    pub fn pending(&self) -> Vec<Transaction> {
        let mut v: Vec<_> = self.txs.values().cloned().collect();
        v.sort_by(|a, b| {
            let fee_cmp = b.fee_rate.cmp(&a.fee_rate);
            if fee_cmp == std::cmp::Ordering::Equal {
                let ha = txid(&a.tx).unwrap_or(Hash32::zero());
                let hb = txid(&b.tx).unwrap_or(Hash32::zero());
                ha.as_bytes().cmp(hb.as_bytes())
            } else {
                fee_cmp
            }
        });
        v.into_iter().map(|e| e.tx).collect()
    }

    pub fn has_tx(&self, id: &TxId) -> bool {
        self.txs.contains_key(id)
    }

    pub fn get_tx(&self, id: &TxId) -> Option<Transaction> {
        self.txs.get(id).map(|e| e.tx.clone())
    }

    fn lowest_fee_rate(&self) -> Option<(TxId, u64, usize)> {
        self.txs
            .iter()
            .map(|(id, e)| (*id, e.fee_rate, e.size))
            .min_by(|a, b| {
                let rate_cmp = a.1.cmp(&b.1);
                if rate_cmp == std::cmp::Ordering::Equal {
                    a.0.as_bytes().cmp(b.0.as_bytes())
                } else {
                    rate_cmp
                }
            })
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
        use k256::ecdsa::SigningKey;
        use k256::EncodedPoint;
        use k256::elliptic_curve::rand_core::OsRng;
        use nulla_core::{TransparentInput, TransparentOutput, PROTOCOL_VERSION};

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
                value: Amount::from_atoms(prev_value - BASE_FEE_ATOMS),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::from_atoms(BASE_FEE_ATOMS),
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

    fn make_tx_with_fee(
        sk: &SigningKey,
        prev: OutPoint,
        prev_value: u64,
        fee: u64,
    ) -> Transaction {
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let output_value = prev_value.saturating_sub(fee).saturating_sub(1);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: prev,
                pubkey: pubkey.clone(),
                sig: vec![],
            }],
            transparent_outputs: vec![TransparentOutput {
                value: Amount::from_atoms(output_value),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::from_atoms(fee),
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
        chain.utxos.insert(prev, (BASE_FEE_ATOMS + 10, pk_hash));

        let tx = make_tx(&sk, prev, BASE_FEE_ATOMS + 10);
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
                value: Amount::from_atoms(BASE_FEE_ATOMS),
                pubkey_hash: [0u8; 20],
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::from_atoms(BASE_FEE_ATOMS),
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
        chain.utxos.insert(prev, (BASE_FEE_ATOMS + 10, pk_hash));

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
                value: Amount::from_atoms(BASE_FEE_ATOMS),
                pubkey_hash: pk_hash,
            }],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::from_atoms(BASE_FEE_ATOMS),
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
        chain.utxos.insert(prev, (BASE_FEE_ATOMS + 10, pk_hash));
        let mut mempool = Mempool::new();
        let tx1 = make_tx(&sk, prev, BASE_FEE_ATOMS + 10);
        mempool.submit_tx(&chain, tx1).unwrap();

        let tx2 = make_tx(&sk, prev, BASE_FEE_ATOMS + 10);
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
            fee: Amount::from_atoms(BASE_FEE_ATOMS),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        let mut mempool = Mempool::new();
        let err = mempool.submit_tx(&chain, tx).unwrap_err();
        matches!(err, SubmitError::InsufficientInputValue);
    }

    #[test]
    fn evicts_lowest_fee_rate_when_full() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        // Two UTXOs for two inputs.
        let prev1 = OutPoint { txid: Hash32::from([1u8;32]), vout: 0 };
        let prev2 = OutPoint { txid: Hash32::from([2u8;32]), vout: 0 };
        let prev3 = OutPoint { txid: Hash32::from([3u8;32]), vout: 0 };
        chain.utxos.insert(prev1, (10_000, pk_hash));
        chain.utxos.insert(prev2, (10_000, pk_hash));
        chain.utxos.insert(prev3, (10_000, pk_hash));

        let mut mempool = Mempool::with_limits(2, 10_000); // tiny for test

        let tx_low = make_tx_with_fee(&sk, prev1, 10_000, BASE_FEE_ATOMS); // low fee
        let low_id = mempool.submit_tx(&chain, tx_low).expect("low ok");

        let tx_mid = make_tx_with_fee(&sk, prev2, 10_000, BASE_FEE_ATOMS * 2);
        let mid_id = mempool.submit_tx(&chain, tx_mid).expect("mid ok");

        // Now pool full; submit high-fee should evict lowest (low_id).
        let tx_high = make_tx_with_fee(&sk, prev3, 10_000, BASE_FEE_ATOMS * 4);
        let high_id = mempool.submit_tx(&chain, tx_high).expect("high ok");

        assert!(mempool.has_tx(&mid_id));
        assert!(mempool.has_tx(&high_id));
        assert!(!mempool.has_tx(&low_id));
    }

    #[test]
    fn pool_full_rejects_lower_fee_rate() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = Vec::from(EncodedPoint::from(sk.verifying_key()).as_bytes());
        let pk_hash = p2pkh_hash(&pubkey);
        let mut chain = FakeChain {
            utxos: HashMap::new(),
        };
        let prev1 = OutPoint { txid: Hash32::from([4u8;32]), vout: 0 };
        let prev2 = OutPoint { txid: Hash32::from([5u8;32]), vout: 0 };
        chain.utxos.insert(prev1, (10_000, pk_hash));
        chain.utxos.insert(prev2, (10_000, pk_hash));

        let mut mempool = Mempool::with_limits(1, 5_000); // single slot
        let tx_high = make_tx_with_fee(&sk, prev1, 10_000, BASE_FEE_ATOMS * 4);
        mempool.submit_tx(&chain, tx_high).expect("high ok");

        let tx_low = make_tx_with_fee(&sk, prev2, 10_000, BASE_FEE_ATOMS);
        let err = mempool.submit_tx(&chain, tx_low).unwrap_err();
        matches!(err, SubmitError::PoolFull);
    }
}
