use std::collections::{HashMap, HashSet};
use std::path::Path;

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use nulla_consensus::{tip_is_better, validate_block_with_prev_bits, work_from_bits};
use nulla_core::{block_header_hash, txid, Amount, Block, Hash32, OutPoint, TransactionKind, GENESIS_HASH_BYTES};
use nulla_state::LedgerState;
use num_bigint::BigUint;
use sled::transaction::{Transactional, TransactionResult};
use sled::Error as SledError;

// Consensus-critical validation is delegated to nulla-consensus; this module only handles storage and tip selection.

const TREE_BLOCKS: &str = "blocks";
const TREE_INDEX: &str = "index";
const TREE_META: &str = "meta";
const TREE_UTXOS: &str = "utxos";
const KEY_BEST: &[u8] = b"best";

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct IndexRecord {
    pub height: u64,
    pub bits: u32,
    pub timestamp: u64,
    pub prev: Hash32,
    pub cumulative_work: Vec<u8>, // BigUint BE bytes
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct UtxoRecord {
    pub value: u64,
    pub pubkey_hash: [u8; 20],
    pub height: u64,
}

#[allow(dead_code)]
pub struct ChainDb {
    db: sled::Db,
    blocks: sled::Tree,
    index: sled::Tree,
    meta: sled::Tree,
    utxos: sled::Tree,
}

impl Clone for ChainDb {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            blocks: self.blocks.clone(),
            index: self.index.clone(),
            meta: self.meta.clone(),
            utxos: self.utxos.clone(),
        }
    }
}

#[allow(dead_code)]
impl ChainDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| e.to_string())?;
        let blocks = db.open_tree(TREE_BLOCKS).map_err(|e| e.to_string())?;
        let index = db.open_tree(TREE_INDEX).map_err(|e| e.to_string())?;
        let meta = db.open_tree(TREE_META).map_err(|e| e.to_string())?;
        let utxos = db.open_tree(TREE_UTXOS).map_err(|e| e.to_string())?;
        Ok(Self { db, blocks, index, meta, utxos })
    }

    pub fn get_block(&self, hash: &Hash32) -> Result<Option<Block>, String> {
        if let Some(bytes) = self.blocks.get(hash.as_bytes()).map_err(|e| e.to_string())? {
            let blk = Block::try_from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(blk))
        } else {
            Ok(None)
        }
    }

    pub fn has_block(&self, hash: &Hash32) -> Result<bool, String> {
        self.blocks
            .contains_key(hash.as_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn get_index(&self, hash: &Hash32) -> Result<Option<IndexRecord>, String> {
        if let Some(bytes) = self.index.get(hash.as_bytes()).map_err(|e| e.to_string())? {
            let rec = IndexRecord::try_from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(rec))
        } else {
            Ok(None)
        }
    }

    pub fn get_utxo(&self, op: &nulla_core::OutPoint) -> Result<Option<UtxoRecord>, String> {
        let key = outpoint_key(op);
        if let Some(bytes) = self.utxos.get(key).map_err(|e| e.to_string())? {
            let rec = UtxoRecord::try_from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(rec))
        } else {
            Ok(None)
        }
    }

    pub fn put_utxo(&self, op: &nulla_core::OutPoint, rec: &UtxoRecord) -> Result<(), String> {
        let key = outpoint_key(op);
        let bytes = to_vec(rec).map_err(|e| e.to_string())?;
        self.utxos.insert(key, bytes).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn del_utxo(&self, op: &nulla_core::OutPoint) -> Result<(), String> {
        let key = outpoint_key(op);
        self.utxos.remove(key).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn clear_utxos(&self) -> Result<(), String> {
        self.utxos.clear().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn all_utxos(&self) -> Result<Vec<(OutPoint, UtxoRecord)>, String> {
        let mut out = Vec::new();
        for item in self.utxos.iter() {
            let (k, v) = item.map_err(|e| e.to_string())?;
            if k.len() != 36 {
                continue;
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&k[0..32]);
            let mut vout_bytes = [0u8; 4];
            vout_bytes.copy_from_slice(&k[32..36]);
            let vout = u32::from_le_bytes(vout_bytes);
            let op = OutPoint {
                txid: Hash32(txid),
                vout,
            };
            let rec = UtxoRecord::try_from_slice(&v).map_err(|e| e.to_string())?;
            out.push((op, rec));
        }
        Ok(out)
    }

    pub fn best_tip(&self) -> Result<Option<Hash32>, String> {
        if let Some(bytes) = self.meta.get(KEY_BEST).map_err(|e| e.to_string())? {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(Hash32(arr)))
        } else {
            Ok(None)
        }
    }

    pub fn ensure_genesis(&self, genesis: &Block) -> Result<(), String> {
        let indices = self.all_indices()?;
        if indices.is_empty() {
            let work = work_from_bits(genesis.header.bits).map_err(|e| e.to_string())?;
            let idx = IndexRecord {
                height: 0,
                bits: genesis.header.bits,
                timestamp: genesis.header.timestamp,
                prev: genesis.header.prev,
                cumulative_work: work.to_bytes_be(),
            };
            self.upsert_block(Hash32::from(GENESIS_HASH_BYTES), genesis, &idx, Some(Hash32::from(GENESIS_HASH_BYTES)))?;
        }
        Ok(())
    }

    pub fn best_tip_by_work(&self) -> Result<Option<Hash32>, String> {
        let mut best: Option<(Hash32, BigUint)> = None;
        for (h, rec) in self.all_indices()? {
            let work = BigUint::from_bytes_be(&rec.cumulative_work);
            if let Some((bh, bw)) = &best {
                if tip_is_better(&work, &h, bw, bh) {
                    best = Some((h, work));
                }
            } else {
                best = Some((h, work));
            }
        }
        Ok(best.map(|(h, _)| h))
    }

    pub fn chain_from_tip(&self, tip: Hash32) -> Result<Vec<Hash32>, String> {
        let mut map = HashMap::new();
        for (h, rec) in self.all_indices()? {
            map.insert(h, rec);
        }
        let mut out = Vec::new();
        let mut cursor = tip;
        loop {
            out.push(cursor);
            let rec = map
                .get(&cursor)
                .ok_or_else(|| "missing index".to_string())?;
            if rec.prev == Hash32::zero() {
                break;
            }
            cursor = rec.prev;
        }
        Ok(out)
    }

    pub fn missing_blocks_on_chain(&self, chain: &[Hash32]) -> Result<Vec<Hash32>, String> {
        let mut missing = Vec::new();
        for h in chain {
            if !self.has_block(h)? {
                missing.push(*h);
            }
        }
        Ok(missing)
    }

    pub fn store_block_if_index_matches(&self, block: &Block) -> Result<(), String> {
        let hash = block_hash(block);
        let idx = self
            .get_index(&hash)?
            .ok_or_else(|| "index missing for block".to_string())?;
        let header = &block.header;
        if header.prev != idx.prev
            || header.bits != idx.bits
            || header.timestamp != idx.timestamp
        {
            return Err("block header does not match index".into());
        }
        self.blocks
            .insert(hash.as_bytes(), to_vec(block).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    #[cfg(test)]
    pub fn clear_best(&self) -> Result<(), String> {
        self.meta.remove(KEY_BEST).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn upsert_block(
        &self,
        hash: Hash32,
        block: &Block,
        index: &IndexRecord,
        best: Option<Hash32>,
    ) -> Result<(), String> {
        let blk_bytes = to_vec(block).map_err(|e| e.to_string())?;
        let idx_bytes = to_vec(index).map_err(|e| e.to_string())?;
        let best_bytes = best.map(|h| h.as_bytes().to_vec());

        let res: TransactionResult<(), SledError> =
            (&self.blocks, &self.index, &self.meta).transaction(|(blocks, index, meta)| {
                blocks.insert(hash.as_bytes(), blk_bytes.clone())?;
                index.insert(hash.as_bytes(), idx_bytes.clone())?;
                if let Some(b) = &best_bytes {
                    meta.insert(KEY_BEST, b.clone())?;
                }
                Ok(())
            });

        res.map_err(|e| e.to_string())
    }

    pub fn all_indices(&self) -> Result<Vec<(Hash32, IndexRecord)>, String> {
        let mut out = Vec::new();
        for item in self.index.iter() {
            let (k, v) = item.map_err(|e| e.to_string())?;
            let rec = IndexRecord::try_from_slice(&v).map_err(|e| e.to_string())?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&k);
            out.push((Hash32(hash), rec));
        }
        Ok(out)
    }
}

#[allow(dead_code)]
pub struct ChainStore {
    entries: HashMap<Hash32, ChainEntry>,
    best: Hash32,
    db: ChainDb,
}

#[derive(Clone)]
pub struct ChainEntry {
    pub block: Block,
    pub height: u64,
    pub cumulative_work: BigUint,
}

impl ChainStore {
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn load_or_init(path: &Path, genesis: Block) -> Result<Self, String> {
        let db = ChainDb::open(path)?;
        Self::load_or_init_with_db(db, genesis)
    }

    pub fn load_or_init_with_db(db: ChainDb, genesis: Block) -> Result<Self, String> {
        let genesis_hash = hash32_from_bytes(&GENESIS_HASH_BYTES);
        if block_hash(&genesis) != genesis_hash {
            return Err("genesis hash mismatch".into());
        }

        let indices = db.all_indices()?;
        if indices.is_empty() {
            let work = work_from_bits(genesis.header.bits).map_err(|e| e.to_string())?;
            let idx = IndexRecord {
                height: 0,
                bits: genesis.header.bits,
                timestamp: genesis.header.timestamp,
                prev: genesis.header.prev,
                cumulative_work: work.to_bytes_be(),
            };
            db.upsert_block(genesis_hash, &genesis, &idx, Some(genesis_hash))?;
        }

        let mut entries = HashMap::new();
        let meta_best = db.best_tip()?;
        let mut best = meta_best.map(|h| (h, BigUint::default()));

        for (h, rec) in db.all_indices()? {
            let block = db
                .get_block(&h)?
                .ok_or_else(|| "block missing for index".to_string())?;
            let cum = BigUint::from_bytes_be(&rec.cumulative_work);
            let entry = ChainEntry {
                block,
                height: rec.height,
                cumulative_work: cum.clone(),
            };
            if let Some((best_h, best_cum)) = best.as_ref() {
                if tip_is_better(&cum, &h, best_cum, best_h) {
                    best = Some((h, cum));
                }
            } else {
                best = Some((h, cum));
            }
            entries.insert(h, entry);
        }

        let best_hash = if let Some((h, _)) = best {
            h
        } else {
            return Err("no tip found after load".into());
        };

        let store = Self { entries, best: best_hash, db };
        store.rebuild_utxos(best_hash)?;
        Ok(store)
    }

    pub fn best_hash(&self) -> Hash32 {
        self.best
    }

    pub fn best_bits(&self) -> u32 {
        self.entries[&self.best].block.header.bits
    }

    pub fn best_entry(&self) -> &ChainEntry {
        &self.entries[&self.best]
    }

    pub fn entry(&self, hash: &Hash32) -> Option<&ChainEntry> {
        self.entries.get(hash)
    }

    pub fn utxo_lookup(&self, out: &OutPoint) -> Option<UtxoRecord> {
        self.db.get_utxo(out).ok().flatten()
    }

    #[cfg(feature = "dev-pow")]
    pub fn db(&self) -> &ChainDb {
        &self.db
    }

    pub fn median_time_past(&self, prev: Hash32) -> Option<u64> {
        let mut ts = Vec::new();
        let mut cursor = prev;
        for _ in 0..11 {
            let entry = self.entries.get(&cursor)?;
            ts.push(entry.block.header.timestamp);
            if entry.block.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.block.header.prev;
        }
        nulla_consensus::median_time_past(&ts)
    }

    pub fn active_chain_hashes(&self, tip: Hash32) -> Result<Vec<Hash32>, String> {
        active_chain_hashes_in(&self.entries, tip)
    }

    pub fn rebuild_state(&self) -> LedgerState {
        let mut state = LedgerState::new();
        for (height, hash) in self
            .active_chain_hashes(self.best)
            .unwrap()
            .into_iter()
            .enumerate()
        {
            let entry = &self.entries[&hash];
            state
                .apply_block(height as u64, &entry.block)
                .expect("replay must succeed");
        }
        state
    }

    fn persist_utxos(&self, utxos: &HashMap<OutPoint, UtxoRecord>) -> Result<(), String> {
        self.db.clear_utxos()?;
        for (op, rec) in utxos {
            self.db.put_utxo(op, rec)?;
        }
        Ok(())
    }

    fn rebuild_utxos(&self, tip: Hash32) -> Result<(), String> {
        let utxos = Self::compute_utxos_for_tip(&self.entries, tip)?;
        self.persist_utxos(&utxos)
    }

    fn compute_utxos_for_tip(
        entries: &HashMap<Hash32, ChainEntry>,
        tip: Hash32,
    ) -> Result<HashMap<OutPoint, UtxoRecord>, String> {
        let mut utxos: HashMap<OutPoint, UtxoRecord> = HashMap::new();
        let chain = active_chain_hashes_in(entries, tip)?;

        for (height, hash) in chain.into_iter().enumerate() {
            let entry = entries.get(&hash).ok_or("missing entry")?;
            let block_height = height as u64;
            let mut fee_sum = Amount::zero();

            for tx in entry.block.txs.iter() {
                let txid = txid(tx).map_err(|e| e.to_string())?;

                // Basic per-tx checks (structural already enforced elsewhere).
                let mut seen_inputs = HashSet::new();
                let mut input_total: u64 = 0;

                for inp in &tx.transparent_inputs {
                    if !seen_inputs.insert(inp.prevout) {
                        return Err("duplicate transparent input".into());
                    }
                    let prev = utxos
                        .remove(&inp.prevout)
                        .ok_or("transparent input not found")?;
                    input_total = input_total
                        .checked_add(prev.value)
                        .ok_or("input overflow")?;
                }

                let mut output_total: u64 = 0;
                for (vout, out) in tx.transparent_outputs.iter().enumerate() {
                    output_total = output_total
                        .checked_add(out.value.atoms())
                        .ok_or("output overflow")?;
                    let op = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let rec = UtxoRecord {
                        value: out.value.atoms(),
                        pubkey_hash: out.pubkey_hash,
                        height: block_height,
                    };
                    if utxos.insert(op, rec).is_some() {
                        return Err("duplicate outpoint insertion".into());
                    }
                }

                if tx.kind == TransactionKind::Regular {
                    let fee_atoms = tx.fee.atoms();
                    let required = output_total
                        .checked_add(fee_atoms)
                        .ok_or("fee overflow")?;
                    if input_total < required {
                        return Err("insufficient transparent input value".into());
                    }
                    fee_sum = fee_sum.checked_add(tx.fee).map_err(|e| format!("{e:?}"))?;
                } else {
                    if !tx.transparent_inputs.is_empty() {
                        return Err("coinbase may not have transparent inputs".into());
                    }
                }
            }

            // coinbase fee claim check: tx[0] is coinbase by construction.
            if let Some(coinbase) = entry.block.txs.first() {
                if coinbase.claimed_fees != fee_sum {
                    return Err("coinbase claimed_fees mismatch".into());
                }
            }
        }

        Ok(utxos)
    }

    pub fn preview_commitment_root(
        &self,
        prev: Hash32,
        txs: &[nulla_core::Transaction],
    ) -> Result<Hash32, String> {
        let mut state = LedgerState::new();
        for (idx, h) in self.active_chain_hashes(prev)?.into_iter().enumerate() {
            let entry = self.entries.get(&h).unwrap();
            state
                .apply_block(idx as u64, &entry.block)
                .map_err(|e| format!("{e:?}"))?;
        }
        state
            .preview_root_after(txs)
            .map_err(|_| "preview failed".into())
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), String> {
        let prev = block.header.prev;
        let prev_entry = self.entries.get(&prev).ok_or("prev not found")?;
        let mtp = self.median_time_past(prev).ok_or("missing mtp")?;

        validate_block_with_prev_bits(prev_entry.block.header.bits, Some(mtp), &block)
            .map_err(|e| format!("{e:?}"))?;

        let work = work_from_bits(block.header.bits).map_err(|e| e.to_string())?;
        let cum_work = &prev_entry.cumulative_work + work;
        let height = prev_entry.height + 1;
        let hash = block_hash(&block);

        let idx = IndexRecord {
            height,
            bits: block.header.bits,
            timestamp: block.header.timestamp,
            prev,
            cumulative_work: cum_work.to_bytes_be(),
        };

        let best_before = self.best_entry();
        let should_update = tip_is_better(&cum_work, &hash, &best_before.cumulative_work, &self.best);

        let entry = ChainEntry {
            block,
            height,
            cumulative_work: cum_work,
        };

        if should_update {
            let mut preview_entries = self.entries.clone();
            preview_entries.insert(hash, entry.clone());
            let utxos = Self::compute_utxos_for_tip(&preview_entries, hash)?;

            self.db
                .upsert_block(hash, &entry.block, &idx, Some(hash))?;

            self.entries.insert(hash, entry);
            self.best = hash;
            self.persist_utxos(&utxos)?;
        } else {
            self.db.upsert_block(hash, &entry.block, &idx, None)?;
            self.entries.insert(hash, entry);
        }
        Ok(())
    }
}

fn block_hash(block: &Block) -> Hash32 {
    block_header_hash(&block.header).expect("hash must succeed")
}

fn hash32_from_bytes(bytes: &[u8; 32]) -> Hash32 {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Hash32(arr)
}

fn outpoint_key(op: &nulla_core::OutPoint) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(op.txid.as_bytes());
    key.extend_from_slice(&op.vout.to_le_bytes());
    key
}

fn active_chain_hashes_in(
    entries: &HashMap<Hash32, ChainEntry>,
    tip: Hash32,
) -> Result<Vec<Hash32>, String> {
    let mut out = Vec::new();
    let mut cursor = tip;
    loop {
        out.push(cursor);
        let entry = entries.get(&cursor).ok_or("missing entry")?;
        if entry.block.header.prev == Hash32::zero() {
            break;
        }
        cursor = entry.block.header.prev;
    }
    out.reverse();
    Ok(out)
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    #[cfg(feature = "dev-pow")]
    use super::*;
    #[cfg(feature = "dev-pow")]
    use nulla_core::{
        txid, Amount, BlockHeader, Commitment, Transaction, TransactionKind, GENESIS_BITS,
        GENESIS_NONCE, GENESIS_TIMESTAMP, PROTOCOL_VERSION,
    };
    #[cfg(feature = "dev-pow")]
    use tempfile::tempdir;

    #[cfg(feature = "dev-pow")]
    fn coinbase_tx(height: u64, subsidy: Amount) -> Transaction {
        Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Coinbase,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![coinbase_commitment(height)],
            fee: Amount::zero(),
            claimed_subsidy: subsidy,
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        }
    }

    #[cfg(feature = "dev-pow")]
    fn coinbase_commitment(height: u64) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[8..16].copy_from_slice(&height.to_le_bytes());
        Commitment(bytes)
    }

    #[cfg(feature = "dev-pow")]
    fn tx_merkle_root(txs: &[Transaction]) -> Hash32 {
        if txs.is_empty() {
            return Hash32::zero();
        }
        let mut acc = Hash32::zero();
        for tx in txs {
            let h = txid(tx).expect("txid");
            acc = xor_hash(acc, h);
        }
        acc
    }

    #[cfg(feature = "dev-pow")]
    fn xor_hash(a: Hash32, b: Hash32) -> Hash32 {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = a.as_bytes()[i] ^ b.as_bytes()[i];
        }
        Hash32(out)
    }

    #[cfg(feature = "dev-pow")]
    fn make_genesis() -> Block {
        let txs = vec![coinbase_tx(0, Amount::from_atoms(800_000_000))];
        let state = LedgerState::new();
        let commitment_root = state.preview_root_after(&txs).expect("preview");
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev: Hash32::zero(),
            tx_merkle_root: tx_merkle_root(&txs),
            commitment_root,
            timestamp: GENESIS_TIMESTAMP,
            bits: GENESIS_BITS,
            nonce: GENESIS_NONCE,
        };
        Block { header, txs }
    }

    #[cfg(feature = "dev-pow")]
    fn build_block(chain: &ChainStore, height: u64, bits: u32) -> Block {
        let prev = chain.best_hash();
        let prev_entry = chain.entry(&prev).unwrap();
        let coinbase = coinbase_tx(height, Amount::from_atoms(800_000_000));
        let txs = vec![coinbase];
        let commitment_root = chain
            .preview_commitment_root(prev, &txs)
            .expect("preview");
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev,
            tx_merkle_root: tx_merkle_root(&txs),
            commitment_root,
            timestamp: prev_entry.block.header.timestamp + 1,
            bits,
            nonce: 0,
        };
        Block { header, txs }
    }

    #[test]
    #[cfg(feature = "dev-pow")]
    fn restart_preserves_best_tip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = make_genesis();
        {
            let mut chain = ChainStore::load_or_init(&path, genesis.clone()).unwrap();
            for h in 1..=5 {
                let blk = build_block(&chain, h, GENESIS_BITS);
                chain.insert_block(blk).unwrap();
            }
            assert_eq!(chain.best_entry().height, 5);
        }
        let chain = ChainStore::load_or_init(&path, genesis).unwrap();
        assert_eq!(chain.best_entry().height, 5);
    }

    #[test]
    #[cfg(feature = "dev-pow")]
    fn restart_chooses_heaviest_fork() {
        use nulla_consensus::{bits_to_target, target_to_bits};

        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = make_genesis();
        {
            let mut chain = ChainStore::load_or_init(&path, genesis.clone()).unwrap();
            // Easy branch: two blocks at genesis bits.
            let a1 = build_block(&chain, 1, GENESIS_BITS);
            chain.insert_block(a1.clone()).unwrap();
            let a2 = build_block(&chain, 2, GENESIS_BITS);
            chain.insert_block(a2).unwrap();

            // Harder single block fork from genesis.
            let base_target = bits_to_target(GENESIS_BITS).unwrap();
            let hard_target = &base_target / 4u32; // much harder
            let hard_bits = target_to_bits(&hard_target).unwrap();
            let b1 = {
                let prev = Hash32::from(GENESIS_HASH_BYTES);
                let coinbase = coinbase_tx(1, Amount::from_atoms(800_000_000));
                let txs = vec![coinbase];
                let commitment_root = chain.preview_commitment_root(prev, &txs).unwrap();
                let header = BlockHeader {
                    version: PROTOCOL_VERSION,
                    prev,
                    tx_merkle_root: tx_merkle_root(&txs),
                    commitment_root,
                    timestamp: GENESIS_TIMESTAMP + 1,
                    bits: hard_bits,
                    nonce: 0,
                };
                Block { header, txs }
            };
            chain.insert_block(b1).unwrap();
        }

        let chain = ChainStore::load_or_init(&path, genesis).unwrap();
        // Best tip should be the harder fork (height 1 but higher work).
        assert_eq!(chain.best_entry().height, 1);
    }

    #[test]
    #[cfg(feature = "dev-pow")]
    fn recovery_when_best_tip_meta_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = make_genesis();
        {
            let mut chain = ChainStore::load_or_init(&path, genesis.clone()).unwrap();
            let blk = build_block(&chain, 1, GENESIS_BITS);
            chain.insert_block(blk).unwrap();
            chain.db().clear_best().unwrap();
        }

        let chain = ChainStore::load_or_init(&path, genesis).unwrap();
        assert_eq!(chain.best_entry().height, 1);
    }

    #[test]
    #[cfg(feature = "dev-pow")]
    fn print_genesis_hash_for_debug() {
        let g = make_genesis();
        let h = block_hash(&g);
        println!("genesis_hash={h:?}");
    }
}
