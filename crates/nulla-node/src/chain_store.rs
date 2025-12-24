use std::collections::HashMap;
use std::path::Path;

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use nulla_consensus::{tip_is_better, validate_block_with_prev_bits, work_from_bits};
use nulla_core::{block_header_hash, Block, Hash32, GENESIS_HASH_BYTES};
use nulla_state::LedgerState;
use num_bigint::BigUint;
use sled::transaction::{Transactional, TransactionResult};
use sled::Error as SledError;

// Consensus-critical validation is delegated to nulla-consensus; this module only handles storage and tip selection.

const TREE_BLOCKS: &str = "blocks";
const TREE_INDEX: &str = "index";
const TREE_META: &str = "meta";
const KEY_BEST: &[u8] = b"best";

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct IndexRecord {
    pub height: u64,
    pub bits: u32,
    pub timestamp: u64,
    pub prev: Hash32,
    pub cumulative_work: Vec<u8>, // BigUint BE bytes
}

#[allow(dead_code)]
pub struct ChainDb {
    db: sled::Db,
    blocks: sled::Tree,
    index: sled::Tree,
    meta: sled::Tree,
}

#[allow(dead_code)]
impl ChainDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| e.to_string())?;
        let blocks = db.open_tree(TREE_BLOCKS).map_err(|e| e.to_string())?;
        let index = db.open_tree(TREE_INDEX).map_err(|e| e.to_string())?;
        let meta = db.open_tree(TREE_META).map_err(|e| e.to_string())?;
        Ok(Self { db, blocks, index, meta })
    }

    pub fn get_block(&self, hash: &Hash32) -> Result<Option<Block>, String> {
        if let Some(bytes) = self.blocks.get(hash.as_bytes()).map_err(|e| e.to_string())? {
            let blk = Block::try_from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(blk))
        } else {
            Ok(None)
        }
    }

    pub fn get_index(&self, hash: &Hash32) -> Result<Option<IndexRecord>, String> {
        if let Some(bytes) = self.index.get(hash.as_bytes()).map_err(|e| e.to_string())? {
            let rec = IndexRecord::try_from_slice(&bytes).map_err(|e| e.to_string())?;
            Ok(Some(rec))
        } else {
            Ok(None)
        }
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

pub struct ChainStore {
    entries: HashMap<Hash32, ChainEntry>,
    best: Hash32,
    db: ChainDb,
}

pub struct ChainEntry {
    pub block: Block,
    pub height: u64,
    pub cumulative_work: BigUint,
}

impl ChainStore {
    pub fn load_or_init(path: &Path, genesis: Block) -> Result<Self, String> {
        let db = ChainDb::open(path)?;

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

        Ok(Self { entries, best: best_hash, db })
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

    #[cfg(test)]
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
        let mut out = Vec::new();
        let mut cursor = tip;
        loop {
            out.push(cursor);
            let entry = self.entries.get(&cursor).ok_or("missing entry")?;
            if entry.block.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.block.header.prev;
        }
        out.reverse();
        Ok(out)
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

        self.db
            .upsert_block(hash, &block, &idx, should_update.then_some(hash))?;

        let entry = ChainEntry {
            block,
            height,
            cumulative_work: cum_work,
        };
        self.entries.insert(hash, entry);
        if should_update {
            self.best = hash;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xor_hash;
    use nulla_core::{
        txid, Amount, BlockHeader, Commitment, Transaction, TransactionKind, GENESIS_BITS,
        GENESIS_NONCE, GENESIS_TIMESTAMP, PROTOCOL_VERSION,
    };
    use tempfile::tempdir;

    fn coinbase_tx(height: u64, subsidy: Amount) -> Transaction {
        Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Coinbase,
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

    fn coinbase_commitment(height: u64) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[8..16].copy_from_slice(&height.to_le_bytes());
        Commitment(bytes)
    }

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
}
