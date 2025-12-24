use std::collections::HashMap;
use std::path::Path;

use borsh::{to_vec, BorshDeserialize, BorshSerialize};
use nulla_consensus::{
    median_time_past, tip_is_better, validate_block_with_prev_bits, validate_header_with_prev_bits,
    work_from_bits,
};
use nulla_core::{block_header_hash, Block, BlockHeader, Hash32, GENESIS_HASH_BYTES};
use num_bigint::BigUint;
use thiserror::Error;

const TREE_HEADERS: &str = "headers";
const TREE_META: &str = "meta";
const TREE_BLOCKS: &str = "blocks";
const KEY_BEST: &[u8] = b"best";

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("io: {0}")]
    Io(String),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("invalid block: {0}")]
    InvalidBlock(String),
    #[error("unknown prev")]
    UnknownPrev,
    #[error("disconnected")]
    Disconnected,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct HeaderRecord {
    header: BlockHeader,
    height: u64,
    cumulative_work: Vec<u8>, // BigUint BE
}

pub struct HeaderStore {
    db: sled::Db,
    headers: sled::Tree,
    meta: sled::Tree,
    blocks: sled::Tree,
    entries: HashMap<Hash32, HeaderEntry>,
    have_block: HashMap<Hash32, bool>,
    best: Hash32,
}

#[derive(Clone)]
pub struct HeaderEntry {
    pub header: BlockHeader,
    pub height: u64,
    pub cumulative_work: BigUint,
}

impl HeaderStore {
    pub fn open(path: &Path, genesis: BlockHeader) -> Result<Self, P2pError> {
        let db = sled::open(path).map_err(|e| P2pError::Io(e.to_string()))?;
        let headers = db
            .open_tree(TREE_HEADERS)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let meta = db
            .open_tree(TREE_META)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let blocks = db
            .open_tree(TREE_BLOCKS)
            .map_err(|e| P2pError::Io(e.to_string()))?;

        let mut store = HeaderStore {
            db,
            headers,
            meta,
            blocks,
            entries: HashMap::new(),
            have_block: HashMap::new(),
            best: Hash32::from(GENESIS_HASH_BYTES),
        };

        let hash = block_header_hash(&genesis).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        if hash != Hash32::from(GENESIS_HASH_BYTES) {
            return Err(P2pError::InvalidHeader("genesis hash mismatch".into()));
        }

        if store.headers.is_empty() {
            let work = work_from_bits(genesis.bits).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
            let rec = HeaderRecord {
                header: genesis.clone(),
                height: 0,
                cumulative_work: work.to_bytes_be(),
            };
            store
                .upsert(hash, &rec, Some(hash))
                .map_err(|e| P2pError::Io(e.to_string()))?;
        }

        // Rebuild in-memory view.
        let mut best: Option<(Hash32, BigUint)> = None;
        for item in store.headers.iter() {
            let (k, v) = item.map_err(|e| P2pError::Io(e.to_string()))?;
            let rec = HeaderRecord::try_from_slice(&v).map_err(|e| P2pError::Io(e.to_string()))?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&k);
            let work = BigUint::from_bytes_be(&rec.cumulative_work);
            let entry = HeaderEntry {
                header: rec.header.clone(),
                height: rec.height,
                cumulative_work: work.clone(),
            };
            if let Some((bh, bw)) = &best {
                if tip_is_better(&work, &Hash32(hash), bw, bh) {
                    best = Some((Hash32(hash), work));
                }
            } else {
                best = Some((Hash32(hash), work));
            }
            store.entries.insert(Hash32(hash), entry);
            let present = store
                .blocks
                .contains_key(&k)
                .map_err(|e| P2pError::Io(e.to_string()))?;
            store.have_block.insert(Hash32(hash), present);
        }
        if let Some((h, _)) = best {
            store.best = h;
        }
        Ok(store)
    }

    pub fn best_hash(&self) -> Hash32 {
        self.best
    }

    pub fn best_entry(&self) -> &HeaderEntry {
        &self.entries[&self.best]
    }

    fn upsert(
        &self,
        hash: Hash32,
        rec: &HeaderRecord,
        best: Option<Hash32>,
    ) -> Result<(), sled::Error> {
        let hdr_bytes = to_vec(rec)?;
        let best_bytes = best.map(|h| h.as_bytes().to_vec());
        // Simpler non-transactional for now; acceptable because caller persists best in same call.
        self.headers
            .insert(hash.as_bytes(), hdr_bytes)
            .map_err(|e| e)?;
        if let Some(b) = best_bytes {
            self.meta.insert(KEY_BEST, b).map_err(|e| e)?;
        }
        Ok(())
    }

    pub fn accept_block(&mut self, block: Block) -> Result<(), P2pError> {
        let hash = block_header_hash(&block.header).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        let hdr_entry = self.entries.get(&hash).ok_or(P2pError::InvalidHeader("unknown header".into()))?;

        // Header consistency.
        if block.header != hdr_entry.header {
            return Err(P2pError::InvalidHeader("block header mismatch".into()));
        }

        let prev = block.header.prev;
        let prev_entry = self.entries.get(&prev).ok_or(P2pError::UnknownPrev)?;
        let mtp = self.median_time_past(prev).ok_or(P2pError::InvalidHeader("missing mtp".into()))?;

        validate_block_with_prev_bits(prev_entry.header.bits, Some(mtp), &block)
            .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        self.blocks
            .insert(hash.as_bytes(), to_vec(&block).map_err(|e| P2pError::Io(e.to_string()))?)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        self.have_block.insert(hash, true);
        Ok(())
    }

    pub fn needs_blocks_on_best(&self, max: usize) -> Vec<Hash32> {
        let mut out = Vec::new();
        let mut cursor = self.best;
        while let Some(entry) = self.entries.get(&cursor) {
            if !self.have_block.get(&cursor).copied().unwrap_or(false) {
                out.push(cursor);
                if out.len() >= max {
                    break;
                }
            }
            if entry.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.header.prev;
        }
        out
    }

    fn median_time_past(&self, prev: Hash32) -> Option<u64> {
        let mut ts = Vec::new();
        let mut cursor = prev;
        for _ in 0..11 {
            let entry = self.entries.get(&cursor)?;
            ts.push(entry.header.timestamp);
            if entry.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.header.prev;
        }
        median_time_past(&ts)
    }

    pub fn accept_header(&mut self, header: BlockHeader) -> Result<(), P2pError> {
        let prev = header.prev;
        let prev_entry = self
            .entries
            .get(&prev)
            .ok_or(P2pError::UnknownPrev)?;
        let mtp = self.median_time_past(prev).ok_or(P2pError::InvalidHeader("missing mtp".into()))?;

        validate_header_with_prev_bits(prev_entry.header.bits, Some(mtp), &header)
            .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        let work = work_from_bits(header.bits).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        let cum = &prev_entry.cumulative_work + work;
        let height = prev_entry.height + 1;
        let hash = block_header_hash(&header).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        let rec = HeaderRecord {
            header: header.clone(),
            height,
            cumulative_work: cum.to_bytes_be(),
        };

        let best_before = self.best_entry();
        let should_update =
            tip_is_better(&cum, &hash, &best_before.cumulative_work, &self.best);

        self.upsert(hash, &rec, should_update.then_some(hash))
            .map_err(|e| P2pError::Io(e.to_string()))?;

        let entry = HeaderEntry {
            header,
            height,
            cumulative_work: cum,
        };
        self.entries.insert(hash, entry);
        if should_update {
            self.best = hash;
        }
        Ok(())
    }

    pub fn locator(&self) -> Vec<Hash32> {
        let mut locator = Vec::new();
        let mut cursor = self.best;
        let mut step = 1u64;
        let mut walked = 0u64;
        while let Some(entry) = self.entries.get(&cursor) {
            locator.push(cursor);
            if cursor == Hash32::zero() || entry.header.prev == Hash32::zero() {
                break;
            }
            walked += step;
            for _ in 0..step {
                if let Some(prev_entry) = self.entries.get(&cursor) {
                    cursor = prev_entry.header.prev;
                } else {
                    break;
                }
            }
            if locator.len() >= 10 {
                step *= 2;
            }
            if walked > entry.height {
                break;
            }
        }
        if locator.last() != Some(&Hash32::zero()) {
            locator.push(Hash32::zero());
        }
        locator
    }

    pub fn get_headers_after(
        &self,
        locator: &[Hash32],
        stop: Option<Hash32>,
        max: usize,
    ) -> Vec<BlockHeader> {
        // Find the first known locator in our chain.
        let mut start = None;
        for h in locator {
            if self.entries.contains_key(h) {
                start = Some(*h);
                break;
            }
        }
        let mut out = Vec::new();
        let mut cursor = start.unwrap_or(Hash32::zero());
        loop {
            if cursor == stop.unwrap_or(Hash32::zero()) && !out.is_empty() {
                break;
            }
            let entry = match self.entries.get(&cursor) {
                Some(e) => e,
                None => break,
            };
            if cursor != start.unwrap_or(Hash32::zero()) {
                out.push(entry.header.clone());
                if out.len() >= max {
                    break;
                }
            }
            if entry.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.header.prev;
        }
        out.reverse();
        out
    }
}

#[derive(Debug, Clone)]
pub struct Version {
    pub height: u64,
}

#[derive(Debug, Clone)]
pub enum Message {
    Version(Version),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders {
        locator: Vec<Hash32>,
        stop: Option<Hash32>,
    },
    Headers(Vec<BlockHeader>),
    GetBlock(Hash32),
    Block(Block),
}

#[derive(Default)]
struct PeerState {
    version_seen: bool,
    verack_seen: bool,
    disconnected: bool,
}

pub struct P2pEngine {
    store: HeaderStore,
    peers: HashMap<u64, PeerState>,
}

impl P2pEngine {
    pub fn new(path: &Path, genesis: BlockHeader) -> Result<Self, P2pError> {
        Ok(Self {
            store: HeaderStore::open(path, genesis)?,
            peers: HashMap::new(),
        })
    }

    pub fn best_hash(&self) -> Hash32 {
        self.store.best_hash()
    }

    pub fn best_entry(&self) -> &HeaderEntry {
        self.store.best_entry()
    }

    pub fn handle_message(&mut self, peer_id: u64, msg: Message) -> Result<Vec<(u64, Message)>, P2pError> {
        let peer = self.peers.entry(peer_id).or_default();
        if peer.disconnected {
            return Err(P2pError::Disconnected);
        }
        match msg {
            Message::Version(v) => {
                peer.version_seen = true;
                let mut out = vec![(peer_id, Message::Verack)];
                // Optionally respond with our version
                out.push((peer_id, Message::Version(Version { height: self.store.best_entry().height })));
                Ok(out)
            }
            Message::Verack => {
                peer.verack_seen = true;
                Ok(Vec::new())
            }
            Message::Ping(nonce) => Ok(vec![(peer_id, Message::Pong(nonce))]),
            Message::Pong(_) => Ok(Vec::new()),
            Message::GetHeaders { locator, stop } => {
                let headers = self.store.get_headers_after(&locator, stop, 32);
                Ok(vec![(peer_id, Message::Headers(headers))])
            }
            Message::Headers(headers) => {
                for h in headers {
                    if let Err(e) = self.store.accept_header(h) {
                        peer.disconnected = true;
                        return Err(e);
                    }
                }
                // Request missing best-chain blocks.
                let mut out = Vec::new();
                for h in self.store.needs_blocks_on_best(16) {
                    out.push((peer_id, Message::GetBlock(h)));
                }
                Ok(out)
            }
            Message::GetBlock(hash) => {
                if let Some(bytes) = self
                    .store
                    .blocks
                    .get(hash.as_bytes())
                    .map_err(|e| P2pError::Io(e.to_string()))?
                {
                    let block =
                        Block::try_from_slice(&bytes).map_err(|e| P2pError::Io(e.to_string()))?;
                    Ok(vec![(peer_id, Message::Block(block))])
                } else {
                    Ok(Vec::new())
                }
            }
            Message::Block(block) => {
                if let Err(e) = self.store.accept_block(block) {
                    peer.disconnected = true;
                    return Err(e);
                }
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(all(test, feature = "dev-pow"))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn genesis_header() -> BlockHeader {
        let prev = Hash32::zero();
        let tx_merkle_root = Hash32(hex_literal::hex!(
            "54e857af9f5afc622a84bce9e4796a2a5c982f3d503a7a40fa8e8a2687629f88"
        ));
        let commitment_root = Hash32(hex_literal::hex!(
            "300eb2dc8d3001271ea0f2fcada9387e7f5817533d863e5a45e5bd8e5f2ca09e"
        ));
        BlockHeader {
            version: 0,
            prev,
            tx_merkle_root,
            commitment_root,
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 2,
        }
    }

    fn make_child(prev: &BlockHeader, bits: u32, ts: u64) -> BlockHeader {
        BlockHeader {
            version: prev.version,
            prev: block_header_hash(prev).unwrap(),
            tx_merkle_root: Hash32::from([ts as u8; 32]),
            commitment_root: Hash32::from([(ts >> 8) as u8; 32]),
            timestamp: ts,
            bits,
            nonce: 0,
        }
    }

    #[test]
    fn heaviest_fork_wins() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis.clone()).unwrap();

        let child_easy = make_child(&genesis, 0x207f_ffff, genesis.timestamp + 1);
        let child_hard = make_child(&genesis, 0x1e00_ffff, genesis.timestamp + 2);

        p2p.handle_message(1, Message::Headers(vec![child_easy.clone()])).unwrap();
        let best_after_easy = p2p.best_hash();
        p2p.handle_message(2, Message::Headers(vec![child_hard.clone()])).unwrap();
        let best_after_hard = p2p.best_hash();
        assert_ne!(best_after_easy, best_after_hard);
        assert_eq!(best_after_hard, block_header_hash(&child_hard).unwrap());
    }

    #[test]
    fn invalid_header_disconnects() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis.clone()).unwrap();

        // Bad MTP: same timestamp as parent.
        let bad = make_child(&genesis, genesis.bits, genesis.timestamp);
        let err = p2p
            .handle_message(1, Message::Headers(vec![bad]))
            .expect_err("should drop");
        matches!(err, P2pError::InvalidHeader(_));
    }

    #[test]
    fn restart_preserves_tip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        {
            let mut p2p = P2pEngine::new(&path, genesis.clone()).unwrap();
            let h1 = make_child(&genesis, genesis.bits, genesis.timestamp + 1);
            p2p.handle_message(1, Message::Headers(vec![h1.clone()])).unwrap();
            assert_eq!(p2p.best_entry().height, 1);
        }
        let p2p = P2pEngine::new(&path, genesis.clone()).unwrap();
        assert_eq!(p2p.best_entry().height, 1);
    }
}
