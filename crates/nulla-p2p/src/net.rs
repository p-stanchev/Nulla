use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
    #[error("policy: {0}")]
    Policy(String),
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct HeaderRecord {
    header: BlockHeader,
    height: u64,
    cumulative_work: Vec<u8>, // BigUint BE
}

pub struct HeaderStore {
    _db: sled::Db,
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
            _db: db,
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
        // Genesis body is hardcoded locally; mark as present to avoid redundant fetches.
        store
            .have_block
            .insert(Hash32::from(GENESIS_HASH_BYTES), true);
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

    pub fn height_of(&self, hash: &Hash32) -> Option<u64> {
        self.entries.get(hash).map(|e| e.height)
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
        // Build the best chain from genesis forward.
        let mut chain = Vec::new();
        let mut cursor = self.best;
        while let Some(entry) = self.entries.get(&cursor) {
            chain.push(entry.header.clone());
            if entry.header.prev == Hash32::zero() {
                break;
            }
            cursor = entry.header.prev;
        }
        chain.reverse();

        // Find the first locator we know and start after it.
        let mut start_idx = 0usize;
        for h in locator {
            if let Some(idx) = chain
                .iter()
                .position(|hdr| block_header_hash(hdr).ok() == Some(*h))
            {
                start_idx = idx.saturating_add(1);
                break;
            }
        }

        let mut out = Vec::new();
        for hdr in chain.into_iter().skip(start_idx) {
            if let Some(stop_hash) = stop {
                if block_header_hash(&hdr).ok() == Some(stop_hash) {
                    break;
                }
            }
            if out.len() >= max {
                break;
            }
            out.push(hdr);
        }
        out
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Version {
    pub height: u64,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
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
    score: u32,
}

#[derive(Clone, Copy)]
pub struct Policy {
    pub max_reorg_depth: Option<u64>,
    pub ban_threshold: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_reorg_depth: Some(100),
            ban_threshold: 3,
        }
    }
}

pub struct P2pEngine {
    store: HeaderStore,
    peers: HashMap<u64, PeerState>,
    next_peer_id: u64,
    policy: Policy,
    on_block: Option<Arc<dyn Fn(&Block) -> Result<(), String> + Send + Sync>>,
}

impl P2pEngine {
    pub fn new(path: &Path, genesis: BlockHeader) -> Result<Self, P2pError> {
        Ok(Self {
            store: HeaderStore::open(path, genesis)?,
            peers: HashMap::new(),
            next_peer_id: 0,
            policy: Policy::default(),
            on_block: None,
        })
    }

    pub fn with_policy(path: &Path, genesis: BlockHeader, policy: Policy) -> Result<Self, P2pError> {
        Ok(Self {
            store: HeaderStore::open(path, genesis)?,
            peers: HashMap::new(),
            next_peer_id: 0,
            policy,
            on_block: None,
        })
    }

    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    pub fn best_hash(&self) -> Hash32 {
        self.store.best_hash()
    }

    pub fn best_entry(&self) -> &HeaderEntry {
        self.store.best_entry()
    }

    pub fn next_peer_id(&mut self) -> u64 {
        let id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1);
        id
    }

    pub fn missing_blocks_on_best(&self, max: usize) -> Vec<Hash32> {
        self.store.needs_blocks_on_best(max)
    }

    pub fn set_block_callback<F>(&mut self, cb: F)
    where
        F: Fn(&Block) -> Result<(), String> + Send + Sync + 'static,
    {
        self.on_block = Some(Arc::new(cb));
    }

    fn policy_allows_reorg(&self, prev: &Hash32) -> Result<(), P2pError> {
        if let Some(limit) = self.policy.max_reorg_depth {
            if let Some(prev_height) = self.store.height_of(prev) {
                let best_height = self.store.best_entry().height;
                if best_height > prev_height && best_height - prev_height > limit {
                    return Err(P2pError::Policy(format!(
                        "reorg depth {} exceeds limit {limit}",
                        best_height - prev_height
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn handle_message(
        &mut self,
        peer_id: u64,
        msg: Message,
    ) -> Result<Vec<(u64, Message)>, P2pError> {
        if self
            .peers
            .get(&peer_id)
            .map(|p| p.disconnected)
            .unwrap_or(false)
        {
            return Err(P2pError::Disconnected);
        }

        match msg {
            Message::Version(_) => {
                let peer = self.peers.entry(peer_id).or_default();
                peer.version_seen = true;
                let mut out = vec![(peer_id, Message::Verack)];
                out.push((peer_id, Message::Version(Version { height: self.store.best_entry().height })));
                Ok(out)
            }
            Message::Verack => {
                let peer = self.peers.entry(peer_id).or_default();
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
                    let result = self
                        .policy_allows_reorg(&h.prev)
                        .and_then(|_| self.store.accept_header(h));
                    if let Err(e) = result {
                        let peer = self.peers.entry(peer_id).or_default();
                        peer.disconnected = true;
                        peer.score += 1;
                        if peer.score >= self.policy.ban_threshold {
                            peer.disconnected = true;
                        }
                        return Err(e);
                    }
                }
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
                let blk_clone = block.clone();
                if let Err(e) = self.store.accept_block(block) {
                    let peer = self.peers.entry(peer_id).or_default();
                    peer.disconnected = true;
                    peer.score += 1;
                    return Err(e);
                }
                if let Some(cb) = &self.on_block {
                    if let Err(e) = cb(&blk_clone) {
                        let peer = self.peers.entry(peer_id).or_default();
                        peer.disconnected = true;
                        return Err(P2pError::Io(e));
                    }
                }
                Ok(Vec::new())
            }
        }
    }

    fn write_message(stream: &mut TcpStream, msg: &Message) -> Result<(), P2pError> {
        let data = to_vec(msg).map_err(|e| P2pError::Io(e.to_string()))?;
        let len = (data.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .and_then(|_| stream.write_all(&data))
            .map_err(|e| P2pError::Io(e.to_string()))
    }

    fn read_message(stream: &mut TcpStream) -> Result<Option<Message>, P2pError> {
        let mut len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(P2pError::Io(e.to_string()));
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        stream
            .read_exact(&mut data)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let msg = Message::try_from_slice(&data).map_err(|e| P2pError::Io(e.to_string()))?;
        Ok(Some(msg))
    }

    pub fn serve_incoming(engine: Arc<Mutex<P2pEngine>>, listener: TcpListener) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let mut guard = engine.lock().expect("engine");
                let peer_id = guard.next_peer_id();
                drop(guard);
                let eng = Arc::clone(&engine);
                thread::spawn(move || {
                    let mut stream = stream;
                    loop {
                        let msg = match P2pEngine::read_message(&mut stream) {
                            Ok(Some(m)) => m,
                            Ok(None) => break,
                            Err(_) => break,
                        };
                        let responses = {
                            let mut p2p = eng.lock().expect("engine");
                            match p2p.handle_message(peer_id, msg) {
                                Ok(out) => out,
                                Err(_) => break,
                            }
                        };
                        for (_, m) in responses {
                            if P2pEngine::write_message(&mut stream, &m).is_err() {
                                break;
                            }
                        }
                    }
                });
            }
        })
    }

    pub fn connect_and_sync(
        engine: Arc<Mutex<P2pEngine>>,
        addr: SocketAddr,
        initial_getblocks: Vec<Hash32>,
    ) -> Result<thread::JoinHandle<()>, P2pError> {
        let mut stream = TcpStream::connect(addr).map_err(|e| P2pError::Io(e.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let (peer_id, locator, height) = {
            let mut eng = engine.lock().expect("engine");
            (eng.next_peer_id(), eng.store.locator(), eng.best_entry().height)
        };

        P2pEngine::write_message(&mut stream, &Message::Version(Version { height }))?;
        P2pEngine::write_message(&mut stream, &Message::Verack)?;
        P2pEngine::write_message(
            &mut stream,
            &Message::GetHeaders {
                locator,
                stop: None,
            },
        )?;
        for h in &initial_getblocks {
            let _ = P2pEngine::write_message(&mut stream, &Message::GetBlock(*h));
        }

        let eng = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let mut stream = stream;
            loop {
                let msg = match P2pEngine::read_message(&mut stream) {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(_) => break,
                };
                let responses = {
                    let mut p2p = eng.lock().expect("engine");
                    match p2p.handle_message(peer_id, msg) {
                        Ok(out) => out,
                        Err(_) => break,
                    }
                };
                for (_, m) in responses {
                    if P2pEngine::write_message(&mut stream, &m).is_err() {
                        break;
                    }
                }
            }
        });
        Ok(handle)
    }
}

#[cfg(all(test, feature = "dev-pow"))]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use nulla_core::{Amount, Commitment, Transaction, TransactionKind, PROTOCOL_VERSION};

    fn genesis_header() -> BlockHeader {
        let prev = Hash32::zero();
        let tx_merkle_root =
            Hash32(hex_literal::hex!("4d89bf74b9c3633fc497f182020f31304c94b1096413687c891a57e7bb92cca3"));
        let commitment_root =
            Hash32(hex_literal::hex!("300eb2dc8d3001271ea0f2fcada9387e7f5817533d863e5a45e5bd8e5f2ca09e"));
        BlockHeader {
            version: PROTOCOL_VERSION,
            prev,
            tx_merkle_root,
            commitment_root,
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 7,
        }
    }

    fn dummy_block(header: BlockHeader) -> Block {
        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Coinbase,
            transparent_inputs: vec![],
            transparent_outputs: vec![],
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![Commitment::zero()],
            fee: Amount::zero(),
            claimed_subsidy: Amount::from_atoms(1),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };
        Block {
            header,
            txs: vec![tx],
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

    #[test]
    fn sockets_sync_headers_and_blocks() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let genesis = genesis_header();
        let eng_a = Arc::new(Mutex::new(P2pEngine::new(&dir_a.path().join("db"), genesis.clone()).unwrap()));
        let eng_b = Arc::new(Mutex::new(P2pEngine::new(&dir_b.path().join("db"), genesis.clone()).unwrap()));

        // Prepare a block on node A.
        let child = make_child(&genesis, genesis.bits, genesis.timestamp + 1);
        let block = dummy_block(child.clone());
        {
            let mut a = eng_a.lock().unwrap();
            a.handle_message(0, Message::Headers(vec![child.clone()])).unwrap();
            a.handle_message(0, Message::Block(block)).unwrap();
        }

        // Wire sockets.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server_stream, _) = listener.accept().unwrap();
        client.set_nodelay(true).unwrap();
        server_stream.set_nodelay(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let locator = { eng_b.lock().unwrap().store.locator() };
        P2pEngine::write_message(&mut client, &Message::Version(Version { height: 0 })).unwrap();
        P2pEngine::write_message(&mut client, &Message::Verack).unwrap();
        P2pEngine::write_message(
            &mut client,
            &Message::GetHeaders {
                locator,
                stop: None,
            },
        )
        .unwrap();

        for _ in 0..20 {
            if let Ok(Some(msg)) = P2pEngine::read_message(&mut server_stream) {
                let responses = {
                    let mut p2p = eng_a.lock().unwrap();
                    p2p.handle_message(0, msg).expect("server handle")
                };
                for (_, m) in responses {
                    P2pEngine::write_message(&mut server_stream, &m).unwrap();
                }
            }
            match P2pEngine::read_message(&mut client) {
                Ok(Some(msg)) => {
                    let responses = {
                        let mut p2p = eng_b.lock().unwrap();
                        p2p.handle_message(1, msg).expect("client handle")
                    };
                    for (_, m) in responses {
                        P2pEngine::write_message(&mut client, &m).unwrap();
                    }
                }
                Ok(None) | Err(_) => {}
            }
        }

        let b = eng_b.lock().unwrap();
        assert_eq!(b.best_entry().height, 1);
        assert!(b.missing_blocks_on_best(10).is_empty());
    }

    #[test]
    fn policy_limits_reorg_depth() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let policy = Policy {
            max_reorg_depth: Some(0),
            ban_threshold: 1,
        };
        let mut p2p = P2pEngine::with_policy(&path, genesis.clone(), policy).unwrap();

        let h1 = make_child(&genesis, genesis.bits, genesis.timestamp + 1);
        let h2 = make_child(&h1, genesis.bits, h1.timestamp + 1);
        p2p.handle_message(1, Message::Headers(vec![h1.clone(), h2.clone()])).unwrap();

        // Competing fork from genesis should exceed policy depth.
        let fork = make_child(&genesis, genesis.bits, genesis.timestamp + 2);
        let err = p2p
            .handle_message(2, Message::Headers(vec![fork]))
            .expect_err("policy should reject deep reorg");
        matches!(err, P2pError::Policy(_));
    }
}
