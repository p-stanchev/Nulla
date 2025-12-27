use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use log::{debug, info};
use nulla_consensus::{
    median_time_past, tip_is_better, validate_block_with_prev_bits, validate_header_with_prev_bits,
    work_from_bits,
};
use nulla_core::{
    Block, BlockHeader, GENESIS_HASH_BYTES, Hash32, Transaction, block_header_hash, txid,
};
use num_bigint::BigUint;
use thiserror::Error;
use std::net::IpAddr;

const TREE_HEADERS: &str = "headers";
const TREE_META: &str = "meta";
const TREE_BLOCKS: &str = "blocks";
const TREE_ADDRS: &str = "addrbook";
const KEY_BEST: &[u8] = b"best";
const MAX_MSG_LEN: usize = 1 * 1024 * 1024; // 1MB hard cap
const MAX_HEADERS: usize = 64;
const MAX_INV_TX: usize = 1024;
const MAX_BLOCK_REQ: usize = 32;
const MAX_MSGS_PER_SEC: u32 = 200;
const MAX_ADDR_RESP: usize = 256;
const MAX_ADDR_TABLE: usize = 2000;
const ADDR_EXPIRY_SECS: u64 = 7 * 24 * 3600;
const TARGET_PEERS_FOR_GOSSIP: usize = 8;
const MAX_ADDR_FAILS: u32 = 3;
// Back off between dial attempts to the same addr; kept small for faster mesh formation.
const DIAL_BACKOFF_SECS: u64 = 15;
const GLOBAL_GETADDR_SECS: u64 = 180;
const GLOBAL_GETADDR_BATCH: usize = 2;

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

        let hash =
            block_header_hash(&genesis).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        if hash != Hash32::from(GENESIS_HASH_BYTES) {
            return Err(P2pError::InvalidHeader("genesis hash mismatch".into()));
        }

        if store.headers.is_empty() {
            let work = work_from_bits(genesis.bits)
                .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
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

    pub fn db(&self) -> sled::Db {
        self._db.clone()
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
        let hash = block_header_hash(&block.header)
            .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        let hdr_entry = self
            .entries
            .get(&hash)
            .ok_or(P2pError::InvalidHeader("unknown header".into()))?;

        // Header consistency.
        if block.header != hdr_entry.header {
            return Err(P2pError::InvalidHeader("block header mismatch".into()));
        }

        let prev = block.header.prev;
        let prev_entry = self.entries.get(&prev).ok_or(P2pError::UnknownPrev)?;
        let mtp = self
            .median_time_past(prev)
            .ok_or(P2pError::InvalidHeader("missing mtp".into()))?;

        validate_block_with_prev_bits(prev_entry.header.bits, Some(mtp), &block)
            .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        self.blocks
            .insert(
                hash.as_bytes(),
                to_vec(&block).map_err(|e| P2pError::Io(e.to_string()))?,
            )
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
        let prev_entry = self.entries.get(&prev).ok_or(P2pError::UnknownPrev)?;
        let mtp = self
            .median_time_past(prev)
            .ok_or(P2pError::InvalidHeader("missing mtp".into()))?;

        validate_header_with_prev_bits(prev_entry.header.bits, Some(mtp), &header)
            .map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        let work =
            work_from_bits(header.bits).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;
        let cum = &prev_entry.cumulative_work + work;
        let height = prev_entry.height + 1;
        let hash =
            block_header_hash(&header).map_err(|e| P2pError::InvalidHeader(format!("{e:?}")))?;

        let rec = HeaderRecord {
            header: header.clone(),
            height,
            cumulative_work: cum.to_bytes_be(),
        };

        let best_before = self.best_entry();
        let should_update = tip_is_better(&cum, &hash, &best_before.cumulative_work, &self.best);

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
    // Advertised listen port (0 if not routable / not set). IP is inferred from socket addr.
    pub listen_port: u16,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct NetAddr {
    pub ip: [u8; 16], // IPv4-mapped allowed
    pub port: u16,
    pub last_seen: u64, // unix seconds
    pub services: u32,
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
    InvTx(Vec<Hash32>),
    GetTx(Hash32),
    Tx(Transaction),
    GetAddr {
        max: u16,
    },
    Addr(Vec<NetAddr>),
}

#[derive(Default)]
struct PeerState {
    version_seen: bool,
    verack_seen: bool,
    disconnected: bool,
    height: u64,
    score: u32,
    msg_count: u32,
    window_start: Option<Instant>,
    sent_getaddr: bool,
    last_getaddr: Option<Instant>,
    addr: Option<SocketAddr>,
    inbound: bool,
    outbound: bool,
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
    outbound: HashMap<u64, mpsc::Sender<Message>>,
    next_peer_id: u64,
    policy: Policy,
    gossip_enabled: bool,
    addr_book: HashMap<SocketAddr, u64>, // last_seen
    dial_history: HashMap<SocketAddr, Instant>,
    dial_failures: HashMap<SocketAddr, u32>,
    static_peers: HashSet<SocketAddr>,
    last_global_getaddr: Option<Instant>,
    advertised_port: Option<u16>,
    on_block: Option<Arc<dyn Fn(&Block) -> Result<(), String> + Send + Sync>>,
    on_tx: Option<Arc<dyn Fn(&Transaction) -> Result<(), String> + Send + Sync>>,
    has_tx: Option<Arc<dyn Fn(&Hash32) -> bool + Send + Sync>>,
    lookup_tx: Option<Arc<dyn Fn(&Hash32) -> Option<Transaction> + Send + Sync>>,
    addr_tree: sled::Tree,
}

#[derive(Clone, Copy, serde::Serialize)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub inbound: bool,
    pub outbound: bool,
    pub height: u64,
}

impl P2pEngine {
    pub fn new(path: &Path, genesis: BlockHeader) -> Result<Self, P2pError> {
        let store = HeaderStore::open(path, genesis)?;
        let addr_tree = store
            .db()
            .open_tree(TREE_ADDRS)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let addr_book = Self::load_addr_book(&addr_tree);
        Ok(Self {
            store,
            peers: HashMap::new(),
            outbound: HashMap::new(),
            next_peer_id: 0,
            policy: Policy::default(),
            gossip_enabled: true,
            addr_book,
            dial_history: HashMap::new(),
            dial_failures: HashMap::new(),
            static_peers: HashSet::new(),
            last_global_getaddr: None,
            advertised_port: None,
            on_block: None,
            on_tx: None,
            has_tx: None,
            lookup_tx: None,
            addr_tree,
        })
    }

    pub fn with_policy(
        path: &Path,
        genesis: BlockHeader,
        policy: Policy,
    ) -> Result<Self, P2pError> {
        let store = HeaderStore::open(path, genesis)?;
        let addr_tree = store
            .db()
            .open_tree(TREE_ADDRS)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let addr_book = Self::load_addr_book(&addr_tree);
        Ok(Self {
            store,
            peers: HashMap::new(),
            outbound: HashMap::new(),
            next_peer_id: 0,
            policy,
            gossip_enabled: true,
            addr_book,
            dial_history: HashMap::new(),
            dial_failures: HashMap::new(),
            static_peers: HashSet::new(),
            last_global_getaddr: None,
            advertised_port: None,
            on_block: None,
            on_tx: None,
            has_tx: None,
            lookup_tx: None,
            addr_tree,
        })
    }

    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    pub fn enable_gossip(&mut self, enabled: bool) {
        self.gossip_enabled = enabled;
    }

    pub fn best_hash(&self) -> Hash32 {
        self.store.best_hash()
    }

    pub fn best_entry(&self) -> &HeaderEntry {
        self.store.best_entry()
    }

    pub fn best_peer_height(&self) -> u64 {
        self.peers
            .values()
            .map(|p| p.height)
            .max()
            .unwrap_or(self.store.best_entry().height)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.values().filter(|p| !p.disconnected).count()
    }

    pub fn peers_snapshot(&self) -> Vec<PeerInfo> {
        let mut out = Vec::new();
        for (_id, peer) in self.peers.iter() {
            if peer.disconnected {
                continue;
            }
            if let Some(addr) = peer.addr {
                let outbound = peer.outbound;
                out.push(PeerInfo {
                    addr,
                    inbound: peer.inbound,
                    outbound,
                    height: peer.height,
                });
            }
        }
        out
    }

    pub fn next_peer_id(&mut self) -> u64 {
        let id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1);
        id
    }

    pub fn addr_table_len(&self) -> usize {
        self.addr_book.len()
    }

    pub fn set_advertised_port(&mut self, port: u16) {
        self.advertised_port = Some(port);
    }

    /// Snapshot of addr book contents (unordered, may include stale entries).
    pub fn addr_book_snapshot(&self) -> Vec<SocketAddr> {
        self.addr_book.keys().copied().collect()
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

    pub fn set_tx_callback<F>(&mut self, cb: F)
    where
        F: Fn(&Transaction) -> Result<(), String> + Send + Sync + 'static,
    {
        self.on_tx = Some(Arc::new(cb));
    }

    pub fn set_has_tx<F>(&mut self, f: F)
    where
        F: Fn(&Hash32) -> bool + Send + Sync + 'static,
    {
        self.has_tx = Some(Arc::new(f));
    }

    pub fn set_lookup_tx<F>(&mut self, f: F)
    where
        F: Fn(&Hash32) -> Option<Transaction> + Send + Sync + 'static,
    {
        self.lookup_tx = Some(Arc::new(f));
    }

    /// Seed the dialer with known-good addresses (e.g., CLI peers/seeds).
    /// These are retried even if gossip is disabled or the address is private.
    pub fn add_static_peers<I>(&mut self, addrs: I)
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for addr in addrs {
            self.static_peers.insert(addr);
            if Self::valid_gossip_addr(&addr) {
                self.insert_addr(addr, now);
            }
        }
    }

    pub fn send_to(&self, peer_id: u64, msg: Message) -> Result<(), P2pError> {
        if let Some(tx) = self.outbound.get(&peer_id) {
            tx.send(msg).map_err(|e| P2pError::Io(e.to_string()))
        } else {
            Err(P2pError::Disconnected)
        }
    }

    pub fn broadcast(&self, msg: Message) {
        for tx in self.outbound.values() {
            let _ = tx.send(msg.clone());
        }
    }

    fn insert_addr(&mut self, addr: SocketAddr, now: u64) {
        if !Self::valid_gossip_addr(&addr) {
            return;
        }
        // Enforce unique IP: keep only one entry per IP, prefer newest.
        let ip = Self::ip_only(&addr);
        if let Some((existing_addr, _)) = self
            .addr_book
            .iter()
            .find(|(a, _)| Self::ip_only(a) == ip)
            .map(|(a, ts)| (*a, *ts))
        {
            // Drop the old entry (and its persisted record) before inserting the new one.
            self.addr_book.remove(&existing_addr);
            let _ = self.addr_tree.remove(existing_addr.to_string().as_bytes());
        }
        if self.addr_book.len() >= MAX_ADDR_TABLE {
            // simple LRU-ish: drop oldest
            if let Some(oldest) = self
                .addr_book
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| *k)
            {
                self.addr_book.remove(&oldest);
                let _ = self.addr_tree.remove(oldest.to_string().as_bytes());
            }
        }
        self.addr_book.insert(addr, now);
        // Persist with last_seen as BE bytes.
        let _ = self
            .addr_tree
            .insert(addr.to_string().as_bytes(), &now.to_be_bytes());
    }

    fn load_addr_book(tree: &sled::Tree) -> HashMap<SocketAddr, u64> {
        let mut out = HashMap::new();
        let mut by_ip: HashMap<IpAddr, (SocketAddr, u64)> = HashMap::new();
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for item in tree.iter() {
            if let Ok((k, v)) = item {
                if v.len() != 8 {
                    let _ = tree.remove(k);
                    continue;
                }
                let mut last = [0u8; 8];
                last.copy_from_slice(&v);
                let last_seen = u64::from_be_bytes(last);
                let key = String::from_utf8_lossy(&k).to_string();
                if let Ok(addr) = key.parse::<SocketAddr>() {
                    if !Self::valid_gossip_addr(&addr) {
                        let _ = tree.remove(k);
                        continue;
                    }
                    if now.saturating_sub(last_seen) > ADDR_EXPIRY_SECS {
                        let _ = tree.remove(k);
                        continue;
                    }
                    let ip = Self::ip_only(&addr);
                    // keep the newest entry per IP
                    let replace = match by_ip.get(&ip) {
                        Some((_, ts)) => last_seen > *ts,
                        None => true,
                    };
                    if replace {
                        if let Some((old_addr, _)) = by_ip.insert(ip, (addr, last_seen)) {
                            let _ = tree.remove(old_addr.to_string().as_bytes());
                        }
                    }
                } else {
                    let _ = tree.remove(k);
                }
            }
        }
        for (_ip, (addr, ts)) in by_ip {
            out.insert(addr, ts);
        }
        // Cap to MAX_ADDR_TABLE by dropping oldest.
        if out.len() > MAX_ADDR_TABLE {
            let mut items: Vec<(SocketAddr, u64)> = out.iter().map(|(a, t)| (*a, *t)).collect();
            items.sort_by_key(|(_, t)| *t);
            for (addr, _) in items.into_iter().take(out.len().saturating_sub(MAX_ADDR_TABLE)) {
                out.remove(&addr);
                let _ = tree.remove(addr.to_string().as_bytes());
            }
        }
        out
    }

    fn connected_addrs(&self) -> HashSet<SocketAddr> {
        self.peers
            .values()
            .filter(|p| !p.disconnected)
            .filter_map(|p| p.addr)
            .collect()
    }

    pub fn next_dial_targets(&mut self, max: usize, min_interval: Duration) -> Vec<SocketAddr> {
        let now = Instant::now();
        let connected = self.connected_addrs();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut candidates: Vec<SocketAddr> = self.static_peers.iter().copied().collect();
        candidates.extend(self.addr_book.keys().copied());
        for addr in candidates {
            if !seen.insert(addr) {
                continue;
            }
            if !Self::valid_gossip_addr(&addr) && !self.static_peers.contains(&addr) {
                continue;
            }
            if connected.contains(&addr) {
                continue;
            }
            if let Some(ts) = self.dial_history.get(&addr) {
                let failures = self.dial_failures.get(&addr).copied().unwrap_or(0);
                let backoff = Duration::from_secs(
                    failures.saturating_mul(DIAL_BACKOFF_SECS as u32) as u64,
                );
                let wait = min_interval + backoff;
                if now.saturating_duration_since(*ts) < wait {
                    continue;
                }
                if failures >= MAX_ADDR_FAILS {
                    let cooloff =
                        Duration::from_secs(DIAL_BACKOFF_SECS * failures as u64);
                    if now.saturating_duration_since(*ts) < cooloff {
                        continue;
                    }
                }
            }
            self.dial_history.insert(addr, now);
            out.push(addr);
            if out.len() >= max {
                break;
            }
        }
        out
    }

    fn collect_addrs(&self, max: usize, now: u64) -> Vec<NetAddr> {
        let mut out = Vec::new();
        for (addr, ts) in self.addr_book.iter() {
            if out.len() >= max {
                break;
            }
            if now.saturating_sub(*ts) > ADDR_EXPIRY_SECS {
                continue;
            }
            match addr {
                SocketAddr::V4(v4) => {
                    let mut ip = [0u8; 16];
                    ip[10] = 0xff;
                    ip[11] = 0xff;
                    ip[12..16].copy_from_slice(&v4.ip().octets());
                    out.push(NetAddr {
                        ip,
                        port: v4.port(),
                        last_seen: *ts,
                        services: 0,
                    });
                }
                SocketAddr::V6(v6) => {
                    out.push(NetAddr {
                        ip: v6.ip().octets(),
                        port: v6.port(),
                        last_seen: *ts,
                        services: 0,
                    });
                }
            }
        }
        out
    }

    fn record_dial_failure(&mut self, addr: SocketAddr) {
        let count = self.dial_failures.entry(addr).or_insert(0);
        *count = count.saturating_add(1);
        self.dial_history.insert(addr, Instant::now());
    }

    fn record_dial_success(&mut self, addr: SocketAddr) {
        self.dial_failures.remove(&addr);
        self.dial_history.insert(addr, Instant::now());
    }

    fn ip_only(addr: &SocketAddr) -> IpAddr {
        match addr {
            SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        }
    }

    fn valid_gossip_addr(addr: &SocketAddr) -> bool {
        match addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip();
                if ip.is_loopback() || ip.is_link_local() || ip.is_private() {
                    return false;
                }
                v4.port() != 0
            }
            SocketAddr::V6(v6) => {
                let ip = v6.ip();
                if ip.is_loopback()
                    || ip.is_unique_local()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                {
                    return false;
                }
                v6.port() != 0
            }
        }
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
        let mut proactive = Vec::new();
        if self.gossip_enabled && self.peer_count() < TARGET_PEERS_FOR_GOSSIP {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                if peer.verack_seen {
                    let now = Instant::now();
                    let should_send = peer.last_getaddr.map_or(true, |t| {
                        now.saturating_duration_since(t) > Duration::from_secs(60)
                    });
                    if should_send {
                        peer.last_getaddr = Some(now);
                        peer.sent_getaddr = true;
                        proactive.push((peer_id, Message::GetAddr { max: 128 }));
                        debug!(
                            "gossip: sending getaddr to peer {} (peers={} target={})",
                            peer_id,
                            self.peer_count(),
                            TARGET_PEERS_FOR_GOSSIP
                        );
                    }
                }
            }
        }
        {
            let peer = self.peers.entry(peer_id).or_default();
            // Simple rate limit: MAX_MSGS_PER_SEC per peer.
            let now = Instant::now();
            if let Some(start) = peer.window_start {
                if now.duration_since(start) > Duration::from_secs(1) {
                    peer.window_start = Some(now);
                    peer.msg_count = 0;
                }
            } else {
                peer.window_start = Some(now);
            }
            peer.msg_count = peer.msg_count.saturating_add(1);
            if peer.msg_count > MAX_MSGS_PER_SEC {
                peer.score = peer.score.saturating_add(1);
                if peer.score >= self.policy.ban_threshold {
                    peer.disconnected = true;
                }
                return Err(P2pError::Policy("rate limit exceeded".into()));
            }
        }
        if self
            .peers
            .get(&peer_id)
            .map(|p| p.disconnected)
            .unwrap_or(false)
        {
            return Err(P2pError::Disconnected);
        }

        let out_msgs: Result<Vec<(u64, Message)>, P2pError> = match msg {
            Message::Version(_) => {
                let peer = self.peers.entry(peer_id).or_default();
                let first_version = !peer.version_seen;
                peer.version_seen = true;
                if let Message::Version(v) = &msg {
                    peer.height = v.height;
                    if v.listen_port != 0 {
                        if let Some(addr) = peer.addr {
                            let mut announced = addr;
                            announced.set_port(v.listen_port);
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            self.insert_addr(announced, now);
                        }
                    }
                }
                let mut out = vec![(peer_id, Message::Verack)];
                out.push((
                    peer_id,
                    Message::Version(Version {
                        height: self.store.best_entry().height,
                        listen_port: self.advertised_port.unwrap_or(0),
                    }),
                ));
                if first_version {
                    let locator = self.store.locator();
                    out.push((
                        peer_id,
                        Message::GetHeaders {
                            locator,
                            stop: None,
                        },
                    ));
                }
                Ok(out)
            }
            Message::Verack => {
                let peer_count = self.peers.len();
                let peer = self.peers.entry(peer_id).or_default();
                peer.verack_seen = true;
                let mut out = Vec::new();
                if self.gossip_enabled && peer_count < TARGET_PEERS_FOR_GOSSIP {
                    peer.sent_getaddr = true;
                    out.push((peer_id, Message::GetAddr { max: 128 }));
                }
                Ok(out)
            }
            Message::Ping(nonce) => Ok(vec![(peer_id, Message::Pong(nonce))]),
            Message::Pong(_) => Ok(Vec::new()),
            Message::GetHeaders { locator, stop } => {
                let headers = self.store.get_headers_after(&locator, stop, MAX_HEADERS);
                Ok(vec![(peer_id, Message::Headers(headers))])
            }
            Message::Headers(headers) => {
                if headers.len() > MAX_HEADERS {
                    let peer = self.peers.entry(peer_id).or_default();
                    peer.score = peer.score.saturating_add(1);
                    if peer.score >= self.policy.ban_threshold {
                        peer.disconnected = true;
                    }
                    return Err(P2pError::Policy("too many headers".into()));
                }
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
                for h in self.store.needs_blocks_on_best(MAX_BLOCK_REQ) {
                    out.push((peer_id, Message::GetBlock(h)));
                }
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.height = peer.height.max(self.store.best_entry().height);
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
            Message::InvTx(txids) => {
                if txids.len() > MAX_INV_TX {
                    let peer = self.peers.entry(peer_id).or_default();
                    peer.score = peer.score.saturating_add(1);
                    if peer.score >= self.policy.ban_threshold {
                        peer.disconnected = true;
                    }
                    return Err(P2pError::Policy("too many inv tx".into()));
                }
                let mut unknown = Vec::new();
                for h in txids {
                    let known = self.has_tx.as_ref().map(|f| f(&h)).unwrap_or(false);
                    if !known {
                        unknown.push(h);
                    }
                }
                let mut out = Vec::new();
                for h in unknown {
                    out.push((peer_id, Message::GetTx(h)));
                }
                Ok(out)
            }
            Message::GetTx(txid) => {
                if let Some(lookup) = &self.lookup_tx {
                    if let Some(tx) = lookup(&txid) {
                        return Ok(vec![(peer_id, Message::Tx(tx))]);
                    }
                }
                Ok(Vec::new())
            }
            Message::Tx(tx) => {
                if let Some(cb) = &self.on_tx {
                    if let Err(e) = cb(&tx) {
                        let peer = self.peers.entry(peer_id).or_default();
                        peer.disconnected = true;
                        peer.score += 1;
                        return Err(P2pError::Io(e));
                    }
                }
                // Re-announce to other peers
                let txid = txid(&tx).map_err(|e| {
                    let peer = self.peers.entry(peer_id).or_default();
                    peer.disconnected = true;
                    P2pError::Io(e.to_string())
                })?;
                let mut out = Vec::new();
                for (&id, state) in self.peers.iter() {
                    if id != peer_id && !state.disconnected {
                        out.push((id, Message::InvTx(vec![txid])));
                    }
                }
                Ok(out)
            }
            Message::GetAddr { max } => {
                if !self.gossip_enabled {
                    return Ok(Vec::new());
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let max = max.min(MAX_ADDR_RESP as u16) as usize;
                let addrs = self.collect_addrs(max, now);
                Ok(vec![(peer_id, Message::Addr(addrs))])
            }
            Message::Addr(addrs) => {
                let out = Vec::new();
                let peer = self.peers.entry(peer_id).or_default();
                if !self.gossip_enabled || !peer.sent_getaddr {
                    return Ok(out);
                }
                if addrs.len() > MAX_ADDR_RESP {
                    return Ok(out);
                }
                let total = addrs.len();
                if total == 0 {
                    debug!("gossip: empty addr response from peer {}", peer_id);
                    return Ok(out);
                }
                let mut accepted = 0usize;
                let mut dropped = 0usize;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                for na in addrs {
                    let addr = match na.ip {
                        ip if ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] => {
                            let mut oct = [0u8; 4];
                            oct.copy_from_slice(&ip[12..16]);
                            SocketAddr::from((std::net::Ipv4Addr::from(oct), na.port))
                        }
                        ip => SocketAddr::from((std::net::Ipv6Addr::from(ip), na.port)),
                    };
                    if !Self::valid_gossip_addr(&addr) {
                        dropped += 1;
                        debug!("gossip: drop addr {:?} (invalid/private/port0)", addr);
                        continue;
                    }
                    if now.saturating_sub(na.last_seen) > ADDR_EXPIRY_SECS {
                        dropped += 1;
                        debug!("gossip: drop addr {:?} (expired)", addr);
                        continue;
                    }
                    self.insert_addr(addr, na.last_seen);
                    accepted += 1;
                }
                debug!(
                    "gossip: received addr from peer {} (total={}, accepted={}, dropped={}, table={})",
                    peer_id,
                    total,
                    accepted,
                    dropped,
                    self.addr_book.len()
                );
                Ok(out)
            }
        };
        let mut out = out_msgs?;
        out.extend(proactive);
        Ok(out)
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
        if len > MAX_MSG_LEN {
            return Err(P2pError::Policy("message too large".into()));
        }
        let mut data = vec![0u8; len];
        stream
            .read_exact(&mut data)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let msg = Message::try_from_slice(&data).map_err(|e| P2pError::Io(e.to_string()))?;
        Ok(Some(msg))
    }

    pub fn serve_incoming(
        engine: Arc<Mutex<P2pEngine>>,
        listener: TcpListener,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let eng_hb = Arc::clone(&engine);
            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(30));
                    let guard = eng_hb.lock().ok();
                    if let Some(mut eng) = guard {
                        let connected = eng.peer_count();
                        let outbound = eng
                            .peers
                            .values()
                            .filter(|p| !p.disconnected && p.outbound)
                            .count();
                        let inbound = eng
                            .peers
                            .values()
                            .filter(|p| !p.disconnected && p.inbound)
                            .count();
                        let addr_table = eng.addr_book.len();
                        info!(
                            "net: peers connected={} outbound={} inbound={} addr_table={}",
                            connected, outbound, inbound, addr_table
                        );
                        // Periodic global getaddr even when target peers is met, to refresh tables.
                        if eng.gossip_enabled {
                            let now = Instant::now();
                            let due = eng
                                .last_global_getaddr
                                .map_or(true, |t| now.saturating_duration_since(t)
                                    >= Duration::from_secs(GLOBAL_GETADDR_SECS));
                            if due {
                                let mut sent = 0usize;
                                for (pid, _ps) in eng
                                    .peers
                                    .iter()
                                    .filter(|(_, ps)| ps.verack_seen && !ps.disconnected)
                                {
                                    let _ = eng.send_to(
                                        *pid,
                                        Message::GetAddr {
                                            max: MAX_ADDR_RESP as u16,
                                        },
                                    );
                                    sent += 1;
                                    if sent >= GLOBAL_GETADDR_BATCH {
                                        break;
                                    }
                                }
                                if sent > 0 {
                                    debug!(
                                        "gossip: periodic getaddr sent to {} peers (table={})",
                                        sent, addr_table
                                    );
                                    eng.last_global_getaddr = Some(now);
                                }
                            }
                        }
                    }
                }
            });
            for stream in listener.incoming().flatten() {
                let peer_addr = stream.peer_addr().ok();
                if let Some(pa) = peer_addr {
                    info!("p2p: incoming connection from {}", pa);
                }
                let _ = stream.set_nodelay(true);
                // Allow blocking reads so idle peers are not dropped due to timeouts.
                let _ = stream.set_read_timeout(None);
                let (tx_out, rx_out) = mpsc::channel::<Message>();
                let mut guard = engine.lock().expect("engine");
                let peer_id = guard.next_peer_id();
                // Do not ingest the ephemeral inbound socket into the addr book; we only
                // gossip stable listen ports that peers advertise via Version.
                guard.outbound.insert(peer_id, tx_out.clone());
                let ps = guard.peers.entry(peer_id).or_insert_with(PeerState::default);
                ps.addr = peer_addr;
                ps.inbound = true;
                ps.outbound = false;
                drop(guard);
                let eng = Arc::clone(&engine);
                thread::spawn(move || {
                    let mut stream = stream;
                    loop {
                        // Drain outbound queue first.
                        while let Ok(m) = rx_out.try_recv() {
                            if P2pEngine::write_message(&mut stream, &m).is_err() {
                                break;
                            }
                        }
                        let msg = match P2pEngine::read_message(&mut stream) {
                            Ok(Some(m)) => m,
                            Ok(None) => break,
                            Err(_) => break,
                        };
                        let send_result = {
                            let mut p2p = eng.lock().expect("engine");
                            match p2p.handle_message(peer_id, msg) {
                                Ok(out) => {
                                    for (pid, m) in out {
                                        let _ = p2p.send_to(pid, m);
                                    }
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            }
                        };
                        if send_result.is_err() {
                            break;
                        }
                    }
                    let mut guard = eng.lock().expect("engine");
                    guard.outbound.remove(&peer_id);
                    guard.peers.remove(&peer_id);
                });
            }
        })
    }

    pub fn connect_and_sync(
        engine: Arc<Mutex<P2pEngine>>,
        addr: SocketAddr,
        initial_getblocks: Vec<Hash32>,
    ) -> Result<thread::JoinHandle<()>, P2pError> {
        info!("p2p: dialing {}", addr);
        let mut stream = TcpStream::connect(addr).map_err(|e| {
            let mut eng = engine.lock().expect("engine");
            eng.record_dial_failure(addr);
            P2pError::Io(e.to_string())
        })?;
        stream
            .set_nodelay(true)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        // Allow blocking reads so idle peers are not dropped due to timeouts.
        stream
            .set_read_timeout(None)
            .map_err(|e| P2pError::Io(e.to_string()))?;
        let (peer_id, locator, height, listen_port) = {
            let mut eng = engine.lock().expect("engine");
            if eng.gossip_enabled && P2pEngine::valid_gossip_addr(&addr) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                eng.insert_addr(addr, now);
            }
            (
                eng.next_peer_id(),
                eng.store.locator(),
                eng.best_entry().height,
                eng.advertised_port.unwrap_or(0),
            )
        };

        P2pEngine::write_message(
            &mut stream,
            &Message::Version(Version {
                height,
                listen_port,
            }),
        )?;
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

        let (tx_out, rx_out) = mpsc::channel::<Message>();
        {
            let mut eng = engine.lock().expect("engine");
            eng.record_dial_success(addr);
            eng.outbound.insert(peer_id, tx_out.clone());
            let ps = eng.peers.entry(peer_id).or_insert_with(PeerState::default);
            ps.addr = Some(addr);
            ps.outbound = true;
        }
        let eng = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            let mut stream = stream;
            loop {
                while let Ok(m) = rx_out.try_recv() {
                    if P2pEngine::write_message(&mut stream, &m).is_err() {
                        break;
                    }
                }
                let msg = match P2pEngine::read_message(&mut stream) {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(_) => break,
                };
                let send_result = {
                    let mut p2p = eng.lock().expect("engine");
                    match p2p.handle_message(peer_id, msg) {
                        Ok(out) => {
                            for (pid, m) in out {
                                let _ = p2p.send_to(pid, m);
                            }
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                };
                if send_result.is_err() {
                    break;
                }
            }
            let mut eng = eng.lock().expect("engine");
            eng.outbound.remove(&peer_id);
            eng.peers.remove(&peer_id);
        });
        Ok(handle)
    }
}

#[cfg(all(test, feature = "dev-pow"))]
mod tests {
    use super::*;
    use nulla_core::{
        Amount, Commitment, OutPoint, PROTOCOL_VERSION, Transaction, TransactionKind,
        TransparentInput, TransparentOutput,
    };
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;
    use tempfile::tempdir;

    fn genesis_header() -> BlockHeader {
        let prev = Hash32::zero();
        let tx_merkle_root = Hash32(hex_literal::hex!(
            "4d89bf74b9c3633fc497f182020f31304c94b1096413687c891a57e7bb92cca3"
        ));
        let commitment_root = Hash32(hex_literal::hex!(
            "300eb2dc8d3001271ea0f2fcada9387e7f5817533d863e5a45e5bd8e5f2ca09e"
        ));
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

        p2p.handle_message(1, Message::Headers(vec![child_easy.clone()]))
            .unwrap();
        let best_after_easy = p2p.best_hash();
        p2p.handle_message(2, Message::Headers(vec![child_hard.clone()]))
            .unwrap();
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
            p2p.handle_message(1, Message::Headers(vec![h1.clone()]))
                .unwrap();
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
        let eng_a = Arc::new(Mutex::new(
            P2pEngine::new(&dir_a.path().join("db"), genesis.clone()).unwrap(),
        ));
        let eng_b = Arc::new(Mutex::new(
            P2pEngine::new(&dir_b.path().join("db"), genesis.clone()).unwrap(),
        ));

        // Prepare a block on node A.
        let child = make_child(&genesis, genesis.bits, genesis.timestamp + 1);
        let block = dummy_block(child.clone());
        {
            let mut a = eng_a.lock().unwrap();
            a.handle_message(0, Message::Headers(vec![child.clone()]))
                .unwrap();
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
        p2p.handle_message(1, Message::Headers(vec![h1.clone(), h2.clone()]))
            .unwrap();

        // Competing fork from genesis should exceed policy depth.
        let fork = make_child(&genesis, genesis.bits, genesis.timestamp + 2);
        let err = p2p
            .handle_message(2, Message::Headers(vec![fork]))
            .expect_err("policy should reject deep reorg");
        matches!(err, P2pError::Policy(_));
    }

    #[test]
    fn tx_reannounce_to_other_peers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis).unwrap();

        // Two peers connected.
        p2p.peers.insert(1, PeerState::default());
        p2p.peers.insert(2, PeerState::default());

        // Track accepted txs.
        let accepted: Arc<Mutex<Vec<Hash32>>> = Arc::new(Mutex::new(Vec::new()));
        let acc_cb = Arc::clone(&accepted);
        p2p.set_tx_callback(move |tx| {
            let id = txid(tx).map_err(|e| e.to_string())?;
            acc_cb.lock().unwrap().push(id);
            Ok(())
        });

        p2p.set_has_tx(|_| false);
        p2p.set_lookup_tx(|_| None);

        // Dummy regular tx.
        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: OutPoint {
                    txid: Hash32::zero(),
                    vout: 0,
                },
                sig: vec![],
                pubkey: vec![],
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

        let out = p2p.handle_message(1, Message::Tx(tx)).expect("handle tx");

        // Peer 2 should receive an InvTx for the new txid.
        assert_eq!(out.len(), 1);
        let (pid, msg) = &out[0];
        assert_eq!(*pid, 2);
        match msg {
            Message::InvTx(list) => {
                assert_eq!(list.len(), 1);
                let stored = accepted.lock().unwrap();
                assert_eq!(stored[0], list[0]);
            }
            _ => panic!("expected InvTx"),
        }
    }

    #[test]
    fn inv_tx_requests_unknown() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis).unwrap();
        p2p.peers.insert(1, PeerState::default());
        p2p.set_has_tx(|_| false);
        let h = Hash32::from([1u8; 32]);
        let out = p2p.handle_message(1, Message::InvTx(vec![h])).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 1);
        match &out[0].1 {
            Message::GetTx(x) => assert_eq!(*x, h),
            _ => panic!("expected GetTx"),
        }
    }

    #[test]
    fn tx_propagates_between_engines() {
        let dir = tempdir().unwrap();
        let a_path = dir.path().join("a.db");
        let b_path = dir.path().join("b.db");
        let genesis = genesis_header();
        let mut a = P2pEngine::new(&a_path, genesis.clone()).unwrap();
        let mut b = P2pEngine::new(&b_path, genesis).unwrap();

        // Wire peers and outbound channels manually.
        let (tx_ab, rx_ab) = mpsc::channel::<Message>();
        let (tx_ba, rx_ba) = mpsc::channel::<Message>();
        a.peers.insert(1, PeerState::default());
        b.peers.insert(0, PeerState::default());
        a.outbound.insert(1, tx_ab.clone());
        b.outbound.insert(0, tx_ba.clone());

        let acc_a: Arc<Mutex<Vec<Hash32>>> = Arc::new(Mutex::new(Vec::new()));
        let acc_b: Arc<Mutex<Vec<Hash32>>> = Arc::new(Mutex::new(Vec::new()));
        let acc_a_cb = Arc::clone(&acc_a);
        let acc_b_cb = Arc::clone(&acc_b);

        a.set_tx_callback(move |tx| {
            let id = txid(tx).map_err(|e| e.to_string())?;
            acc_a_cb.lock().unwrap().push(id);
            Ok(())
        });
        b.set_tx_callback(move |tx| {
            let id = txid(tx).map_err(|e| e.to_string())?;
            acc_b_cb.lock().unwrap().push(id);
            Ok(())
        });

        a.set_has_tx(|_| false);
        b.set_has_tx(|_| false);
        a.set_lookup_tx(|_| None);
        b.set_lookup_tx(|_| None);

        // Dummy tx.
        let tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: vec![TransparentInput {
                prevout: OutPoint {
                    txid: Hash32::zero(),
                    vout: 0,
                },
                sig: vec![],
                pubkey: vec![],
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

        // Submit tx to engine A (peer 1).
        let out = a.handle_message(1, Message::Tx(tx.clone())).expect("tx ok");
        for (pid, msg) in out {
            a.send_to(pid, msg).unwrap();
        }
        // Simulate local broadcast from A to B (as RPC would do).
        tx_ab.send(Message::Tx(tx.clone())).unwrap();

        // Deliver messages from A -> B.
        while let Ok(m) = rx_ab.try_recv() {
            let out = b.handle_message(0, m).unwrap_or_default();
            for (pid, msg) in out {
                b.send_to(pid, msg).unwrap_or(());
            }
        }

        // Deliver any messages from B -> A (e.g., reannounce).
        while let Ok(m) = rx_ba.try_recv() {
            let out = a.handle_message(1, m).unwrap_or_default();
            for (pid, msg) in out {
                a.send_to(pid, msg).unwrap_or(());
            }
        }

        // Both sides should have accepted the txid.
        assert_eq!(acc_a.lock().unwrap().len(), 1);
        assert_eq!(acc_b.lock().unwrap().len(), 1);
        assert_eq!(acc_a.lock().unwrap()[0], acc_b.lock().unwrap()[0]);
    }

    #[test]
    fn too_many_headers_hits_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis.clone()).unwrap();
        let child = make_child(&genesis, genesis.bits, genesis.timestamp + 1);
        let headers = vec![child; 65]; // MAX_HEADERS is 64
        let err = p2p
            .handle_message(1, Message::Headers(headers))
            .expect_err("should reject too many headers");
        matches!(err, P2pError::Policy(_));
    }

    #[test]
    fn too_many_inv_tx_hits_policy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db");
        let genesis = genesis_header();
        let mut p2p = P2pEngine::new(&path, genesis).unwrap();
        let hashes = vec![Hash32::zero(); 1_100]; // > MAX_INV_TX
        let err = p2p
            .handle_message(1, Message::InvTx(hashes))
            .expect_err("should reject too many inv tx");
        matches!(err, P2pError::Policy(_));
    }
}
