use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hex::FromHex;
use nulla_core::Transaction;
use serde_json::{json, Value};

use crate::{decode_address, submit_tx_to_node};
use crate::mempool::Mempool;
use nulla_p2p::net::{P2pEngine, PeerInfo};
use crate::ChainStore;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

// RPC rate limiting (DoS protection)
const MAX_RPC_REQUESTS_PER_SEC: usize = 10;
const RATE_LIMIT_WINDOW_SECS: u64 = 1;

struct RateLimiter {
    requests: Arc<Mutex<HashMap<SocketAddr, Vec<Instant>>>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn check_rate_limit(&self, addr: SocketAddr) -> bool {
        let mut requests = self.requests.lock().unwrap_or_else(|poisoned| {
            eprintln!("WARN: rate limiter mutex poisoned, recovering");
            poisoned.into_inner()
        });

        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Get or create entry for this address
        let times = requests.entry(addr).or_insert_with(Vec::new);

        // Remove expired entries
        times.retain(|&t| now.duration_since(t) < window);

        // Check if rate limit exceeded
        if times.len() >= MAX_RPC_REQUESTS_PER_SEC {
            return false;
        }

        // Record this request
        times.push(now);
        true
    }

    fn cleanup_old_entries(&self) {
        let mut requests = self.requests.lock().unwrap_or_else(|poisoned| {
            eprintln!("WARN: rate limiter mutex poisoned, recovering");
            poisoned.into_inner()
        });

        let now = Instant::now();
        let window = Duration::from_secs(RATE_LIMIT_WINDOW_SECS * 10); // Keep 10x window for cleanup

        requests.retain(|_, times| {
            times.retain(|&t| now.duration_since(t) < window);
            !times.is_empty()
        });
    }
}

fn parse_pubkey_hash(v: &Value) -> Result<[u8; 20], String> {
    if let Some(addr) = v.get("address").and_then(|a| a.as_str()) {
        decode_address(addr)
    } else if let Some(pk_hex) = v.get("pubkey_hash").and_then(|p| p.as_str()) {
        <[u8; 20]>::from_hex(pk_hex).map_err(|_| "bad pubkey_hash".to_string())
    } else {
        Err("missing address/pubkey_hash".into())
    }
}

pub fn serve_rpc(
    addr: &str,
    auth_token: Option<String>,
    chain: Arc<Mutex<ChainStore>>,
    mempool: Arc<Mutex<Mempool>>,
    p2p: Arc<Mutex<P2pEngine>>,
    mining_ready: Arc<AtomicBool>,
    mining_block_reason: Arc<Mutex<Option<String>>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let rate_limiter = Arc::new(RateLimiter::new());

    // Spawn cleanup thread for rate limiter
    {
        let limiter = Arc::clone(&rate_limiter);
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(60));
                limiter.cleanup_old_entries();
            }
        });
    }

    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let chain = Arc::clone(&chain);
                let mempool = Arc::clone(&mempool);
                let p2p = Arc::clone(&p2p);
                let mining_ready = Arc::clone(&mining_ready);
                let mining_block_reason = Arc::clone(&mining_block_reason);
                let auth_token = auth_token.clone();
                let limiter = Arc::clone(&rate_limiter);
                thread::spawn(move || {
                    handle_client(
                        stream,
                        auth_token,
                        chain,
                        mempool,
                        p2p,
                        mining_ready,
                        mining_block_reason,
                        limiter,
                    )
                });
            }
        }
    });
    Ok(())
}

fn handle_client(
    stream: TcpStream,
    auth_token: Option<String>,
    chain: Arc<Mutex<ChainStore>>,
    mempool: Arc<Mutex<Mempool>>,
    p2p: Arc<Mutex<P2pEngine>>,
    mining_ready: Arc<AtomicBool>,
    mining_block_reason: Arc<Mutex<Option<String>>>,
    rate_limiter: Arc<RateLimiter>,
) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("WARN: failed to get peer address, closing connection");
            return;
        }
    };

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }

        // Check rate limit
        if !rate_limiter.check_rate_limit(peer_addr) {
            let resp = json!({"ok": false, "error": "rate limit exceeded"});
            let mut stream = stream.try_clone().unwrap();
            let _ = stream.write_all(resp.to_string().as_bytes());
            let _ = stream.write_all(b"\n");
            line.clear();
            continue;
        }

        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(v) => handle_request(
                v,
                &auth_token,
                &chain,
                &mempool,
                &p2p,
                &mining_ready,
                &mining_block_reason,
            ),
            Err(_) => json!({"ok": false, "error": "invalid json"}),
        };
        line.clear();
        let mut stream = stream.try_clone().unwrap();
        let _ = stream.write_all(resp.to_string().as_bytes());
        let _ = stream.write_all(b"\n");
    }
}

fn handle_request(
    v: Value,
    auth_token: &Option<String>,
    chain: &Arc<Mutex<ChainStore>>,
    mempool: &Arc<Mutex<Mempool>>,
    p2p: &Arc<Mutex<P2pEngine>>,
    mining_ready: &Arc<AtomicBool>,
    mining_block_reason: &Arc<Mutex<Option<String>>>,
) -> Value {
    if let Some(expected) = auth_token {
        match v.get("auth").and_then(|a| a.as_str()) {
            Some(tok) if tok == expected => {}
            _ => return json!({"ok": false, "error": "Unauthorized"}),
        }
    }
    let method = match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return json!({"ok": false, "error": "missing method"}),
    };

    match method {
        "ping" => json!({"ok": true}),
        "get_chain_info" => {
            let chain = chain.lock().unwrap_or_else(|poisoned| {
                eprintln!("WARN: chain mutex poisoned, recovering");
                poisoned.into_inner()
            });
            let best = chain.best_entry();
            let peer_count = {
                let net = p2p.lock().unwrap_or_else(|poisoned| {
                    eprintln!("WARN: p2p mutex poisoned, recovering");
                    poisoned.into_inner()
                });
                net.peer_count()
            };
            let ready = mining_ready.load(Ordering::Relaxed);
            let reason = mining_block_reason
                .lock()
                .ok()
                .and_then(|r| r.clone());
            json!({
                "ok": true,
                "height": best.height,
                "best_hash": hex::encode(crate::block_hash(&best.block).as_bytes()),
                "peers": peer_count,
                "can_mine": ready,
                "mining_block_reason": reason,
            })
        }
        "get_peer_stats" => {
            let net = p2p.lock().unwrap_or_else(|poisoned| {
                eprintln!("WARN: p2p mutex poisoned, recovering");
                poisoned.into_inner()
            });
            json!({
                "ok": true,
                "peers": net.peer_count(),
                "addr_table": net.addr_table_len(),
            })
        }
        "get_peers" => {
            let net = p2p.lock().unwrap_or_else(|poisoned| {
                eprintln!("WARN: p2p mutex poisoned, recovering");
                poisoned.into_inner()
            });
            let list: Vec<Value> = net
                .peers_snapshot()
                .into_iter()
                .map(|p: PeerInfo| {
                    json!({
                        "addr": p.addr.to_string(),
                        "inbound": p.inbound,
                        "outbound": p.outbound,
                        "height": p.height,
                    })
                })
                .collect();
            json!({"ok": true, "peers": list, "addr_table": net.addr_table_len()})
        }
        "get_utxos" => {
            let pk_bytes = match parse_pubkey_hash(&v) {
                Ok(b) => b,
                Err(e) => return json!({"ok": false, "error": e}),
            };
            let chain = chain.lock().unwrap_or_else(|poisoned| {
                eprintln!("WARN: chain mutex poisoned, recovering");
                poisoned.into_inner()
            });
            match chain.utxos_for_pubkey_hash(pk_bytes) {
                Ok(list) => {
                    let utxos: Vec<Value> = list
                        .into_iter()
                        .map(|(op, rec)| {
                            json!({
                                "txid": hex::encode(op.txid.as_bytes()),
                                "vout": op.vout,
                                "value": rec.value,
                                "height": rec.height,
                            })
                        })
                        .collect();
                    json!({"ok": true, "utxos": utxos})
                }
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        "get_balance" => {
            let pk_bytes = match parse_pubkey_hash(&v) {
                Ok(b) => b,
                Err(e) => return json!({"ok": false, "error": e}),
            };
            let chain = chain.lock().unwrap_or_else(|poisoned| {
                eprintln!("WARN: chain mutex poisoned, recovering");
                poisoned.into_inner()
            });
            match chain.utxos_for_pubkey_hash(pk_bytes) {
                Ok(list) => {
                    let bal: u64 = list.iter().map(|(_, rec)| rec.value).sum();
                    json!({"ok": true, "balance": bal})
                }
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        "submit_tx" => {
            let tx_hex = match v.get("tx_hex").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing tx_hex"}),
            };
            let bytes = match Vec::from_hex(tx_hex) {
                Ok(b) => b,
                Err(_) => return json!({"ok": false, "error": "bad hex"}),
            };
            let tx: Transaction = match borsh::BorshDeserialize::try_from_slice(&bytes) {
                Ok(t) => t,
                Err(_) => return json!({"ok": false, "error": "decode failed"}),
            };
            match submit_tx_to_node(chain, mempool, Some(p2p), tx) {
                Ok(id) => json!({"ok": true, "txid": hex::encode(id.as_bytes())}),
                Err(e) => json!({"ok": false, "error": format!("{:?}", e)}),
            }
        }
        "validate_address" => {
            let addr = match v.get("address").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing address"}),
            };
            match decode_address(addr) {
                Ok(pk) => json!({"ok": true, "pubkey_hash": hex::encode(pk)}),
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
        _ => json!({"ok": false, "error": "unknown method"}),
    }
}
