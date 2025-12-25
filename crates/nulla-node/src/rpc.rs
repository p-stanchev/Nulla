use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use hex::FromHex;
use nulla_core::Transaction;
use serde_json::{json, Value};

use crate::{decode_address, submit_tx_to_node};
use crate::mempool::Mempool;
use crate::ChainStore;

pub fn serve_rpc(
    addr: &str,
    auth_token: Option<String>,
    chain: Arc<Mutex<ChainStore>>,
    mempool: Arc<Mutex<Mempool>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let chain = Arc::clone(&chain);
                let mempool = Arc::clone(&mempool);
                let auth_token = auth_token.clone();
                thread::spawn(move || handle_client(stream, auth_token, chain, mempool));
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
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(v) => handle_request(v, &auth_token, &chain, &mempool),
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
            let chain = chain.lock().expect("chain");
            let best = chain.best_entry();
            json!({
                "ok": true,
                "height": best.height,
                "best_hash": hex::encode(crate::block_hash(&best.block).as_bytes()),
            })
        }
        "get_utxos" => {
            let pk_hex = match v.get("pubkey_hash").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing pubkey_hash"}),
            };
            let pk_bytes = match <[u8;20]>::from_hex(pk_hex) {
                Ok(b) => b,
                Err(_) => return json!({"ok": false, "error": "bad pubkey_hash"}),
            };
            let chain = chain.lock().expect("chain");
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
            match submit_tx_to_node(chain, mempool, tx) {
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
