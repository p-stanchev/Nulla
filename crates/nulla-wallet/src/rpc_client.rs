use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use anyhow::Result;
use hex::FromHex;
use serde_json::{json, Value};

use nulla_core::Hash32;

use crate::UtxoRecord;

pub struct RpcClient {
    addr: String,
    auth: Option<String>,
}

impl RpcClient {
    pub fn new(addr: &str, auth: Option<String>) -> Self {
        Self {
            addr: addr.to_string(),
            auth,
        }
    }

    fn send(&self, req: Value) -> Result<Value> {
        let mut stream = TcpStream::connect(&self.addr)?;
        let mut req = req;
        if let Some(token) = &self.auth {
            req["auth"] = json!(token);
        }
        let line = req.to_string();
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        let mut reader = BufReader::new(stream);
        let mut resp = String::new();
        reader.read_line(&mut resp)?;
        let v: Value = serde_json::from_str(&resp)?;
        Ok(v)
    }

    pub fn best_height(&self) -> Result<u64> {
        let v = self.send(json!({"method":"get_chain_info"}))?;
        if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            return Ok(0);
        }
        Ok(v.get("height").and_then(|h| h.as_u64()).unwrap_or(0))
    }

    pub fn get_utxos(&self, pk_hash: &[u8; 20]) -> Result<Vec<UtxoRecord>> {
        let v = self.send(json!({
            "method": "get_utxos",
            "pubkey_hash": hex::encode(pk_hash),
        }))?;
        if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if let Some(list) = v.get("utxos").and_then(|u| u.as_array()) {
            for item in list {
                if let (Some(txid_str), Some(vout), Some(value), Some(height)) = (
                    item.get("txid").and_then(|s| s.as_str()),
                    item.get("vout").and_then(|n| n.as_u64()),
                    item.get("value").and_then(|n| n.as_u64()),
                    item.get("height").and_then(|n| n.as_u64()),
                ) {
                    if let Ok(txid_bytes) = Vec::from_hex(txid_str) {
                        if txid_bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&txid_bytes);
                            out.push(UtxoRecord {
                                txid: Hash32(arr),
                                vout: vout as u32,
                                value,
                                height,
                                pubkey_hash: *pk_hash,
                            });
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn submit_tx(&self, tx_hex: &str) -> Result<Result<Hash32, String>> {
        let v = self.send(json!({
            "method": "submit_tx",
            "tx_hex": tx_hex,
        }))?;
        if v.get("ok").and_then(|o| o.as_bool()) != Some(true) {
            let err = v
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Ok(Err(err));
        }
        if let Some(txid_str) = v.get("txid").and_then(|s| s.as_str()) {
            if let Ok(bytes) = Vec::from_hex(txid_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Ok(Ok(Hash32(arr)));
                }
            }
        }
        Ok(Err("bad txid".into()))
    }
}
