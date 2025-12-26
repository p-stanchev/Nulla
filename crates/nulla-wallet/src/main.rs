#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use anyhow::Result;
use clap::Parser;
use serde_json::{json, Value};

use nulla_wallet::{
    decode_address, rpc_client::RpcClient, Wallet, BASE_FEE_ATOMS,
};

#[derive(Parser, Debug)]
#[command(name = "nulla-wallet", version)]
struct Cli {
    #[arg(long, default_value = "nulla.wallet.db")]
    wallet_db: PathBuf,
    /// Node RPC address (wallet uses this to rescan/submit)
    #[arg(long, default_value = "127.0.0.1:27445")]
    rpc: String,
    #[arg(long)]
    rpc_auth_token: Option<String>,
    /// Wallet RPC listen address (start server if set)
    #[arg(long)]
    wallet_rpc_listen: Option<String>,
    /// Auth token for wallet RPC (optional)
    #[arg(long)]
    wallet_rpc_auth: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Init {
        #[arg(long)]
        password: Option<String>,
    },
    Addr {
        #[arg(long)]
        new: bool,
        #[arg(long)]
        password: Option<String>,
    },
    Balance,
    ListUtxos,
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        /// Interpret amount as atoms instead of NUL if set.
        #[arg(long, default_value_t = false)]
        atoms: bool,
        #[arg(long)]
        password: String,
    },
    Rescan {
        #[arg(long)]
        from_height: Option<u64>,
    },
    Serve,
    ExportKey {
        #[arg(long)]
        address: String,
        #[arg(long)]
        password: Option<String>,
    },
    ImportKey {
        #[arg(long)]
        key_hex: String,
        #[arg(long)]
        password: Option<String>,
        /// Optionally rescan after import (from height 0)
        #[arg(long, default_value_t = false)]
        rescan: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new(&cli.rpc, cli.rpc_auth_token.clone());
    let wallet = Wallet::open(&cli.wallet_db)?;

    if let Some(listen) = &cli.wallet_rpc_listen {
        serve_wallet_rpc(
            &cli.wallet_db,
            rpc.clone(),
            listen.clone(),
            cli.wallet_rpc_auth.clone(),
        )?;
    }

    match cli.command {
        Commands::Init { password } => {
            let pwd = password.unwrap_or_else(|| prompt_password("Set wallet password: ").unwrap());
            let addr = wallet.init(&pwd)?;
            println!("Initialized wallet. Default address: {addr}");
        }
        Commands::Addr { new, password } => {
            if new {
                let pwd = password.unwrap_or_else(|| prompt_password("Wallet password: ").unwrap());
                let addr = wallet.new_address(&pwd)?;
                println!("{addr}");
            } else {
                let _ = password.unwrap_or_else(|| prompt_password("Wallet password: ").unwrap());
                let key = wallet.default_key()?;
                println!("{}", key.address);
            }
        }
        Commands::Balance => {
            let total = wallet.balance()?;
            println!(
                "Balance: {} NUL ({} atoms)",
                nulla_wallet::atoms_to_nul(total),
                total
            );
        }
        Commands::ListUtxos => {
            let utxos = wallet.list_utxos()?;
            for u in utxos {
                println!(
                    "{}:{} value={} NUL ({} atoms) height={}",
                    hex::encode(u.txid.as_bytes()),
                    u.vout,
                    nulla_wallet::atoms_to_nul(u.value),
                    u.value,
                    u.height
                );
            }
        }
        Commands::Send {
            to,
            amount,
            atoms,
            password,
        } => {
            let to_hash = decode_address(&to)?;
            let atoms_amount = if atoms {
                amount
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid atoms amount"))?
            } else {
                nulla_wallet::nul_to_atoms(&amount)?
            };
            let tx =
                wallet.build_signed_tx(atoms_amount, to_hash, BASE_FEE_ATOMS, &password)?;
            let bytes = borsh::to_vec(&tx)?;
            let tx_hex = hex::encode(bytes);
            match rpc.submit_tx(&tx_hex)? {
                Ok(id) => println!("Submitted tx {}", hex::encode(id.as_bytes())),
                Err(e) => println!("Submit failed: {e}"),
            }
        }
        Commands::Rescan { from_height } => {
            let found = wallet.rescan_via_rpc(&rpc, from_height)?;
            println!("Rescan complete. Stored {found} UTXOs.");
        }
        Commands::ExportKey { address, password } => {
            let pwd = password.unwrap_or_else(|| prompt_password("Wallet password: ").unwrap());
            let hex = wallet.export_key_hex(&address, &pwd)?;
            println!("Private key (hex): {hex}");
            println!("Store this key securely. Anyone with it can spend your funds.");
        }
        Commands::ImportKey {
            key_hex,
            password,
            rescan,
        } => {
            let pwd = password.unwrap_or_else(|| prompt_password("Wallet password: ").unwrap());
            let addr = wallet.import_key_hex(&key_hex, &pwd)?;
            println!("Imported key for address: {addr}");
            if rescan {
                let found = wallet.rescan_via_rpc(&rpc, None)?;
                println!("Rescan complete. Stored {found} UTXOs.");
            } else {
                println!("Run `rescan` to populate UTXOs for this key.");
            }
        }
        Commands::Serve => {
            // already started above if listen provided; nothing to do
            println!("Wallet RPC serving");
        }
    }

    Ok(())
}

fn serve_wallet_rpc(
    wallet_db: &PathBuf,
    node_rpc: RpcClient,
    listen: String,
    auth_token: Option<String>,
) -> Result<()> {
    let listener = TcpListener::bind(&listen)?;
    let wallet_path = wallet_db.clone();
    println!("Wallet RPC listening on {listen}");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let wallet_path = wallet_path.clone();
            let node_rpc = node_rpc.clone();
            let auth = auth_token.clone();
            thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 {
                        break;
                    }
                    let resp = match serde_json::from_str::<Value>(&line) {
                        Ok(v) => handle_wallet_request(&wallet_path, &node_rpc, auth.clone(), v),
                        Err(_) => json!({"ok": false, "error": "invalid json"}),
                    };
                    line.clear();
                    let mut stream = stream.try_clone().unwrap();
                    let _ = stream.write_all(resp.to_string().as_bytes());
                    let _ = stream.write_all(b"\n");
                }
            });
        }
    });
    Ok(())
}

fn handle_wallet_request(
    wallet_path: &PathBuf,
    node_rpc: &RpcClient,
    auth: Option<String>,
    v: Value,
) -> Value {
    if let Some(expected) = auth {
        match v.get("auth").and_then(|a| a.as_str()) {
            Some(tok) if tok == expected => {}
            _ => return json!({"ok": false, "error": "Unauthorized"}),
        }
    }
    let method = match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return json!({"ok": false, "error": "missing method"}),
    };

    let wallet = match Wallet::open(wallet_path.as_path()) {
        Ok(w) => w,
        Err(e) => return json!({"ok": false, "error": e.to_string()}),
    };

    match method {
        "wallet_init" => {
            let pwd = match v.get("password").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing password"}),
            };
            match wallet.init(pwd) {
                Ok(addr) => json!({"ok": true, "address": addr}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "wallet_addr" => {
            let new = v.get("new").and_then(|b| b.as_bool()).unwrap_or(false);
            if new {
                let pwd = match v.get("password").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return json!({"ok": false, "error": "missing password"}),
                };
                match wallet.new_address(pwd) {
                    Ok(addr) => json!({"ok": true, "address": addr}),
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                }
            } else {
                match wallet.default_key() {
                    Ok(k) => json!({"ok": true, "address": k.address}),
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                }
            }
        }
        "wallet_balance" => match wallet.balance() {
            Ok(b) => json!({"ok": true, "balance": b}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        "wallet_utxos" => match wallet.list_utxos() {
            Ok(list) => {
                let utxos: Vec<Value> = list
                    .into_iter()
                    .map(|u| {
                        json!({
                            "txid": hex::encode(u.txid.as_bytes()),
                            "vout": u.vout,
                            "value": u.value,
                            "height": u.height,
                        })
                    })
                    .collect();
                json!({"ok": true, "utxos": utxos})
            }
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        "wallet_rescan" => {
            let from_height = v.get("from_height").and_then(|h| h.as_u64());
            match wallet.rescan_via_rpc(node_rpc, from_height) {
                Ok(found) => json!({"ok": true, "found": found}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "wallet_export_key" => {
            let addr = match v.get("address").and_then(|a| a.as_str()) {
                Some(a) => a,
                None => return json!({"ok": false, "error": "missing address"}),
            };
            let pwd = match v.get("password").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing password"}),
            };
            match wallet.export_key_hex(addr, pwd) {
                Ok(hex) => json!({"ok": true, "key_hex": hex}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "wallet_import_key" => {
            let key_hex = match v.get("key_hex").and_then(|k| k.as_str()) {
                Some(k) => k,
                None => return json!({"ok": false, "error": "missing key_hex"}),
            };
            let pwd = match v.get("password").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing password"}),
            };
            match wallet.import_key_hex(key_hex, pwd) {
                Ok(addr) => json!({"ok": true, "address": addr}),
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "wallet_send" => {
            let to = match v.get("to").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing to"}),
            };
            let amount = match v.get("amount").and_then(|n| n.as_u64()) {
                Some(a) => a,
                None => return json!({"ok": false, "error": "missing amount"}),
            };
            let pwd = match v.get("password").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => return json!({"ok": false, "error": "missing password"}),
            };
            let to_hash = match decode_address(to) {
                Ok(h) => h,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            };
            match wallet.build_signed_tx(amount, to_hash, BASE_FEE_ATOMS, pwd) {
                Ok(tx) => {
                    let bytes = match borsh::to_vec(&tx) {
                        Ok(b) => b,
                        Err(e) => return json!({"ok": false, "error": e.to_string()}),
                    };
                    let tx_hex = hex::encode(bytes);
                    match node_rpc.submit_tx(&tx_hex) {
                        Ok(Ok(id)) => json!({"ok": true, "txid": hex::encode(id.as_bytes())}),
                        Ok(Err(err)) => json!({"ok": false, "error": err}),
                        Err(e) => json!({"ok": false, "error": e.to_string()}),
                    }
                }
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "get_chain_info" => match node_rpc.chain_info() {
            Ok(Some((h, best, peers))) => {
                json!({"ok": true, "height": h, "best_hash": best, "peers": peers})
            }
            Ok(None) => json!({"ok": false, "error": "node rpc failed"}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        _ => json!({"ok": false, "error": "unknown method"}),
    }
}

fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).map_err(|e| anyhow::anyhow!(e.to_string()))
}
