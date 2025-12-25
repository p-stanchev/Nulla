#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use argon2::{password_hash::SaltString, Argon2};
use borsh::{BorshDeserialize, BorshSerialize};
use blake3::Hasher;
use bs58::encode as b58encode;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use clap::{Parser, Subcommand};
use k256::{ecdsa::SigningKey, EncodedPoint};
use nulla_core::Hash32;
use nulla_node::chain_store::ChainDb;
use rand_core::{OsRng, RngCore};
use rpassword::prompt_password;
use zeroize::Zeroizing;

const TREE_KEYS: &str = "keys";
const TREE_META: &str = "meta";
const TREE_UTXOS: &str = "utxos";
const ADDR_PREFIX: u8 = 0x35;
fn argon2_params() -> Argon2<'static> {
    Argon2::default()
}

#[derive(Parser, Debug)]
#[command(name = "nulla-wallet", version)]
struct Cli {
    #[arg(long, default_value = "nulla.wallet.db")]
    wallet_db: PathBuf,
    #[arg(long, default_value = "nulla.chain.db")]
    chain_db: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Addr {
        #[arg(long)]
        new: bool,
    },
    Balance,
    ListUtxos,
    Rescan {
        #[arg(long)]
        from_height: Option<u64>,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct EncryptedKey {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct KeyRecord {
    enc: EncryptedKey,
    pubkey: Vec<u8>,
    address: String,
}

#[derive(BorshSerialize, BorshDeserialize, Default)]
struct WalletMeta {
    default_key: Option<String>,
    last_scanned_height: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
struct UtxoRecord {
    txid: Hash32,
    vout: u32,
    value: u64,
    height: u64,
    pubkey_hash: [u8; 20],
}

struct Wallet {
    db: sled::Db,
}

impl Wallet {
    fn open(path: &PathBuf) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    fn keys(&self) -> sled::Tree {
        self.db.open_tree(TREE_KEYS).expect("keys tree")
    }
    fn meta(&self) -> sled::Tree {
        self.db.open_tree(TREE_META).expect("meta tree")
    }
    fn utxos(&self) -> sled::Tree {
        self.db.open_tree(TREE_UTXOS).expect("utxo tree")
    }

    fn read_meta(&self) -> Result<WalletMeta> {
        if let Some(bytes) = self.meta().get("meta")? {
            Ok(WalletMeta::try_from_slice(&bytes)?)
        } else {
            Ok(WalletMeta::default())
        }
    }

    fn write_meta(&self, meta: &WalletMeta) -> Result<()> {
        self.meta().insert("meta", borsh::to_vec(meta)?)?;
        Ok(())
    }

    fn init(&self, password: &str) -> Result<()> {
        if !self.keys().is_empty() {
            return Err(anyhow!("wallet already initialized"));
        }
        let key = SigningKey::random(&mut OsRng);
        let pubkey = EncodedPoint::from(key.verifying_key()).as_bytes().to_vec();
        let addr = encode_address(&pubkey);
        let enc = encrypt_key(&key.to_bytes(), password)?;
        let record = KeyRecord {
            enc,
            pubkey,
            address: addr.clone(),
        };
        self.keys()
            .insert(addr.as_bytes(), borsh::to_vec(&record)?)?;
        let meta = WalletMeta {
            default_key: Some(addr.clone()),
            last_scanned_height: 0,
        };
        self.write_meta(&meta)?;
        println!("Initialized wallet. Default address: {addr}");
        Ok(())
    }

    fn default_key(&self) -> Result<KeyRecord> {
        let meta = self.read_meta()?;
        let addr = meta.default_key.ok_or_else(|| anyhow!("wallet not initialized"))?;
        let bytes = self
            .keys()
            .get(addr.as_bytes())?
            .ok_or_else(|| anyhow!("default key missing"))?;
        Ok(KeyRecord::try_from_slice(&bytes)?)
    }

    fn new_address(&self, password: &str) -> Result<String> {
        let key = SigningKey::random(&mut OsRng);
        let pubkey = EncodedPoint::from(key.verifying_key()).as_bytes().to_vec();
        let addr = encode_address(&pubkey);
        let enc = encrypt_key(&key.to_bytes(), password)?;
        let record = KeyRecord {
            enc,
            pubkey,
            address: addr.clone(),
        };
        self.keys()
            .insert(addr.as_bytes(), borsh::to_vec(&record)?)?;
        let mut meta = self.read_meta()?;
        if meta.default_key.is_none() {
            meta.default_key = Some(addr.clone());
            self.write_meta(&meta)?;
        }
        Ok(addr)
    }

    fn balance(&self) -> Result<u64> {
        let mut total = 0u64;
        for item in self.utxos().iter() {
            let (_, v) = item?;
            let utxo = UtxoRecord::try_from_slice(&v)?;
            total = total.saturating_add(utxo.value);
        }
        Ok(total)
    }

    fn list_utxos(&self) -> Result<Vec<UtxoRecord>> {
        let mut out = Vec::new();
        for item in self.utxos().iter() {
            let (_, v) = item?;
            let utxo = UtxoRecord::try_from_slice(&v)?;
            out.push(utxo);
        }
        Ok(out)
    }

    fn rescan(&self, chain_db: &ChainDb, from_height: Option<u64>) -> Result<()> {
        let meta = self.read_meta()?;
        let start_height = from_height.unwrap_or(meta.last_scanned_height);
        let best = chain_db
            .best_tip_by_work()
            .map_err(|e| anyhow!(e))?
            .unwrap_or_else(|| Hash32::from([0u8; 32]));
        let chain = chain_db
            .chain_from_tip(best)
            .map_err(|e| anyhow!(e))?;

        // Clear UTXOs for a full rescan.
        self.utxos().clear()?;

        // Since transparent outputs aren’t implemented yet, we just advance the scan marker.
        let new_height = chain.len().saturating_sub(1) as u64;
        let mut new_meta = meta;
        new_meta.last_scanned_height = new_height.max(start_height);
        self.write_meta(&new_meta)?;
        println!(
            "Rescan complete. Scanned heights {} -> {}. (No transparent outputs available yet.)",
            start_height, new_meta.last_scanned_height
        );
        Ok(())
    }
}

fn encrypt_key(priv_bytes: &[u8], password: &str) -> Result<EncryptedKey> {
    let salt = SaltString::generate(&mut OsRng);
    let mut key = Zeroizing::new([0u8; 32]);
    let salt_binding = salt.as_salt();
    let salt_bytes = salt_binding.as_ref().as_bytes();
    argon2_params()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key[..])
        .map_err(|e| anyhow!(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), priv_bytes)
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(EncryptedKey {
        salt: salt.as_str().as_bytes().to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

fn decrypt_key(enc: &EncryptedKey, password: &str) -> Result<Vec<u8>> {
    let salt_str = std::str::from_utf8(&enc.salt)?;
    let salt = SaltString::from_b64(salt_str).map_err(|e| anyhow!(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    let salt_binding = salt.as_salt();
    let salt_bytes = salt_binding.as_ref().as_bytes();
    argon2_params()
        .hash_password_into(password.as_bytes(), salt_bytes, &mut key[..])
        .map_err(|e| anyhow!(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce = XNonce::from_slice(&enc.nonce);
    let plaintext = cipher
        .decrypt(nonce, enc.ciphertext.as_ref())
        .map_err(|e| anyhow!(e.to_string()))?;
    Ok(plaintext)
}

fn encode_address(pubkey: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(pubkey);
    let mut h160 = [0u8; 20];
    h.finalize_xof().fill(&mut h160);
    let mut payload = Vec::with_capacity(1 + 20 + 4);
    payload.push(ADDR_PREFIX);
    payload.extend_from_slice(&h160);
    let checksum = checksum4(&payload);
    payload.extend_from_slice(&checksum);
    b58encode(payload).into_string()
}

fn checksum4(data: &[u8]) -> [u8; 4] {
    let mut h = Hasher::new();
    h.update(data);
    let mut out = [0u8; 4];
    h.finalize_xof().fill(&mut out);
    out
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let wallet = Wallet::open(&cli.wallet_db)?;

    match cli.command {
        Commands::Init => {
            let pwd = prompt_password("Set wallet password: ")?;
            wallet.init(&pwd)?;
        }
        Commands::Addr { new } => {
            let pwd = prompt_password("Wallet password: ")?;
            if new {
                let addr = wallet.new_address(&pwd)?;
                println!("{addr}");
            } else {
                let key = wallet.default_key()?;
                // Verify password before printing address.
                let _ = decrypt_key(&key.enc, &pwd)?;
                println!("{}", key.address);
            }
        }
        Commands::Balance => {
            let total = wallet.balance()?;
            println!("Balance: {} atoms", total);
        }
        Commands::ListUtxos => {
            let utxos = wallet.list_utxos()?;
            for u in utxos {
                println!(
                    "{}:{} value={} height={}",
                    hex::encode(u.txid.as_bytes()),
                    u.vout,
                    u.value,
                    u.height
                );
            }
        }
        Commands::Rescan { from_height } => {
            let chain_db = ChainDb::open(&cli.chain_db).map_err(|e| anyhow!(e))?;
            wallet.rescan(&chain_db, from_height)?;
        }
    }

    Ok(())
}
