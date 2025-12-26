#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use argon2::{password_hash::SaltString, Argon2};
use borsh::{BorshDeserialize, BorshSerialize};
use blake3::Hasher;
use bs58::{decode as b58decode, encode as b58encode};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hex::FromHex;
use k256::{
    ecdsa::{signature::Signer, SigningKey},
    EncodedPoint,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use nulla_core::{
    Amount, Hash32, OutPoint, Transaction, TransactionKind, TransparentInput, TransparentOutput,
    PROTOCOL_VERSION,
};

pub mod rpc_client;
use rpc_client::RpcClient;

const TREE_KEYS: &str = "keys";
const TREE_META: &str = "meta";
const TREE_UTXOS: &str = "utxos";
const ADDR_PREFIX: u8 = 0x35;
/// Node policy: must match nulla-node BASE_FEE_ATOMS.
pub const BASE_FEE_ATOMS: u64 = 1000;

fn argon2_params() -> Argon2<'static> {
    Argon2::default()
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct EncryptedKey {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct KeyRecord {
    pub enc: EncryptedKey,
    pub pubkey: Vec<u8>,
    pub address: String,
}

#[derive(BorshSerialize, BorshDeserialize, Default, Clone)]
pub struct WalletMeta {
    pub default_key: Option<String>,
    pub last_scanned_height: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct UtxoRecord {
    pub txid: Hash32,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
    pub pubkey_hash: [u8; 20],
}

pub struct Wallet {
    db: sled::Db,
}

impl Wallet {
    pub fn open(path: &std::path::Path) -> Result<Self> {
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

    pub fn init(&self, password: &str) -> Result<String> {
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
        Ok(addr)
    }

    pub fn default_key(&self) -> Result<KeyRecord> {
        let meta = self.read_meta()?;
        let addr = meta
            .default_key
            .ok_or_else(|| anyhow!("wallet not initialized"))?;
        let bytes = self
            .keys()
            .get(addr.as_bytes())?
            .ok_or_else(|| anyhow!("default key missing"))?;
        Ok(KeyRecord::try_from_slice(&bytes)?)
    }

    pub fn new_address(&self, password: &str) -> Result<String> {
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

    pub fn balance(&self) -> Result<u64> {
        let mut total = 0u64;
        for item in self.utxos().iter() {
            let (_, v) = item?;
            let utxo = UtxoRecord::try_from_slice(&v)?;
            total = total.saturating_add(utxo.value);
        }
        Ok(total)
    }

    pub fn list_utxos(&self) -> Result<Vec<UtxoRecord>> {
        let mut out = Vec::new();
        for item in self.utxos().iter() {
            let (_, v) = item?;
            let utxo = UtxoRecord::try_from_slice(&v)?;
            out.push(utxo);
        }
        Ok(out)
    }

    pub fn rescan_via_rpc(&self, rpc: &RpcClient, from_height: Option<u64>) -> Result<usize> {
        let meta = self.read_meta()?;
        // Until we track spent outputs incrementally, always rebuild from height 0 (or user override).
        let start_height = from_height.unwrap_or(0);
        self.utxos().clear()?;

        // Collect wallet pubkey hashes.
        let mut pk_hashes = Vec::new();
        for item in self.keys().iter() {
            let (_, v) = item?;
            let rec = KeyRecord::try_from_slice(&v)?;
            let mut h = Hasher::new();
            h.update(&rec.pubkey);
            let mut h160 = [0u8; 20];
            h.finalize_xof().fill(&mut h160);
            pk_hashes.push((h160, rec.address));
        }

        let mut found = 0usize;
        for (pk_hash, _addr) in pk_hashes {
            let utxos = rpc.get_utxos(&pk_hash)?;
            for u in utxos {
                if u.height < start_height {
                    continue;
                }
                let key = format!("{}:{}", hex::encode(u.txid.as_bytes()), u.vout);
                self.utxos().insert(key.as_bytes(), borsh::to_vec(&u)?)?;
                found += 1;
                // Print is caller-specific; omit here.
            }
        }

        let mut new_meta = meta;
        new_meta.last_scanned_height = rpc.best_height().unwrap_or(start_height);
        self.write_meta(&new_meta)?;
        Ok(found)
    }

    pub fn export_key_hex(&self, address: &str, password: &str) -> Result<String> {
        let bytes = self
            .keys()
            .get(address.as_bytes())?
            .ok_or_else(|| anyhow!("address not found in wallet"))?;
        let rec = KeyRecord::try_from_slice(&bytes)?;
        let sk = decrypt_key(&rec.enc, password)?;
        Ok(hex::encode(sk))
    }

    pub fn import_key_hex(&self, key_hex: &str, password: &str) -> Result<String> {
        let priv_bytes = Vec::from_hex(key_hex).map_err(|_| anyhow!("invalid hex"))?;
        if priv_bytes.len() != 32 {
            return Err(anyhow!("expected 32-byte secret key"));
        }
        let sk = SigningKey::from_slice(&priv_bytes).map_err(|e| anyhow!(e.to_string()))?;
        let pubkey = EncodedPoint::from(sk.verifying_key()).as_bytes().to_vec();
        let addr = encode_address(&pubkey);
        if self.keys().contains_key(addr.as_bytes())? {
            return Err(anyhow!("key already present"));
        }
        let enc = encrypt_key(&priv_bytes, password)?;
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

    pub fn build_signed_tx(
        &self,
        amount: u64,
        to_hash: [u8; 20],
        fee: u64,
        password: &str,
    ) -> Result<Transaction> {
        let key = self.default_key()?;
        let sk_bytes = decrypt_key(&key.enc, password)?;
        let sk = SigningKey::from_slice(&sk_bytes).map_err(|e| anyhow!(e.to_string()))?;
        let mut change_hash = [0u8; 20];
        {
            let mut h = Hasher::new();
            h.update(&key.pubkey);
            h.finalize_xof().fill(&mut change_hash);
        }
        self.consume_utxos(amount, fee, to_hash, change_hash, &sk)
    }

    fn consume_utxos(
        &self,
        amount: u64,
        fee: u64,
        to_hash: [u8; 20],
        change_hash: [u8; 20],
        sk: &SigningKey,
    ) -> Result<Transaction> {
        let mut utxos = self.list_utxos()?;
        utxos.sort_by_key(|u| std::cmp::Reverse(u.value));
        let target = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("amount overflow"))?;
        let mut selected = Vec::new();
        let mut total = 0u64;
        for u in utxos {
            total = total.checked_add(u.value).ok_or_else(|| anyhow!("overflow"))?;
            selected.push(u);
            if total >= target {
                break;
            }
        }
        if total < target {
            return Err(anyhow!("insufficient funds"));
        }

        let mut inputs = Vec::new();
        for u in &selected {
            inputs.push(TransparentInput {
                prevout: OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                },
                sig: Vec::new(),
                pubkey: Vec::new(),
            });
        }

        let mut outputs = vec![TransparentOutput {
            value: Amount::from_atoms(amount),
            pubkey_hash: to_hash,
        }];
        let change = total - target;
        if change > 0 {
            outputs.push(TransparentOutput {
                value: Amount::from_atoms(change),
                pubkey_hash: change_hash,
            });
        }

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            kind: TransactionKind::Regular,
            transparent_inputs: inputs,
            transparent_outputs: outputs,
            anchor_root: Hash32::zero(),
            nullifiers: vec![],
            outputs: vec![],
            fee: Amount::from_atoms(fee),
            claimed_subsidy: Amount::zero(),
            claimed_fees: Amount::zero(),
            proof: vec![],
            memo: vec![],
        };

        for idx in 0..tx.transparent_inputs.len() {
            let pubkey = EncodedPoint::from(sk.verifying_key()).as_bytes().to_vec();
            let mut h = Hasher::new();
            h.update(&pubkey);
            let mut pk_hash = [0u8; 20];
            h.finalize_xof().fill(&mut pk_hash);
            let sighash = tx_sighash(&tx, idx, pk_hash);
            let sig: k256::ecdsa::Signature = sk.sign(&sighash);
            let inp = tx.transparent_inputs.get_mut(idx).expect("input exists");
            inp.pubkey = pubkey;
            inp.sig = sig.to_der().as_bytes().to_vec();
        }

        Ok(tx)
    }
}

fn tx_sighash(tx: &Transaction, input_idx: usize, pk_hash: [u8; 20]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&tx.version.to_le_bytes());
    data.extend_from_slice(&(tx.transparent_inputs.len() as u64).to_le_bytes());
    for (i, inp) in tx.transparent_inputs.iter().enumerate() {
        data.extend_from_slice(inp.prevout.txid.as_bytes());
        data.extend_from_slice(&inp.prevout.vout.to_le_bytes());
        if i == input_idx {
            data.extend_from_slice(&pk_hash);
        } else {
            data.extend_from_slice(&[0u8; 20]);
        }
    }
    data.extend_from_slice(&(tx.transparent_outputs.len() as u64).to_le_bytes());
    for o in &tx.transparent_outputs {
        data.extend_from_slice(&o.value.atoms().to_le_bytes());
        data.extend_from_slice(&o.pubkey_hash);
    }
    let mut h = Hasher::new();
    h.update(&data);
    h.finalize().as_bytes().to_vec()
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

pub fn encode_address(pubkey: &[u8]) -> String {
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

pub fn decode_address(addr: &str) -> Result<[u8; 20]> {
    let bytes = b58decode(addr).into_vec().map_err(|e| anyhow!(e))?;
    if bytes.len() != 1 + 20 + 4 {
        return Err(anyhow!("invalid address length"));
    }
    if bytes[0] != ADDR_PREFIX {
        return Err(anyhow!("invalid address prefix"));
    }
    let (payload, checksum) = bytes.split_at(1 + 20);
    let mut expected = [0u8; 4];
    expected.copy_from_slice(&checksum4(payload));
    if expected != checksum[0..4] {
        return Err(anyhow!("checksum mismatch"));
    }
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&payload[1..]);
    Ok(h160)
}

fn checksum4(data: &[u8]) -> [u8; 4] {
    let mut h = Hasher::new();
    h.update(data);
    let mut out = [0u8; 4];
    h.finalize_xof().fill(&mut out);
    out
}
