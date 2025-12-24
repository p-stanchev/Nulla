use nulla_consensus::pow_hash;
use nulla_core::{block_header_hash, BlockHeader, Hash32};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HeaderFields {
    version: u16,
    prev: String,
    tx_merkle_root: String,
    commitment_root: String,
    timestamp: u64,
    bits: u32,
    nonce: u64,
    height: u64,
}

#[derive(Debug, Deserialize)]
struct PowVector {
    name: String,
    header: HeaderFields,
    serialized_hex: String,
    header_hash_hex: String,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("vectors")
        .join("pow_header.json")
}

fn parse_hex32(s: &str) -> Hash32 {
    let bytes = hex::decode(s).expect("hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Hash32(arr)
}

#[test]
fn pow_header_vectors() {
    let data = fs::read_to_string(vectors_path()).expect("vector file");
    let vectors: Vec<PowVector> = serde_json::from_str(&data).expect("parse json");

    for v in vectors {
        let header = BlockHeader {
            version: v.header.version,
            prev: parse_hex32(&v.header.prev),
            tx_merkle_root: parse_hex32(&v.header.tx_merkle_root),
            commitment_root: parse_hex32(&v.header.commitment_root),
            timestamp: v.header.timestamp,
            bits: v.header.bits,
            nonce: v.header.nonce,
        };

        let ser = borsh::to_vec(&header).expect("borsh");
        assert_eq!(
            hex::encode(&ser),
            v.serialized_hex,
            "serialized bytes mismatch for {}",
            v.name
        );

        let hash = block_header_hash(&header).expect("hash");
        assert_eq!(
            hex::encode(hash.as_bytes()),
            v.header_hash_hex,
            "header hash mismatch for {}",
            v.name
        );

        let pow = pow_hash(&header).expect("pow hash");
        assert_eq!(
            hex::encode(pow),
            v.header_hash_hex,
            "pow hash mismatch for {}",
            v.name
        );
    }
}
