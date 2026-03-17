//! Block header wire format serialization/deserialization
//!
//! Bitcoin block header wire format specification.
//! Must match consensus serialization exactly for consensus compatibility.

use super::transaction::{deserialize_transaction_with_witness, serialize_transaction};
use super::varint::{decode_varint, encode_varint};
use crate::error::{ConsensusError, Result};
use crate::types::*;
use std::borrow::Cow;

/// Error type for block parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockParseError {
    InsufficientBytes,
    InvalidVersion,
    InvalidTimestamp,
    InvalidBits,
    InvalidNonce,
    InvalidTransactionCount,
    InvalidWitnessMarker,
}

impl std::fmt::Display for BlockParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockParseError::InsufficientBytes => write!(f, "Insufficient bytes to parse block header"),
            BlockParseError::InvalidVersion => write!(f, "Invalid block version"),
            BlockParseError::InvalidTimestamp => write!(f, "Invalid block timestamp"),
            BlockParseError::InvalidBits => write!(f, "Invalid block bits"),
            BlockParseError::InvalidNonce => write!(f, "Invalid block nonce"),
            BlockParseError::InvalidTransactionCount => write!(f, "Invalid transaction count"),
            BlockParseError::InvalidWitnessMarker => write!(f, "Invalid witness marker"),
        }
    }
}

impl std::error::Error for BlockParseError {}

/// Serialize a block header to Bitcoin wire format
pub fn serialize_block_header(header: &BlockHeader) -> Vec<u8> {
    let mut result = Vec::with_capacity(80);
    result.extend_from_slice(&(header.version as i32).to_le_bytes());
    result.extend_from_slice(&header.prev_block_hash);
    result.extend_from_slice(&header.merkle_root);
    result.extend_from_slice(&(header.timestamp as u32).to_le_bytes());
    result.extend_from_slice(&(header.bits as u32).to_le_bytes());
    result.extend_from_slice(&(header.nonce as u32).to_le_bytes());
    assert_eq!(result.len(), 80);
    result
}

/// Deserialize a block header from Bitcoin wire format
pub fn deserialize_block_header(data: &[u8]) -> Result<BlockHeader> {
    if data.len() < 80 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            BlockParseError::InsufficientBytes.to_string(),
        )));
    }

    let mut offset = 0;

    let version = i32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as i64;
    offset += 4;

    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let timestamp = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;
    offset += 4;

    let bits = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;
    offset += 4;

    let nonce = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;

    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        bits,
        nonce,
    })
}

/// Deserialize a complete block from Bitcoin wire format (including witness data)
pub fn deserialize_block_with_witnesses(data: &[u8]) -> Result<(Block, Vec<Vec<Witness>>)> {
    if data.len() < 80 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            BlockParseError::InsufficientBytes.to_string(),
        )));
    }

    let mut offset = 0;

    let header = deserialize_block_header(&data[offset..offset + 80])?;
    offset += 80;

    let (tx_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if tx_count == 0 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            BlockParseError::InvalidTransactionCount.to_string(),
        )));
    }

    let mut transactions = Vec::new();
    let mut all_witnesses: Vec<Vec<Witness>> = Vec::new();

    for _ in 0..tx_count {
        let (tx, input_witnesses, bytes_consumed) =
            deserialize_transaction_with_witness(&data[offset..])?;
        offset += bytes_consumed;
        transactions.push(tx);
        all_witnesses.push(input_witnesses);
    }

    while all_witnesses.len() < transactions.len() {
        all_witnesses.push(Vec::new());
    }

    Ok((
        Block {
            header,
            transactions: transactions.into_boxed_slice(),
        },
        all_witnesses,
    ))
}

/// Serialize a complete block to Bitcoin wire format (including witness data)
pub fn serialize_block_with_witnesses(
    block: &Block,
    witnesses: &[Vec<Witness>],
    include_witness: bool,
) -> Vec<u8> {
    let mut result = Vec::new();

    result.extend_from_slice(&serialize_block_header(&block.header));
    result.extend_from_slice(&encode_varint(block.transactions.len() as u64));

    let has_witness = include_witness
        && witnesses
            .iter()
            .any(|tx_witnesses| tx_witnesses.iter().any(|w| !w.is_empty()));

    if has_witness {
        result.push(0x00);
        result.push(0x01);
    }

    for tx in block.transactions.iter() {
        result.extend_from_slice(&serialize_transaction(tx));
    }

    if has_witness {
        for tx_witnesses in witnesses.iter().take(block.transactions.len()) {
            for witness in tx_witnesses {
                result.extend_from_slice(&encode_varint(witness.len() as u64));
                for element in witness {
                    result.extend_from_slice(&encode_varint(element.len() as u64));
                    result.extend_from_slice(element);
                }
            }
        }
    }

    result
}

/// Serialize a block without witness data (convenience for non-SegWit blocks)
pub fn serialize_block(block: &Block) -> Vec<u8> {
    let witnesses: Vec<Vec<Witness>> = block
        .transactions
        .iter()
        .map(|_| Vec::new())
        .collect();
    serialize_block_with_witnesses(block, &witnesses, false)
}

/// Validate that a serialized block size matches the size implied by the Block + Witness data
pub fn validate_block_serialized_size(
    block: &Block,
    witnesses: &[Vec<Witness>],
    include_witness: bool,
    provided_size: usize,
) -> bool {
    let serialized = serialize_block_with_witnesses(block, witnesses, include_witness);
    serialized.len() == provided_size
}
