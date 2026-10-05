//! Block header wire format serialization/deserialization
//!
//! Bitcoin block header wire format specification.
//! Must match consensus serialization exactly for consensus compatibility.

use super::transaction::{
    deserialize_transaction_with_witness, serialize_transaction, serialize_transaction_with_witness,
};
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
            BlockParseError::InsufficientBytes => {
                write!(f, "Insufficient bytes to parse block header")
            }
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
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as i64;
    offset += 4;

    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let timestamp = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as u64;
    offset += 4;

    let bits = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as u64;
    offset += 4;

    let nonce = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
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
        Block::from_parts(header, transactions.into_boxed_slice()),
        all_witnesses,
    ))
}

/// Serialize a complete block to Bitcoin P2P wire format (BIP144 per-transaction SegWit layout).
///
/// Layout: 80-byte header, `compact_size(tx_count)`, then each transaction in turn. This is the
/// inverse of [`deserialize_block_with_witnesses`], which decodes every transaction with
/// [`deserialize_transaction_with_witness`].
///
/// When `include_witness` is true, a transaction is written in extended (BIP144) form — its own
/// `0x00 0x01` marker/flag, inputs, outputs, one witness stack per input, lock time — only if it
/// actually carries witness data, i.e. `witnesses[i]` has one stack per input and at least one
/// stack is non-empty. This matches Bitcoin Core (`SerializeTransaction` / `HasWitness`), which
/// never emits the marker for a transaction whose witnesses are all empty (Core rejects that
/// encoding as a "superfluous witness record"). Every other transaction, and every transaction
/// when `include_witness` is false, uses the legacy encoding from [`serialize_transaction`].
///
/// `witnesses` is indexed per transaction, then per input. Missing entries (a shorter slice) are
/// treated as "no witness". An entry whose stack count does not match the transaction's input
/// count cannot be encoded as BIP144 and is serialized without witness data.
pub fn serialize_block_with_witnesses(
    block: &Block,
    witnesses: &[Vec<Witness>],
    include_witness: bool,
) -> Vec<u8> {
    let mut result = Vec::new();

    result.extend_from_slice(&serialize_block_header(&block.header));
    result.extend_from_slice(&encode_varint(block.transactions.len() as u64));

    for (i, tx) in block.transactions.iter().enumerate() {
        match witnesses.get(i) {
            Some(tx_witnesses)
                if include_witness && tx_has_serializable_witness(tx, tx_witnesses) =>
            {
                result.extend_from_slice(&serialize_transaction_with_witness(tx, tx_witnesses));
            }
            _ => result.extend_from_slice(&serialize_transaction(tx)),
        }
    }

    result
}

/// True when `tx` should be written in BIP144 extended form: one witness stack per input and at
/// least one non-empty stack (Bitcoin Core `CTransaction::HasWitness`).
#[inline]
fn tx_has_serializable_witness(tx: &Transaction, tx_witnesses: &[Witness]) -> bool {
    tx_witnesses.len() == tx.inputs.len() && tx_witnesses.iter().any(|w| !w.is_empty())
}

/// Serialize a block without witness data (convenience for non-SegWit blocks)
pub fn serialize_block(block: &Block) -> Vec<u8> {
    let witnesses: Vec<Vec<Witness>> = block.transactions.iter().map(|_| Vec::new()).collect();
    serialize_block_with_witnesses(block, &witnesses, false)
}

/// Validate that a serialized block size matches the size implied by the Block + Witness data.
///
/// Re-encodes with [`serialize_block_with_witnesses`] (Bitcoin Core-compatible P2P layout), so for
/// `include_witness = true` this equals the length of the canonical wire bytes a peer or
/// `submitblock` caller would send. Non-canonical input (e.g. a marker on a transaction whose
/// witnesses are all empty, which Core rejects) re-encodes shorter and fails this check.
pub fn validate_block_serialized_size(
    block: &Block,
    witnesses: &[Vec<Witness>],
    include_witness: bool,
    provided_size: usize,
) -> bool {
    let serialized = serialize_block_with_witnesses(block, witnesses, include_witness);
    serialized.len() == provided_size
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> BlockHeader {
        BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: [0x11; 32],
            merkle_root: [0x22; 32],
            timestamp: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 42,
        }
    }

    /// Coinbase with a BIP34 height push and a witness-commitment-style output.
    fn coinbase() -> Transaction {
        Transaction {
            version: 2,
            inputs: crate::tx_inputs![TransactionInput {
                prevout: OutPoint {
                    hash: [0; 32],
                    index: 0xffff_ffff,
                },
                script_sig: vec![0x01, 0x01],
                sequence: 0xffff_ffff,
            }],
            outputs: crate::tx_outputs![
                TransactionOutput {
                    value: 50_0000_0000,
                    script_pubkey: vec![0x51],
                },
                TransactionOutput {
                    value: 0,
                    script_pubkey: {
                        let mut s = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
                        s.extend_from_slice(&[0x33; 32]);
                        s
                    },
                }
            ],
            lock_time: 0,
        }
    }

    fn spend(seed: u8, n_inputs: usize) -> Transaction {
        let inputs = (0..n_inputs)
            .map(|i| TransactionInput {
                prevout: OutPoint {
                    hash: [seed; 32],
                    index: i as u32,
                },
                script_sig: if i % 2 == 0 { vec![] } else { vec![0x51, 0x52] },
                sequence: 0xffff_fffd,
            })
            .collect();
        Transaction {
            version: 2,
            inputs,
            outputs: crate::tx_outputs![TransactionOutput {
                value: 1_000 * seed as i64,
                script_pubkey: vec![0x00, 0x14, seed, seed, seed],
            }],
            lock_time: seed as u64,
        }
    }

    fn assert_tx_eq(a: &Transaction, b: &Transaction) {
        assert_eq!(serialize_transaction(a), serialize_transaction(b));
    }

    /// Round-trip and check the decoded block + witnesses match, and re-encoding is byte-identical.
    fn round_trip(block: &Block, witnesses: &[Vec<Witness>]) -> Vec<u8> {
        let wire = serialize_block_with_witnesses(block, witnesses, true);
        let (decoded, decoded_w) = deserialize_block_with_witnesses(&wire).expect("decode");
        assert_eq!(decoded.header, block.header);
        assert_eq!(decoded.transactions.len(), block.transactions.len());
        for (a, b) in decoded.transactions.iter().zip(block.transactions.iter()) {
            assert_tx_eq(a, b);
        }
        for (i, tx) in block.transactions.iter().enumerate() {
            let expected: Vec<Witness> = match witnesses.get(i) {
                Some(w) if tx_has_serializable_witness(tx, w) => w.clone(),
                _ => vec![Vec::new(); tx.inputs.len()],
            };
            assert_eq!(decoded_w[i], expected, "witnesses for tx {i}");
        }
        assert_eq!(
            serialize_block_with_witnesses(&decoded, &decoded_w, true),
            wire,
            "re-encode must be byte-identical"
        );
        assert!(validate_block_serialized_size(
            block,
            witnesses,
            true,
            wire.len()
        ));
        wire
    }

    #[test]
    fn legacy_block_round_trips_without_marker() {
        let block = Block::from_parts(
            header(),
            vec![coinbase(), spend(1, 1), spend(2, 3)].into_boxed_slice(),
        );
        let witnesses: Vec<Vec<Witness>> = block
            .transactions
            .iter()
            .map(|tx| vec![Vec::new(); tx.inputs.len()])
            .collect();
        let wire = round_trip(&block, &witnesses);

        // No witness data: identical to legacy serialization, no marker anywhere.
        let mut expected = serialize_block_header(&block.header);
        expected.extend_from_slice(&encode_varint(3));
        for tx in block.transactions.iter() {
            expected.extend_from_slice(&serialize_transaction(tx));
        }
        assert_eq!(wire, expected);
        assert_eq!(serialize_block(&block), expected);
        assert_eq!(serialize_block_with_witnesses(&block, &[], true), expected);
    }

    /// BIP141 coinbase reserved value (one 32-byte stack item) must be written per-tx, BIP144.
    #[test]
    fn coinbase_reserved_witness_round_trips() {
        let block = Block::from_parts(header(), vec![coinbase()].into_boxed_slice());
        let witnesses = vec![vec![vec![vec![0u8; 32]]]];
        let wire = round_trip(&block, &witnesses);

        // header | count | version | 0x00 0x01 marker/flag | ...
        assert_eq!(wire[80], 0x01);
        assert_eq!(&wire[81..85], &2i32.to_le_bytes());
        assert_eq!(&wire[85..87], &[0x00, 0x01]);
        // ... | witness: 1 item, 32 bytes of zero | lock_time
        let n = wire.len();
        assert_eq!(&wire[n - 4..], &0u32.to_le_bytes());
        assert_eq!(&wire[n - 4 - 32..n - 4], &[0u8; 32]);
        assert_eq!(&wire[n - 4 - 34..n - 4 - 32], &[0x01, 0x20]);

        // Exact size: legacy tx + 2 (marker/flag) + 1 (stack count) + 1 (item len) + 32.
        let legacy_len = 80 + 1 + serialize_transaction(&block.transactions[0]).len();
        assert_eq!(wire.len(), legacy_len + 2 + 1 + 1 + 32);
    }

    /// Mixed block: only txs that carry witness data get the marker; others stay legacy.
    #[test]
    fn mixed_block_round_trips() {
        let block = Block::from_parts(
            header(),
            vec![coinbase(), spend(1, 1), spend(2, 3), spend(3, 2)].into_boxed_slice(),
        );
        let witnesses: Vec<Vec<Witness>> = vec![
            vec![vec![vec![0u8; 32]]],
            vec![Vec::new()],
            vec![
                vec![vec![0x30; 71], vec![0x02; 33]],
                Vec::new(),
                vec![vec![], vec![0x51]],
            ],
            vec![Vec::new(), Vec::new()],
        ];
        let wire = round_trip(&block, &witnesses);

        let mut expected = serialize_block_header(&block.header);
        expected.extend_from_slice(&encode_varint(4));
        expected.extend_from_slice(&serialize_transaction_with_witness(
            &block.transactions[0],
            &witnesses[0],
        ));
        expected.extend_from_slice(&serialize_transaction(&block.transactions[1]));
        expected.extend_from_slice(&serialize_transaction_with_witness(
            &block.transactions[2],
            &witnesses[2],
        ));
        expected.extend_from_slice(&serialize_transaction(&block.transactions[3]));
        assert_eq!(wire, expected);
    }

    #[test]
    fn include_witness_false_strips_witnesses() {
        let block = Block::from_parts(header(), vec![coinbase(), spend(2, 3)].into_boxed_slice());
        let witnesses: Vec<Vec<Witness>> = vec![
            vec![vec![vec![0u8; 32]]],
            vec![vec![vec![0x01]], Vec::new(), vec![vec![0x02]]],
        ];
        let stripped = serialize_block_with_witnesses(&block, &witnesses, false);
        assert_eq!(stripped, serialize_block(&block));
        let (decoded, decoded_w) = deserialize_block_with_witnesses(&stripped).unwrap();
        assert_eq!(decoded.transactions.len(), 2);
        assert!(decoded_w.iter().flatten().all(|w| w.is_empty()));
    }

    /// Short witness slice or a stack count that doesn't match inputs: fall back to legacy
    /// encoding for that tx instead of emitting an unparseable stream.
    #[test]
    fn mismatched_witness_shapes_fall_back_to_legacy() {
        let block = Block::from_parts(
            header(),
            vec![coinbase(), spend(2, 3), spend(3, 1)].into_boxed_slice(),
        );
        // tx1 has 3 inputs but only 1 stack; tx2 missing entirely.
        let witnesses: Vec<Vec<Witness>> = vec![vec![vec![vec![0u8; 32]]], vec![vec![vec![0x01]]]];
        let wire = serialize_block_with_witnesses(&block, &witnesses, true);
        let (decoded, decoded_w) = deserialize_block_with_witnesses(&wire).unwrap();
        assert_eq!(decoded.transactions.len(), 3);
        assert_eq!(decoded_w[0], witnesses[0]);
        assert!(decoded_w[1].iter().all(|w| w.is_empty()));
        assert!(decoded_w[2].iter().all(|w| w.is_empty()));
    }
}
