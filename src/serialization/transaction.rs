//! Transaction wire format serialization/deserialization
//!
//! Bitcoin transaction wire format specification.
//! Must match Bitcoin protocol serialization exactly for consensus compatibility.

use super::varint::{decode_varint, encode_varint};
use crate::error::{ConsensusError, Result};
use crate::types::*;
use std::borrow::Cow;

#[cfg(feature = "production")]
use smallvec::SmallVec;

/// Error type for transaction parsing failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionParseError {
    InsufficientBytes,
    InvalidVersion,
    InvalidInputCount,
    InvalidOutputCount,
    InvalidScriptLength,
    InvalidLockTime,
}

impl std::fmt::Display for TransactionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionParseError::InsufficientBytes => {
                write!(f, "Insufficient bytes to parse transaction")
            }
            TransactionParseError::InvalidVersion => write!(f, "Invalid transaction version"),
            TransactionParseError::InvalidInputCount => write!(f, "Invalid input count"),
            TransactionParseError::InvalidOutputCount => write!(f, "Invalid output count"),
            TransactionParseError::InvalidScriptLength => write!(f, "Invalid script length"),
            TransactionParseError::InvalidLockTime => write!(f, "Invalid lock time"),
        }
    }
}

impl std::error::Error for TransactionParseError {}

/// Serialize a transaction to Bitcoin wire format
#[inline(always)]
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut result = Vec::new();
    serialize_transaction_append(&mut result, tx);
    result
}

/// Append serialized transaction to buffer (shared logic for into/inner).
#[inline(always)]
fn serialize_transaction_append(result: &mut Vec<u8>, tx: &Transaction) {
    result.extend_from_slice(&(tx.version as i32).to_le_bytes());
    result.extend_from_slice(&encode_varint(tx.inputs.len() as u64));

    for input in &tx.inputs {
        result.extend_from_slice(&input.prevout.hash);
        result.extend_from_slice(&input.prevout.index.to_le_bytes());
        result.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
        result.extend_from_slice(&input.script_sig);
        result.extend_from_slice(&(input.sequence as u32).to_le_bytes());
    }

    result.extend_from_slice(&encode_varint(tx.outputs.len() as u64));

    for output in &tx.outputs {
        result.extend_from_slice(&(output.value as u64).to_le_bytes());
        result.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        result.extend_from_slice(&output.script_pubkey);
    }

    result.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
}

/// Serialize transaction into an existing buffer
#[inline(always)]
pub fn serialize_transaction_into(dst: &mut Vec<u8>, tx: &Transaction) -> usize {
    dst.clear();
    serialize_transaction_append(dst, tx);
    dst.len()
}

/// Serialize a transaction in SegWit wire format
pub fn serialize_transaction_with_witness(tx: &Transaction, witnesses: &[Witness]) -> Vec<u8> {
    assert_eq!(witnesses.len(), tx.inputs.len(), "witness count must match input count");
    let mut result = Vec::new();
    result.extend_from_slice(&(tx.version as i32).to_le_bytes());
    result.push(0x00);
    result.push(0x01);
    result.extend_from_slice(&encode_varint(tx.inputs.len() as u64));
    for input in &tx.inputs {
        result.extend_from_slice(&input.prevout.hash);
        result.extend_from_slice(&input.prevout.index.to_le_bytes());
        result.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
        result.extend_from_slice(&input.script_sig);
        result.extend_from_slice(&(input.sequence as u32).to_le_bytes());
    }
    result.extend_from_slice(&encode_varint(tx.outputs.len() as u64));
    for output in &tx.outputs {
        result.extend_from_slice(&(output.value as u64).to_le_bytes());
        result.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        result.extend_from_slice(&output.script_pubkey);
    }
    for witness in witnesses {
        result.extend_from_slice(&encode_varint(witness.len() as u64));
        for element in witness {
            result.extend_from_slice(&encode_varint(element.len() as u64));
            result.extend_from_slice(element);
        }
    }
    result.extend_from_slice(&(tx.lock_time as u32).to_le_bytes());
    result
}

/// Deserialize a transaction from Bitcoin wire format
pub fn deserialize_transaction(data: &[u8]) -> Result<Transaction> {
    let mut offset = 0;

    if data.len() < offset + 4 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        )));
    }
    let version = i32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;
    offset += 4;

    let is_segwit = data.len() >= offset + 2
        && data[offset] == 0x00
        && data[offset + 1] == 0x01;

    if is_segwit {
        offset += 2;
    }

    let (input_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if input_count > 1000000 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidInputCount.to_string(),
        )));
    }

    #[cfg(feature = "production")]
    let mut inputs = SmallVec::<[TransactionInput; 2]>::new();
    #[cfg(not(feature = "production"))]
    let mut inputs = Vec::new();

    for _ in 0..input_count {
        if data.len() < offset + 36 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let index = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if data.len() < offset + script_len as usize {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_sig = data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        let sequence = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as u64;
        offset += 4;

        inputs.push(TransactionInput {
            prevout: OutPoint { hash, index },
            script_sig,
            sequence,
        });
    }

    let (output_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if output_count > 1000000 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidOutputCount.to_string(),
        )));
    }

    #[cfg(feature = "production")]
    let mut outputs = SmallVec::<[TransactionOutput; 2]>::new();
    #[cfg(not(feature = "production"))]
    let mut outputs = Vec::new();

    for _ in 0..output_count {
        if data.len() < offset + 8 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let value = i64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if data.len() < offset + script_len as usize {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_pubkey = data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        outputs.push(TransactionOutput { value, script_pubkey });
    }

    if is_segwit {
        for _ in 0..input_count {
            let (stack_count, varint_len) = decode_varint(&data[offset..])?;
            offset += varint_len;
            for _ in 0..stack_count {
                let (item_len, varint_len) = decode_varint(&data[offset..])?;
                offset += varint_len;
                if data.len() < offset + item_len as usize {
                    return Err(ConsensusError::Serialization(Cow::Owned(
                        TransactionParseError::InsufficientBytes.to_string(),
                    )));
                }
                offset += item_len as usize;
            }
        }
    }

    if data.len() < offset + 4 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        )));
    }
    let lock_time = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;

    Ok(Transaction {
        version,
        inputs,
        outputs,
        lock_time,
    })
}

/// Deserialize a transaction, returning (tx, bytes_consumed). Convenience wrapper that discards witness data.
pub fn deserialize_transaction_with_offset(data: &[u8]) -> Result<(Transaction, usize)> {
    let (tx, _witnesses, bytes_consumed) = deserialize_transaction_with_witness(data)?;
    Ok((tx, bytes_consumed))
}

/// Deserialize a transaction from Bitcoin wire format, returning transaction, witness, and bytes consumed
pub fn deserialize_transaction_with_witness(
    data: &[u8],
) -> Result<(Transaction, Vec<Witness>, usize)> {
    let mut offset = 0;

    if data.len() < offset + 4 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        )));
    }
    let version = i32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;
    offset += 4;

    let is_segwit = data.len() >= offset + 2
        && data[offset] == 0x00
        && data[offset + 1] == 0x01;

    if is_segwit {
        offset += 2;
    }

    let (input_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if input_count > 1000000 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidInputCount.to_string(),
        )));
    }

    #[cfg(feature = "production")]
    let mut inputs = SmallVec::<[TransactionInput; 2]>::new();
    #[cfg(not(feature = "production"))]
    let mut inputs = Vec::new();

    for _ in 0..input_count {
        if data.len() < offset + 36 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let index = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if data.len() < offset + script_len as usize {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_sig = data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        let sequence = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as u64;
        offset += 4;

        inputs.push(TransactionInput {
            prevout: OutPoint { hash, index },
            script_sig,
            sequence,
        });
    }

    let (output_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if output_count > 1000000 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidOutputCount.to_string(),
        )));
    }

    #[cfg(feature = "production")]
    let mut outputs = SmallVec::<[TransactionOutput; 2]>::new();
    #[cfg(not(feature = "production"))]
    let mut outputs = Vec::new();

    for _ in 0..output_count {
        if data.len() < offset + 8 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let value = i64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if data.len() < offset + script_len as usize {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_pubkey = data[offset..offset + script_len as usize].to_vec();
        offset += script_len as usize;

        outputs.push(TransactionOutput { value, script_pubkey });
    }

    let mut all_witnesses: Vec<Witness> = Vec::new();
    if is_segwit {
        for _ in 0..input_count {
            let (stack_count, varint_len) = decode_varint(&data[offset..])?;
            offset += varint_len;

            let mut witness_stack: Witness = Vec::new();
            for _ in 0..stack_count {
                let (item_len, varint_len) = decode_varint(&data[offset..])?;
                offset += varint_len;

                if data.len() < offset + item_len as usize {
                    return Err(ConsensusError::Serialization(Cow::Owned(
                        TransactionParseError::InsufficientBytes.to_string(),
                    )));
                }
                witness_stack.push(data[offset..offset + item_len as usize].to_vec());
                offset += item_len as usize;
            }
            all_witnesses.push(witness_stack);
        }
    } else {
        for _ in 0..input_count {
            all_witnesses.push(Vec::new());
        }
    }

    if data.len() < offset + 4 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        )));
    }
    let lock_time = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as u64;
    offset += 4;

    let tx = Transaction {
        version,
        inputs,
        outputs,
        lock_time,
    };

    Ok((tx, all_witnesses, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let tx = Transaction {
            version: 1,
            inputs: crate::tx_inputs![TransactionInput {
                prevout: OutPoint { hash: [1; 32], index: 0 },
                script_sig: vec![0x51],
                sequence: 0xffffffff,
            }],
            outputs: crate::tx_outputs![TransactionOutput {
                value: 5000000000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };

        let serialized = serialize_transaction(&tx);
        let deserialized = deserialize_transaction(&serialized).unwrap();

        assert_eq!(deserialized.version, tx.version);
        assert_eq!(deserialized.inputs.len(), tx.inputs.len());
        assert_eq!(deserialized.outputs.len(), tx.outputs.len());
        assert_eq!(deserialized.lock_time, tx.lock_time);
    }
}
