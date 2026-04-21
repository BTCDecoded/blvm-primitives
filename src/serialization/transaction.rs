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

#[inline]
fn checked_slice_end(offset: usize, len: u64) -> Result<usize> {
    let len = usize::try_from(len).map_err(|_| {
        ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidScriptLength.to_string(),
        ))
    })?;
    offset.checked_add(len).ok_or_else(|| {
        ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        ))
    })
}

/// After the 4-byte `version`, read the compact input count and optional segwit wrapper.
///
/// Matches [`UnserializeTransaction`] in Bitcoin Core: the first varint is always the input count.
/// If it is zero, the next byte is an optional-features flag. `1` means BIP141 extended encoding
/// (marker was absorbed into the empty `vin` vector); the real input-count varint follows. Flag `0`
/// means no extension: `vin` and `vout` both stay empty and **no** output-count varint appears on
/// the wire before `lock_time`.
///
/// **Do not** detect segwit by peeking `0x00 0x01` before decoding that first varint: the compact
/// encoding of the input count is not always a single `0x00` byte, so peeking mis-aligns the stream.
fn read_tx_input_count_after_version(
    data: &[u8],
    mut offset: usize,
) -> Result<(bool, u64, usize, bool)> {
    let (mut input_count, varint_len) = decode_varint(&data[offset..])?;
    offset += varint_len;

    if input_count > 1_000_000 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InvalidInputCount.to_string(),
        )));
    }

    let mut is_segwit = false;
    // When true, Bitcoin Core left vout empty without reading a vector length (flag byte was 0).
    let mut implicit_empty_outputs = false;

    if input_count == 0 {
        if offset >= data.len() {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let flag = data[offset];
        offset += 1;

        if flag == 0 {
            implicit_empty_outputs = true;
            return Ok((false, 0, offset, implicit_empty_outputs));
        }

        if flag != 1 {
            return Err(ConsensusError::Serialization(Cow::Owned(format!(
                "Unsupported segwit transaction flag: {flag}"
            ))));
        }

        is_segwit = true;

        let (ic2, vl2) = decode_varint(&data[offset..])?;
        offset += vl2;
        if ic2 > 1_000_000 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InvalidInputCount.to_string(),
            )));
        }
        input_count = ic2;
    }

    Ok((is_segwit, input_count, offset, implicit_empty_outputs))
}

/// Serialize a transaction to Bitcoin wire format
#[inline(always)]
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut result = Vec::new();
    serialize_transaction_append(&mut result, tx);
    result
}

/// Append serialized transaction to buffer (shared logic for into/inner).
///
/// When `vin` is empty and `vout` is non-empty, legacy `compact_size(0) || compact_size(n)` would
/// serialize as `0x00 0x01…`, which our witness-aware deserializer (matching Bitcoin Core with
/// witnesses allowed) reads as empty `vin` + **flag** `0x01`, not as `vout` count. Emit extended
/// framing: dummy empty `vin`, flag `0x01`, real input count, then `vout` (see `SerializeTransaction`
/// in Bitcoin Core).
#[inline(always)]
fn serialize_transaction_append(result: &mut Vec<u8>, tx: &Transaction) {
    result.extend_from_slice(&(tx.version as i32).to_le_bytes());

    if tx.inputs.is_empty() && !tx.outputs.is_empty() {
        result.extend_from_slice(&encode_varint(0));
        result.push(0x01);
        result.extend_from_slice(&encode_varint(tx.inputs.len() as u64));
    } else {
        result.extend_from_slice(&encode_varint(tx.inputs.len() as u64));
    }

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
    assert_eq!(
        witnesses.len(),
        tx.inputs.len(),
        "witness count must match input count"
    );
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
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as u64;
    offset += 4;

    let (is_segwit, input_count, mut offset, implicit_empty_outputs) =
        read_tx_input_count_after_version(data, offset)?;

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
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        let script_sig_end = checked_slice_end(offset, script_len)?;
        if data.len() < script_sig_end {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_sig = data[offset..script_sig_end].to_vec();
        offset = script_sig_end;

        if data.len() < offset + 4 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let sequence = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        offset += 4;

        inputs.push(TransactionInput {
            prevout: OutPoint { hash, index },
            script_sig,
            sequence,
        });
    }

    let output_count = if implicit_empty_outputs {
        0
    } else {
        let (output_count, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if output_count > 1000000 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InvalidOutputCount.to_string(),
            )));
        }
        output_count
    };

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
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        let script_pubkey_end = checked_slice_end(offset, script_len)?;
        if data.len() < script_pubkey_end {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_pubkey = data[offset..script_pubkey_end].to_vec();
        offset = script_pubkey_end;

        outputs.push(TransactionOutput {
            value,
            script_pubkey,
        });
    }

    if is_segwit {
        for _ in 0..input_count {
            let (stack_count, varint_len) = decode_varint(&data[offset..])?;
            offset += varint_len;
            for _ in 0..stack_count {
                let (item_len, varint_len) = decode_varint(&data[offset..])?;
                offset += varint_len;
                let item_end = checked_slice_end(offset, item_len)?;
                if data.len() < item_end {
                    return Err(ConsensusError::Serialization(Cow::Owned(
                        TransactionParseError::InsufficientBytes.to_string(),
                    )));
                }
                offset = item_end;
            }
        }
    }

    if data.len() < offset + 4 {
        return Err(ConsensusError::Serialization(Cow::Owned(
            TransactionParseError::InsufficientBytes.to_string(),
        )));
    }
    let lock_time = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
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
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as u64;
    offset += 4;

    let (is_segwit, input_count, mut offset, implicit_empty_outputs) =
        read_tx_input_count_after_version(data, offset)?;

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
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        let script_sig_end = checked_slice_end(offset, script_len)?;
        if data.len() < script_sig_end {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_sig = data[offset..script_sig_end].to_vec();
        offset = script_sig_end;

        if data.len() < offset + 4 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let sequence = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        offset += 4;

        inputs.push(TransactionInput {
            prevout: OutPoint { hash, index },
            script_sig,
            sequence,
        });
    }

    let output_count = if implicit_empty_outputs {
        0
    } else {
        let (output_count, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        if output_count > 1000000 {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InvalidOutputCount.to_string(),
            )));
        }
        output_count
    };

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
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        let (script_len, varint_len) = decode_varint(&data[offset..])?;
        offset += varint_len;

        let script_pubkey_end = checked_slice_end(offset, script_len)?;
        if data.len() < script_pubkey_end {
            return Err(ConsensusError::Serialization(Cow::Owned(
                TransactionParseError::InsufficientBytes.to_string(),
            )));
        }
        let script_pubkey = data[offset..script_pubkey_end].to_vec();
        offset = script_pubkey_end;

        outputs.push(TransactionOutput {
            value,
            script_pubkey,
        });
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

                let item_end = checked_slice_end(offset, item_len)?;
                if data.len() < item_end {
                    return Err(ConsensusError::Serialization(Cow::Owned(
                        TransactionParseError::InsufficientBytes.to_string(),
                    )));
                }
                witness_stack.push(data[offset..item_end].to_vec());
                offset = item_end;
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
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
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
                prevout: OutPoint {
                    hash: [1; 32],
                    index: 0
                },
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

    /// Bitcoin Core: empty `vin` + flag `0` implies empty `vout` without a separate output-count read.
    #[test]
    fn empty_tx_round_trip_matches_double_zero_preamble() {
        let tx = Transaction {
            version: 1,
            inputs: crate::tx_inputs![],
            outputs: crate::tx_outputs![],
            lock_time: 0,
        };
        let bytes = serialize_transaction(&tx);
        let back = deserialize_transaction(&bytes).unwrap();
        assert_eq!(back.version, tx.version);
        assert!(back.inputs.is_empty());
        assert!(back.outputs.is_empty());
        assert_eq!(back.lock_time, tx.lock_time);
        // version(4) + vin=0 + flags=0 + locktime(4) — two 0x00 bytes after version
        assert_eq!(&bytes[4..6], &[0u8, 0u8]);
    }

    #[test]
    fn zero_inputs_one_output_round_trips_extended_framing() {
        let tx = Transaction {
            version: 2,
            inputs: crate::tx_inputs![],
            outputs: crate::tx_outputs![TransactionOutput {
                value: 1000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0x11223344,
        };
        let bytes = serialize_transaction(&tx);
        let back = deserialize_transaction(&bytes).unwrap();
        assert_eq!(back.version, tx.version);
        assert!(back.inputs.is_empty());
        assert_eq!(back.outputs.len(), 1);
        assert_eq!(back.outputs[0].value, 1000);
        assert_eq!(back.lock_time, tx.lock_time);
        // version(4) + 0x00 dummy vin + 0x01 flag + 0x00 real ic + vout count + ...
        assert_eq!(&bytes[4..8], &[0u8, 1, 0, 1]);
    }
}
