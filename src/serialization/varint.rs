//! Bitcoin VarInt encoding/decoding
//!
//! VarInt (Variable Integer) is a compact encoding for integers used throughout
//! Bitcoin's wire format. It uses 1-9 bytes depending on the value.
//!
//! Encoding rules:
//! - If value < 0xfd: single byte
//! - If value <= 0xffff: 0xfd prefix + 2 bytes (little-endian)
//! - If value <= 0xffffffff: 0xfe prefix + 4 bytes (little-endian)
//! - Otherwise: 0xff prefix + 8 bytes (little-endian)
//!
//! This must match consensus's CVarInt implementation exactly.

use crate::error::{ConsensusError, Result};
use std::borrow::Cow;

/// Error type for VarInt encoding/decoding failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarIntError {
    /// Insufficient bytes to decode VarInt
    InsufficientBytes,
    /// Invalid VarInt encoding format
    InvalidEncoding,
    /// VarInt value exceeds maximum (u64::MAX)
    ValueTooLarge,
}

impl std::fmt::Display for VarIntError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarIntError::InsufficientBytes => write!(f, "Insufficient bytes to decode VarInt"),
            VarIntError::InvalidEncoding => write!(f, "Invalid VarInt encoding"),
            VarIntError::ValueTooLarge => write!(f, "VarInt value too large"),
        }
    }
}

impl std::error::Error for VarIntError {}

/// Encode a u64 value as a Bitcoin VarInt
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        debug_assert!(value >= 0xfd);
        let mut result = vec![0xfd];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        debug_assert!(result.len() == 3);
        result
    } else if value <= 0xffffffff {
        debug_assert!(value > 0xffff);
        let mut result = vec![0xfe];
        result.extend_from_slice(&(value as u32).to_le_bytes());
        debug_assert!(result.len() == 5);
        result
    } else {
        debug_assert!(value > 0xffffffff);
        let mut result = vec![0xff];
        result.extend_from_slice(&value.to_le_bytes());
        debug_assert!(result.len() == 9);
        result
    }
}

/// Decode a Bitcoin VarInt from bytes
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err(ConsensusError::Serialization(Cow::Owned(
            VarIntError::InsufficientBytes.to_string(),
        )));
    }

    let first_byte = data[0];

    match first_byte {
        b if b < 0xfd => Ok((b as u64, 1)),

        0xfd => {
            if data.len() < 3 {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InsufficientBytes.to_string(),
                )));
            }
            let value = u16::from_le_bytes([data[1], data[2]]) as u64;
            if value < 0xfd {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InvalidEncoding.to_string(),
                )));
            }
            Ok((value, 3))
        }

        0xfe => {
            if data.len() < 5 {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InsufficientBytes.to_string(),
                )));
            }
            let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
            if value <= 0xffff {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InvalidEncoding.to_string(),
                )));
            }
            Ok((value, 5))
        }

        0xff => {
            if data.len() < 9 {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InsufficientBytes.to_string(),
                )));
            }
            let value = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            if value <= 0xffffffff {
                return Err(ConsensusError::Serialization(Cow::Owned(
                    VarIntError::InvalidEncoding.to_string(),
                )));
            }
            Ok((value, 9))
        }

        _ => Err(ConsensusError::Serialization(Cow::Owned(
            VarIntError::InvalidEncoding.to_string(),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_round_trip() {
        let values = [0u64, 252, 253, 65535, 65536, 0xffffffff, 0x100000000, u64::MAX];
        for value in values {
            let encoded = encode_varint(value);
            let (decoded, len) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(len, encoded.len());
        }
    }
}
