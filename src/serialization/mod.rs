//! Bitcoin wire format serialization/deserialization
//!
//! Consensus-critical serialization functions that must match
//! consensus wire format exactly for consensus compatibility.
//!
//! All serialization uses little-endian byte order (Bitcoin standard).

pub mod block;
pub mod transaction;
pub mod varint;

pub use block::{
    deserialize_block_header, deserialize_block_with_witnesses,
    output_script_pubkey_slices_from_wire_block,
    serialize_block, serialize_block_header, serialize_block_with_witnesses,
    validate_block_serialized_size,
};
pub use transaction::{
    deserialize_transaction, deserialize_transaction_with_offset,
    deserialize_transaction_with_witness, output_script_pubkey_slices_from_wire_tx,
    serialize_transaction,
    serialize_transaction_into, serialize_transaction_with_witness,
};
pub use varint::{VarIntError, decode_varint, encode_varint};
