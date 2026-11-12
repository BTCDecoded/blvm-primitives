//! Test-line QA: serialization round-trip and a truncated buffer.

use blvm_primitives::{
    Block, BlockHeader, ConsensusError, OutPoint, Transaction, TransactionInput, TransactionOutput,
    decode_varint, deserialize_block_header, deserialize_block_with_witnesses,
    deserialize_transaction, encode_varint, serialize_block, serialize_block_header,
    serialize_transaction,
};

fn expect_insufficient(result: blvm_primitives::Result<()>) {
    match result {
        Err(ConsensusError::Serialization(message)) => {
            assert!(
                message.contains("Insufficient bytes"),
                "truncated input returned a different serialization error: {message}"
            );
        }
        Ok(()) => panic!("truncated input was accepted"),
        Err(other) => panic!("truncated input returned {other:?}"),
    }
}

fn sample_transaction() -> Transaction {
    Transaction {
        version: 1,
        inputs: blvm_primitives::tx_inputs![TransactionInput {
            prevout: OutPoint {
                hash: [1; 32],
                index: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: blvm_primitives::tx_outputs![TransactionOutput {
            value: 50,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    }
}

#[test]
fn varint_round_trip_and_truncated_prefix_fail() {
    let encoded = encode_varint(0xfd);
    let (value, consumed) = decode_varint(&encoded).expect("encoded varint");
    assert_eq!(value, 0xfd);
    assert_eq!(consumed, encoded.len());

    expect_insufficient(decode_varint(&[0xfd]).map(|_| ()));
}

#[test]
fn transaction_round_trip_and_truncated_buffer_fail() {
    let tx = sample_transaction();
    let bytes = serialize_transaction(&tx);
    let decoded = deserialize_transaction(&bytes).expect("serialized transaction");
    assert_eq!(decoded, tx);

    expect_insufficient(deserialize_transaction(&bytes[..bytes.len() - 1]).map(|_| ()));
}

#[test]
fn block_round_trip_and_truncated_header_fail() {
    let header = BlockHeader {
        version: 1,
        prev_block_hash: [0; 32],
        merkle_root: [2; 32],
        timestamp: 1_231_006_505,
        bits: 0x1d00_ffff,
        nonce: 1,
    };
    let header_bytes = serialize_block_header(&header);
    let decoded_header = deserialize_block_header(&header_bytes).expect("serialized header");
    assert_eq!(decoded_header, header);
    expect_insufficient(deserialize_block_header(&header_bytes[..79]).map(|_| ()));

    let block = Block::from_parts(header, vec![sample_transaction()].into_boxed_slice());
    let bytes = serialize_block(&block);
    let (decoded, _) = deserialize_block_with_witnesses(&bytes).expect("serialized block");
    assert_eq!(decoded.header, block.header);
    assert_eq!(decoded.transactions.as_ref(), block.transactions.as_ref());
    expect_insufficient(deserialize_block_with_witnesses(&bytes[..bytes.len() - 1]).map(|_| ()));
}
