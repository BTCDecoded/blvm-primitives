//! Rejects the primitives helpers already return: a non-minimal varint,
//! an underflow, and a subsidy past the last halving.

use blvm_primitives::int_ops::safe_sub;
use blvm_primitives::orange_paper_helpers::expected_getblocksubsidy_from_orange_paper;
use blvm_primitives::{ConsensusError, H, decode_varint};

#[test]
fn decode_varint_rejects_a_non_minimal_encoding() {
    match decode_varint(&[0xfd, 0x01, 0x00]) {
        Err(ConsensusError::Serialization(message)) => {
            assert!(
                message.contains("Invalid VarInt encoding"),
                "non-minimal varint returned {message}"
            );
        }
        Ok((value, consumed)) => panic!("non-minimal varint decoded {value} in {consumed} bytes"),
        Err(other) => panic!("non-minimal varint returned {other:?}"),
    }
}

#[test]
fn safe_sub_rejects_underflow() {
    match safe_sub(i64::MIN, 1) {
        Err(ConsensusError::TransactionValidation(message)) => {
            assert!(
                message.contains("Arithmetic underflow"),
                "safe_sub returned {message}"
            );
        }
        Ok(value) => panic!("underflow subtracted to {value}"),
        Err(other) => panic!("safe_sub returned {other:?}"),
    }
}

#[test]
fn subsidy_is_zero_after_the_last_halving() {
    let subsidy = expected_getblocksubsidy_from_orange_paper(64 * H);
    assert_eq!(subsidy, 0, "subsidy after 64 halvings was {subsidy}");
}
