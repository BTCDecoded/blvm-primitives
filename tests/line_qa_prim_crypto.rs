//! Test-line QA: known-answer hashes, an unequal compare, and an overflow error.

use blvm_primitives::{
    ConsensusError, hash256, hash_compare::hash_eq, int_ops::safe_add, sha256,
};

const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const HASH256_EMPTY: &str = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

#[test]
fn sha256_and_hash256_match_the_empty_vector() {
    assert_eq!(sha256(b""), hex32(SHA256_EMPTY));
    assert_eq!(hash256(b""), hex32(HASH256_EMPTY));
}

#[test]
fn hash_eq_rejects_a_mismatched_digest() {
    let empty = sha256(b"");
    let other = sha256(b"x");
    assert_eq!(hash_eq(&empty, &empty), true);
    assert_eq!(hash_eq(&empty, &other), false);
}

#[test]
fn safe_add_rejects_overflow() {
    match safe_add(i64::MAX, 1) {
        Err(ConsensusError::TransactionValidation(message)) => {
            assert!(
                message.contains("Arithmetic overflow"),
                "overflow returned {message}"
            );
        }
        Ok(value) => panic!("i64::MAX + 1 was accepted as {value}"),
        Err(other) => panic!("overflow returned {other:?}"),
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sha_ni_and_batch_match_the_empty_vector() {
    use blvm_primitives::avx2_batch::batch_sha256_avx2;
    use blvm_primitives::sha256_avx2::{is_avx2_available, sha256_8way_avx2};
    use blvm_primitives::sha_ni;

    let expected = hex32(SHA256_EMPTY);
    assert_eq!(sha_ni::sha256(b""), expected);
    assert_eq!(sha_ni::hash256(b""), hex32(HASH256_EMPTY));
    assert_eq!(batch_sha256_avx2(&[b""])[0], expected);

    if is_avx2_available() {
        let inputs = [&b""[..]; 8];
        let digests = unsafe { sha256_8way_avx2(&inputs) };
        assert_eq!(digests[0], hex32(HASH256_EMPTY));
    }
}
