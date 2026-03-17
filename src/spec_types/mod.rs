//! Specification-aware type wrappers for formal verification (spec-lock/Z3).
//!
//! Transparent wrappers around standard collections so types can be aligned with
//! Orange Paper / spec-lock. Use `SpecVec` / `SpecHashMap` or the `spec_wrap!` macro.

mod spec_hashmap;
mod spec_vec;

pub use spec_hashmap::SpecHashMap;
pub use spec_vec::SpecVec;

/// Macro for type aliases using spec wrappers (for spec alignment / formal verification).
///
/// # Example
///
/// ```ignore
/// use blvm_primitives::spec_wrap;
///
/// spec_wrap!(ByteString = Vec<u8>);
/// // pub type ByteString = SpecVec<u8>;
/// ```
#[macro_export]
macro_rules! spec_wrap {
    ($name:ident = Vec<$t:ty>) => {
        pub type $name = $crate::SpecVec<$t>;
    };
    ($name:ident = HashMap<$k:ty, $v:ty>) => {
        pub type $name = $crate::SpecHashMap<$k, $v>;
    };
}
