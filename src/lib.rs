//! # blvm-primitives
//!
//! Foundational types, serialization, crypto, and config for Bitcoin consensus and protocol layers.
//!
//! This crate provides the shared foundation that both blvm-consensus and blvm-protocol depend on,
//! enabling parallel compilation and clean separation of concerns.

pub mod config;
pub mod constants;
pub mod crypto;
pub mod ibd_tuning;
pub mod orange_paper_helpers;
pub mod error;
pub mod opcodes;
pub mod serialization;
pub mod spec_types;
pub mod types;

// Re-export commonly used items
pub use config::*;
pub use constants::*;
pub use crypto::*;
pub use error::*;
pub use opcodes::*;
pub use serialization::*;
pub use spec_types::{SpecHashMap, SpecVec};
pub use types::*;
