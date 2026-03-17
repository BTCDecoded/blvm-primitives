//! Configuration types for consensus and protocol layers
//!
//! Provides foundational config structs used by blvm-consensus and blvm-protocol.
//! Full ConsensusConfig (with mempool, spam_filter, utxo_commitments) remains in
//! blvm-consensus until Phase 2/4 migration.

use serde::{Deserialize, Serialize};

/// Network message size limits configuration
///
/// These limits protect against DoS attacks by bounding the size of network messages.
/// All limits match Bitcoin protocol defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMessageLimits {
    /// Maximum addresses in an addr message (protocol default: 1000)
    #[serde(default = "default_max_addr_addresses")]
    pub max_addr_addresses: usize,

    /// Maximum inventory items in inv/getdata messages (protocol default: 50000)
    #[serde(default = "default_max_inv_items")]
    pub max_inv_items: usize,

    /// Maximum headers in a headers message (protocol default: 2000)
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,

    /// Maximum user agent length in version message (protocol default: 256 bytes)
    #[serde(default = "default_max_user_agent_length")]
    pub max_user_agent_length: usize,
}

fn default_max_addr_addresses() -> usize {
    1000
}

fn default_max_inv_items() -> usize {
    50000
}

fn default_max_headers() -> usize {
    2000
}

fn default_max_user_agent_length() -> usize {
    256
}

impl Default for NetworkMessageLimits {
    fn default() -> Self {
        Self {
            max_addr_addresses: 1000,
            max_inv_items: 50000,
            max_headers: 2000,
            max_user_agent_length: 256,
        }
    }
}

/// Block validation configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockValidationConfig {
    /// Assume-valid height: blocks before this height skip signature verification
    #[serde(default)]
    pub assume_valid_height: u64,

    /// Assume-valid block hash: when set, verify block at assume_valid_height matches
    #[serde(default)]
    pub assume_valid_hash: Option<[u8; 32]>,

    /// Minimum chain work: skip only when best_header_chainwork >= this
    #[serde(default)]
    pub n_minimum_chain_work: u128,

    /// Number of recent headers for median time-past calculation (BIP113)
    #[serde(default = "default_median_time_past_headers")]
    pub median_time_past_headers: usize,

    /// Enable parallel transaction validation
    #[serde(default = "default_true")]
    pub enable_parallel_validation: bool,

    /// Coinbase maturity override (for testing only)
    #[serde(default)]
    pub coinbase_maturity_override: u64,

    /// Maximum block sigop cost override (for testing only)
    #[serde(default)]
    pub max_block_sigops_cost_override: u64,
}

fn default_median_time_past_headers() -> usize {
    11
}

fn default_true() -> bool {
    true
}

impl Default for BlockValidationConfig {
    fn default() -> Self {
        Self {
            assume_valid_height: 0,
            assume_valid_hash: None,
            n_minimum_chain_work: 0,
            median_time_past_headers: 11,
            enable_parallel_validation: true,
            coinbase_maturity_override: 0,
            max_block_sigops_cost_override: 0,
        }
    }
}
