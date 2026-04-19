//! Configuration types for consensus and protocol layers
//!
//! Provides foundational config structs used by blvm-consensus and blvm-protocol.
//! `ConsensusConfig` and other aggregates remain in blvm-consensus; operational
//! limits used across layers live here.

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
            // Matches Bitcoin Core's built-in hashAssumeValid (mainnet block 938343 in Core v28+).
            // Core skips script/signature verification for all blocks below this height when the
            // chain's total work meets nMinimumChainWork — BLVM must do the same to avoid false
            // divergences on blocks that were accepted historically without script validation.
            assume_valid_height: 938343,
            assume_valid_hash: None,
            n_minimum_chain_work: 0,
            median_time_past_headers: 11,
            enable_parallel_validation: true,
            coinbase_maturity_override: 0,
            max_block_sigops_cost_override: 0,
        }
    }
}

/// Mempool configuration
///
/// Controls mempool size limits, fee rates, and transaction expiry.
/// These are operational parameters, not consensus-critical.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum mempool size in megabytes (default 300 MB)
    /// Default: 300 MB
    #[serde(default = "default_max_mempool_mb")]
    pub max_mempool_mb: u64,

    /// Maximum number of transactions in mempool (alternative to size-based limit)
    /// Default: 100000
    #[serde(default = "default_max_mempool_txs")]
    pub max_mempool_txs: usize,

    /// Mempool transaction expiry in hours (default 336 = 14 days)
    /// Transactions older than this are removed from mempool
    /// Default: 336 (14 days)
    #[serde(default = "default_mempool_expiry_hours")]
    pub mempool_expiry_hours: u64,

    /// Minimum relay fee rate in satoshis per virtual byte (default 1 sat/vB)
    /// Transactions with fee rate below this are not relayed
    /// Default: 1 sat/vB (1000 sat/kB)
    #[serde(default = "default_min_relay_fee_rate")]
    pub min_relay_fee_rate: u64,

    /// Minimum transaction fee in satoshis (absolute minimum, regardless of size)
    /// Default: 1000 satoshis
    #[serde(default = "default_min_tx_fee")]
    pub min_tx_fee: i64,

    /// RBF (Replace-By-Fee) minimum fee increment in satoshis (BIP125)
    /// Replacement transactions must pay at least this much more than the original
    /// Default: 1000 satoshis
    #[serde(default = "default_rbf_fee_increment")]
    pub rbf_fee_increment: i64,

    /// Maximum OP_RETURN data size in bytes (default 80)
    /// Default: 80 bytes
    #[serde(default = "default_max_op_return_size")]
    pub max_op_return_size: u32,

    /// Maximum number of OP_RETURN outputs allowed (default: 1)
    /// Transactions with more than this are rejected as non-standard
    #[serde(default = "default_max_op_return_outputs")]
    pub max_op_return_outputs: u32,

    /// Reject transactions with multiple OP_RETURN outputs
    /// Default: true
    #[serde(default = "default_reject_multiple_op_return")]
    pub reject_multiple_op_return: bool,

    /// Maximum standard script size in bytes
    /// Default: 200 bytes
    #[serde(default = "default_max_standard_script_size")]
    pub max_standard_script_size: u32,

    /// Reject envelope protocol (OP_FALSE OP_IF) scripts
    /// Default: true
    #[serde(default = "default_reject_envelope_protocol")]
    pub reject_envelope_protocol: bool,

    /// Reject spam transactions at mempool entry (opt-in)
    /// Default: false (spam filtering is opt-in for mempool)
    ///
    /// **Admission:** enforced in `blvm-node` by `MempoolPolicyConfig::reject_spam_in_mempool`
    /// in `MempoolManager::add_transaction` (uses `blvm-protocol` spam filter).
    #[serde(default = "default_reject_spam_in_mempool")]
    pub reject_spam_in_mempool: bool,

    /// Spam filter configuration (if reject_spam_in_mempool is enabled)
    /// Note: Prefer `blvm-node` `MempoolPolicyConfig::spam_filter` + `SpamFilterConfigSerializable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spam_filter_config: Option<serde_json::Value>,

    /// Minimum fee rate for large transactions (satoshis per vbyte)
    /// Transactions larger than large_tx_threshold_bytes must pay at least this fee rate
    /// Default: 2 sat/vB (higher than standard min_relay_fee_rate)
    #[serde(default = "default_min_fee_rate_large_tx")]
    pub min_fee_rate_large_tx: u64,

    /// Large transaction threshold (bytes)
    /// Transactions larger than this require min_fee_rate_large_tx
    /// Default: 1000 bytes
    #[serde(default = "default_large_tx_threshold_bytes")]
    pub large_tx_threshold_bytes: u64,
}

fn default_rbf_fee_increment() -> i64 {
    1000
}

fn default_max_mempool_mb() -> u64 {
    300
}

fn default_max_mempool_txs() -> usize {
    100_000
}

fn default_mempool_expiry_hours() -> u64 {
    336 // 14 days
}

fn default_min_relay_fee_rate() -> u64 {
    1 // 1 sat/vB = 1000 sat/kB
}

fn default_min_tx_fee() -> i64 {
    1000
}

fn default_max_op_return_size() -> u32 {
    80
}

fn default_max_op_return_outputs() -> u32 {
    1
}

fn default_reject_multiple_op_return() -> bool {
    true
}

fn default_max_standard_script_size() -> u32 {
    200
}

fn default_reject_envelope_protocol() -> bool {
    true
}

fn default_reject_spam_in_mempool() -> bool {
    false
}

fn default_min_fee_rate_large_tx() -> u64 {
    2 // 2 sat/vB (higher than standard 1 sat/vB)
}

fn default_large_tx_threshold_bytes() -> u64 {
    1000 // 1 KB
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_mempool_mb: 300,
            max_mempool_txs: 100_000,
            mempool_expiry_hours: 336,
            min_relay_fee_rate: 1,
            min_tx_fee: 1000,
            rbf_fee_increment: 1000,
            max_op_return_size: 80,
            max_op_return_outputs: 1,
            reject_multiple_op_return: true,
            max_standard_script_size: 200,
            reject_envelope_protocol: true,
            reject_spam_in_mempool: false,
            spam_filter_config: None,
            min_fee_rate_large_tx: 2,
            large_tx_threshold_bytes: 1000,
        }
    }
}

fn default_false() -> bool {
    false
}

/// UTXO Commitment configuration
///
/// Controls UTXO commitment set size, storage limits, and performance tuning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoCommitmentConfig {
    /// Maximum UTXO commitment set size in megabytes
    /// This limits the in-memory size of the UTXO Merkle tree
    /// Default: 512 MB (sufficient for ~100M UTXOs)
    #[serde(default = "default_max_utxo_commitment_set_mb")]
    pub max_utxo_commitment_set_mb: u64,

    /// Maximum number of UTXOs in commitment set (alternative to size-based limit)
    /// Default: 100_000_000 (100 million UTXOs)
    #[serde(default = "default_max_utxo_count")]
    pub max_utxo_count: u64,

    /// Maximum number of historical commitments to keep in memory
    /// Older commitments are stored on disk
    /// Default: 1000 (keeps last ~7 days of commitments at 1 per block)
    #[serde(default = "default_max_historical_commitments")]
    pub max_historical_commitments: usize,

    /// Enable incremental commitment updates (recommended)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_incremental_updates: bool,
}

fn default_max_utxo_commitment_set_mb() -> u64 {
    512
}

fn default_max_utxo_count() -> u64 {
    100_000_000
}

fn default_max_historical_commitments() -> usize {
    1000
}

impl Default for UtxoCommitmentConfig {
    fn default() -> Self {
        Self {
            max_utxo_commitment_set_mb: 512,
            max_utxo_count: 100_000_000,
            max_historical_commitments: 1000,
            enable_incremental_updates: true,
        }
    }
}

/// Performance and optimization configuration
///
/// Controls performance tuning, parallelization, and optimization features.
/// These are operational parameters that affect performance but not consensus correctness.
///
/// IBD batch tuning: When `ibd_chunk_threshold` / `ibd_min_chunk_size` are `None`,
/// hardware-derived values are used. When `Some(x)`, config overrides hardware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of threads for script verification (default: number of CPU cores)
    /// Default: 0 (auto-detect from CPU count)
    #[serde(default)]
    pub script_verification_threads: usize,

    /// Batch size for parallel transaction validation
    /// Larger batches improve throughput but increase latency
    /// Default: 8 transactions per batch
    #[serde(default = "default_parallel_batch_size")]
    pub parallel_batch_size: usize,

    /// IBD batch: chunk threshold (parallelize when sig count exceeds this).
    /// None = use hardware-derived; Some(x) = override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ibd_chunk_threshold: Option<usize>,

    /// IBD batch: minimum chunk size for parallel batches.
    /// None = use hardware-derived; Some(x) = override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ibd_min_chunk_size: Option<usize>,

    /// Enable SIMD/vectorization optimizations (if available)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_simd_optimizations: bool,

    /// Enable cache-friendly memory layouts
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_cache_optimizations: bool,

    /// Enable batch UTXO lookups (pre-fetch all UTXOs before validation)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_batch_utxo_lookups: bool,
}

fn default_parallel_batch_size() -> usize {
    8
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            script_verification_threads: 0, // Auto-detect
            parallel_batch_size: 8,
            ibd_chunk_threshold: None,
            ibd_min_chunk_size: None,
            enable_simd_optimizations: true,
            enable_cache_optimizations: true,
            enable_batch_utxo_lookups: true,
        }
    }
}

/// Debug and development configuration
///
/// Controls debug assertions, runtime checks, and development features.
/// These options are safe to enable in production but may impact performance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DebugConfig {
    /// Enable runtime assertions (debug_assert! statements)
    /// Default: false (enabled automatically in debug builds)
    #[serde(default = "default_false")]
    pub enable_runtime_assertions: bool,

    /// Enable runtime invariant checks (additional safety checks)
    /// Default: false
    #[serde(default = "default_false")]
    pub enable_runtime_invariants: bool,

    /// Enable verbose logging for consensus operations
    /// Default: false
    #[serde(default = "default_false")]
    pub enable_verbose_logging: bool,

    /// Enable performance profiling (timing measurements)
    /// Default: false
    #[serde(default = "default_false")]
    pub enable_performance_profiling: bool,

    /// Log all rejected transactions/blocks (for debugging)
    /// Default: false
    #[serde(default = "default_false")]
    pub log_rejections: bool,
}

/// Feature flags configuration
///
/// Controls optional features and experimental functionality.
/// These are safe to enable/disable without affecting consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagsConfig {
    /// Enable experimental optimizations (may be unstable)
    /// Default: false
    #[serde(default = "default_false")]
    pub enable_experimental_optimizations: bool,

    /// Enable bounds check optimizations (requires formal proofs)
    /// Default: true (if production feature enabled)
    #[serde(default = "default_true")]
    pub enable_bounds_check_optimizations: bool,

    /// Enable reference implementation checks (slower but safer)
    /// Default: false
    #[serde(default = "default_false")]
    pub enable_reference_checks: bool,

    /// Enable aggressive caching (may use more memory)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_aggressive_caching: bool,

    /// Enable batch transaction ID computation (faster but uses more memory)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_batch_tx_id_computation: bool,

    /// Enable SIMD hash operations (faster on supported CPUs)
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_simd_hash_operations: bool,
}

impl Default for FeatureFlagsConfig {
    fn default() -> Self {
        Self {
            enable_experimental_optimizations: false,
            enable_bounds_check_optimizations: true,
            enable_reference_checks: false,
            enable_aggressive_caching: true,
            enable_batch_tx_id_computation: true,
            enable_simd_hash_operations: true,
        }
    }
}

/// Advanced configuration options
///
/// Advanced settings for power users and specific use cases.
/// These options provide fine-grained control over behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// Custom checkpoint heights (additional to assume-valid)
    /// Format: comma-separated list of block heights
    /// Example: "100000,200000,300000"
    /// Default: empty (no custom checkpoints)
    #[serde(default)]
    pub custom_checkpoints: Vec<u64>,

    /// Maximum depth for chain reorganization (safety limit)
    /// Prevents extremely deep reorganizations that could be DoS attacks
    /// Default: 100 blocks
    #[serde(default = "default_max_reorg_depth")]
    pub max_reorg_depth: u64,

    /// Enable strict mode (reject any non-standard transactions)
    /// Default: false (accept standard transactions)
    #[serde(default = "default_false")]
    pub strict_mode: bool,

    /// Maximum block size to accept (override consensus limit for testing)
    /// Default: 0 (use consensus limit)
    /// WARNING: Setting this may cause consensus divergence
    #[serde(default)]
    pub max_block_size_override: usize,

    /// Enable transaction replacement (RBF) by default
    /// Default: true
    #[serde(default = "default_true")]
    pub enable_rbf: bool,
}

fn default_max_reorg_depth() -> u64 {
    100
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            custom_checkpoints: Vec::new(),
            max_reorg_depth: 100,
            strict_mode: false,
            max_block_size_override: 0,
            enable_rbf: true,
        }
    }
}
