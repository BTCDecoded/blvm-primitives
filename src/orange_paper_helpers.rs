//! Property test helpers from Orange Paper formulas
//!
//! Auto-generated from blvm-spec/THE_ORANGE_PAPER.md via cargo spec-lock extract-formulas.
//! These helpers allow property tests to compare implementation results against the spec.

use crate::constants::{C, H, M_MAX};

/// ValidateSupplyLimit(h) = TotalSupply(h) <= MAX_MONEY
pub fn expected_validatesupplylimit_from_orange_paper(height: u64) -> bool {
    let total_supply = expected_totalsupply_from_orange_paper(height);
    total_supply <= M_MAX
}

/// TotalSupply(h) = sum of all block subsidies from 0 to h
pub fn expected_totalsupply_from_orange_paper(height: u64) -> i64 {
    let mut total = 0i64;
    for h in 0..=height {
        let halving_period = h / H;
        let initial_subsidy = 50 * C;
        if halving_period < 64 {
            total += (initial_subsidy >> halving_period) as i64;
        }
    }
    total
}

/// GetBlockSubsidy(h) = 50 × C × 2^(-⌊h/H⌋)
pub fn expected_getblocksubsidy_from_orange_paper(height: u64) -> i64 {
    let halving_period = height / H;
    let initial_subsidy = 50 * C;
    if halving_period >= 64 {
        0
    } else {
        (initial_subsidy >> halving_period) as i64
    }
}

/// BlockReward(h) = GetBlockSubsidy(h) + Fees(block)
pub fn expected_blockreward_from_orange_paper(height: u64, fees: i64) -> i64 {
    expected_getblocksubsidy_from_orange_paper(height) + fees
}

/// InflationRate(h) = (GetBlockSubsidy(h) × BlocksPerYear) / TotalSupply(h)
pub fn expected_inflationrate_from_orange_paper(height: u64) -> f64 {
    const BLOCKS_PER_YEAR: f64 = 52_560.0;
    let subsidy = expected_getblocksubsidy_from_orange_paper(height) as f64;
    let total_supply = expected_totalsupply_from_orange_paper(height) as f64;
    if total_supply > 0.0 {
        (subsidy * BLOCKS_PER_YEAR) / total_supply
    } else {
        0.0
    }
}

/// HalvingEpoch(h) = ⌊h/H⌋
pub fn expected_halvingepoch_from_orange_paper(height: u64) -> u64 {
    height / H
}

/// RemainingSupply(h) = M_MAX - TotalSupply(h)
pub fn expected_remainingsupply_from_orange_paper(height: u64) -> i64 {
    M_MAX - expected_totalsupply_from_orange_paper(height)
}

/// Difficulty(target) = TARGET_MAX / target
pub fn expected_difficultyfromtarget_from_orange_paper(target: u64) -> f64 {
    const TARGET_MAX: f64 = 2.69599466e67;
    if target > 0 {
        TARGET_MAX / (target as f64)
    } else {
        f64::INFINITY
    }
}

/// Work(target) = 2^256 / (target + 1) (simplified)
pub fn expected_workfromtarget_from_orange_paper(target: u64) -> u128 {
    if target > 0 {
        let target_plus_one = (target as u128) + 1;
        u128::MAX / target_plus_one.max(1)
    } else {
        u128::MAX
    }
}

/// UTXOSetValue(utxo_set) = sum(utxo.value for utxo in utxo_set)
pub fn expected_utxosetvalue_from_orange_paper(utxo_values: &[i64]) -> i64 {
    utxo_values.iter().sum()
}
