// Network parameters and consensus rules
// This module defines the consensus parameters for different Bitcoin networks

use bitcoin::{BlockHash, CompactTarget, Target};
use std::str::FromStr;

/// Consensus parameters for a specific Bitcoin network
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    /// Maximum allowed target (minimum difficulty)
    pub pow_limit: CompactTarget,
    /// Target timespan for difficulty adjustment (2 weeks in seconds)
    pub pow_target_timespan: u32,
    /// Target spacing between blocks (10 minutes in seconds)
    pub pow_target_spacing: u32,
    /// Number of blocks between difficulty adjustments
    pub difficulty_adjustment_interval: u32,
    /// Genesis block hash for this network
    pub genesis_hash: BlockHash,
    /// Network name for debugging
    pub network_name: &'static str,
}

impl ConsensusParams {
    /// Get consensus parameters for Bitcoin mainnet
    pub fn mainnet() -> Self {
        Self {
            pow_limit: CompactTarget::from_consensus(0x1d00ffff),
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks in seconds
            pow_target_spacing: 10 * 60,             // 10 minutes in seconds
            difficulty_adjustment_interval: 2016,    // 2016 blocks
            genesis_hash: BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .expect("Valid mainnet genesis hash"),
            network_name: "mainnet",
        }
    }

    /// Get consensus parameters for Bitcoin testnet
    pub fn testnet() -> Self {
        Self {
            pow_limit: CompactTarget::from_consensus(0x1d00ffff), // Same as mainnet
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks in seconds
            pow_target_spacing: 10 * 60,             // 10 minutes in seconds
            difficulty_adjustment_interval: 2016,    // 2016 blocks
            genesis_hash: BlockHash::from_str("000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")
                .expect("Valid testnet genesis hash"),
            network_name: "testnet",
        }
    }

    /// Get the maximum allowed target as a Target type
    pub fn pow_limit_target(&self) -> Target {
        Target::from_compact(self.pow_limit)
    }

    /// Check if a target is within the network's PoW limit
    pub fn is_target_valid(&self, target: &Target) -> bool {
        *target <= self.pow_limit_target()
    }

    /// Get the expected time for a difficulty adjustment period
    pub fn expected_timespan(&self) -> u32 {
        self.difficulty_adjustment_interval * self.pow_target_spacing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_params() {
        let params = ConsensusParams::mainnet();

        assert_eq!(params.pow_target_timespan, 14 * 24 * 60 * 60);
        assert_eq!(params.pow_target_spacing, 10 * 60);
        assert_eq!(params.difficulty_adjustment_interval, 2016);
        assert_eq!(params.network_name, "mainnet");

        // Check that pow_limit is valid
        let pow_limit_target = params.pow_limit_target();
        assert!(params.is_target_valid(&pow_limit_target));
    }

    #[test]
    fn test_testnet_params() {
        let params = ConsensusParams::testnet();

        assert_eq!(params.pow_target_timespan, 14 * 24 * 60 * 60);
        assert_eq!(params.pow_target_spacing, 10 * 60);
        assert_eq!(params.difficulty_adjustment_interval, 2016);
        assert_eq!(params.network_name, "testnet");

        // Testnet should have different genesis hash than mainnet
        let mainnet_params = ConsensusParams::mainnet();
        assert_ne!(params.genesis_hash, mainnet_params.genesis_hash);
    }

    #[test]
    fn test_target_validation() {
        let params = ConsensusParams::mainnet();

        // Valid target (at the limit)
        let valid_target = params.pow_limit_target();
        assert!(params.is_target_valid(&valid_target));

        // Invalid target (exceeds limit) - use a very small target
        let invalid_target = Target::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(!params.is_target_valid(&invalid_target));
    }

    #[test]
    fn test_expected_timespan() {
        let params = ConsensusParams::mainnet();
        let expected = params.expected_timespan();

        // Should be 2016 blocks * 10 minutes = 20,160 minutes = 1,209,600 seconds
        assert_eq!(expected, 2016 * 10 * 60);
    }
}
