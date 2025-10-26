// Consensus rules and parameters
// This module provides consensus-related functionality for Bitcoin networks

pub mod params;

pub use params::ConsensusParams;

/// Get consensus parameters for a specific network
pub fn get_consensus_params(network: &crate::config::Network) -> ConsensusParams {
    match network {
        crate::config::Network::Mainnet => ConsensusParams::mainnet(),
        crate::config::Network::Testnet => ConsensusParams::testnet(),
    }
}
