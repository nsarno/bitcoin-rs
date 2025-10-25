// DNS seed resolution for peer discovery
// This module handles DNS seed queries to discover Bitcoin peers

use crate::network::message::NetworkAddress;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::lookup_host;

#[derive(Error, Debug)]
pub enum DnsSeedError {
    #[error("DNS lookup failed: {0}")]
    LookupFailed(String),
    #[error("No addresses found for seed: {0}")]
    NoAddresses(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// DNS seed configuration for different networks
pub struct DnsSeeds {
    pub testnet_seeds: Vec<&'static str>,
    pub mainnet_seeds: Vec<&'static str>,
}

impl DnsSeeds {
    pub fn new() -> Self {
        Self {
            testnet_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "seed.testnet.bitcoin.sprovoost.nl",
                "testnet-seed.bluematt.me",
            ],
            mainnet_seeds: vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
            ],
        }
    }

    /// Get DNS seeds for the specified network
    pub fn get_seeds(&self, is_testnet: bool) -> &[&'static str] {
        if is_testnet {
            &self.testnet_seeds
        } else {
            &self.mainnet_seeds
        }
    }
}

impl Default for DnsSeeds {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS seed resolver for peer discovery
pub struct DnsSeedResolver {
    seeds: DnsSeeds,
    timeout: Duration,
}

impl DnsSeedResolver {
    /// Create a new DNS seed resolver
    pub fn new() -> Self {
        Self {
            seeds: DnsSeeds::new(),
            timeout: Duration::from_secs(10), // 10 second timeout
        }
    }

    /// Create a DNS seed resolver with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            seeds: DnsSeeds::new(),
            timeout,
        }
    }

    /// Resolve DNS seeds to get peer addresses
    pub async fn resolve_seeds(&self, is_testnet: bool) -> Result<Vec<NetworkAddress>, DnsSeedError> {
        let seeds = self.seeds.get_seeds(is_testnet);
        let mut all_addresses = Vec::new();

        for seed in seeds {
            match self.resolve_single_seed(seed).await {
                Ok(addresses) => {
                    all_addresses.extend(addresses);
                }
                Err(e) => {
                    tracing::warn!("Failed to resolve seed {}: {}", seed, e);
                    // Continue with other seeds
                }
            }
        }

        if all_addresses.is_empty() {
            return Err(DnsSeedError::NoAddresses("No addresses found from any seed".to_string()));
        }

        // Remove duplicates and shuffle
        all_addresses.sort_by_key(|addr| addr.ip);
        all_addresses.dedup_by_key(|addr| addr.ip);

        // Shuffle the results
        use rand::seq::SliceRandom;
        use rand::thread_rng;
        all_addresses.shuffle(&mut thread_rng());

        Ok(all_addresses)
    }

    /// Resolve a single DNS seed
    async fn resolve_single_seed(&self, seed: &str) -> Result<Vec<NetworkAddress>, DnsSeedError> {
        let host = format!("{}:18333", seed); // Default to testnet port, will be adjusted based on network

        let addresses = tokio::time::timeout(self.timeout, lookup_host(&host))
            .await
            .map_err(|_| DnsSeedError::LookupFailed(format!("Timeout resolving {}", seed)))?
            .map_err(|e| DnsSeedError::LookupFailed(format!("Failed to resolve {}: {}", seed, e)))?;

        let mut network_addresses = Vec::new();

        for addr in addresses {
            if let SocketAddr::V4(ipv4_addr) = addr {
                let ip_bytes = ipv4_addr.ip().octets();
                let mut ipv6_bytes = [0u8; 16];
                // Convert IPv4 to IPv6-mapped IPv4
                ipv6_bytes[10] = 0xff;
                ipv6_bytes[11] = 0xff;
                ipv6_bytes[12..16].copy_from_slice(&ip_bytes);

                network_addresses.push(NetworkAddress {
                    services: 1, // NODE_NETWORK
                    ip: ipv6_bytes,
                    port: ipv4_addr.port(),
                });
            }
        }

        if network_addresses.is_empty() {
            return Err(DnsSeedError::NoAddresses(format!("No addresses found for {}", seed)));
        }

        Ok(network_addresses)
    }

    /// Resolve DNS seeds with network-specific port
    pub async fn resolve_seeds_with_port(&self, is_testnet: bool) -> Result<Vec<NetworkAddress>, DnsSeedError> {
        let seeds = self.seeds.get_seeds(is_testnet);
        let port = if is_testnet { 18333 } else { 8333 };
        let mut all_addresses = Vec::new();

        for seed in seeds {
            let host = format!("{}:{}", seed, port);

            let result = tokio::time::timeout(self.timeout, lookup_host(&host)).await;

            match result {
                Ok(Ok(addresses)) => {
                    for addr in addresses {
                        if let SocketAddr::V4(ipv4_addr) = addr {
                            let ip_bytes = ipv4_addr.ip().octets();
                            let mut ipv6_bytes = [0u8; 16];
                            // Convert IPv4 to IPv6-mapped IPv4
                            ipv6_bytes[10] = 0xff;
                            ipv6_bytes[11] = 0xff;
                            ipv6_bytes[12..16].copy_from_slice(&ip_bytes);

                            all_addresses.push(NetworkAddress {
                                services: 1, // NODE_NETWORK
                                ip: ipv6_bytes,
                                port: ipv4_addr.port(),
                            });
                        }
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to resolve seed {}: {}", seed, e);
                }
                Err(_) => {
                    tracing::warn!("Timeout resolving seed {}", seed);
                }
            }
        }

        if all_addresses.is_empty() {
            return Err(DnsSeedError::NoAddresses("No addresses found from any seed".to_string()));
        }

        // Remove duplicates and shuffle
        all_addresses.sort_by_key(|addr| addr.ip);
        all_addresses.dedup_by_key(|addr| addr.ip);

        // Shuffle the results
        use rand::seq::SliceRandom;
        use rand::thread_rng;
        all_addresses.shuffle(&mut thread_rng());

        Ok(all_addresses)
    }
}

impl Default for DnsSeedResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_seed_resolver_creation() {
        let resolver = DnsSeedResolver::new();
        assert!(!resolver.seeds.testnet_seeds.is_empty());
        assert!(!resolver.seeds.mainnet_seeds.is_empty());
    }

    #[tokio::test]
    async fn test_dns_seed_resolution() {
        let resolver = DnsSeedResolver::new();

        // Test with a short timeout to avoid hanging in tests
        let resolver = DnsSeedResolver::with_timeout(Duration::from_secs(5));

        // This might fail in CI environments without internet access
        match resolver.resolve_seeds_with_port(true).await {
            Ok(addresses) => {
                assert!(!addresses.is_empty());
                for addr in addresses {
                    assert_eq!(addr.services, 1);
                    assert_eq!(addr.port, 18333);
                }
            }
            Err(e) => {
                // This is expected in some test environments
                println!("DNS resolution failed (expected in some environments): {}", e);
            }
        }
    }

    #[test]
    fn test_dns_seeds_configuration() {
        let seeds = DnsSeeds::new();
        assert!(!seeds.testnet_seeds.is_empty());
        assert!(!seeds.mainnet_seeds.is_empty());

        let testnet_seeds = seeds.get_seeds(true);
        let mainnet_seeds = seeds.get_seeds(false);

        assert_eq!(testnet_seeds.len(), seeds.testnet_seeds.len());
        assert_eq!(mainnet_seeds.len(), seeds.mainnet_seeds.len());
    }
}
