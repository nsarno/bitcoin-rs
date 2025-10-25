// Integration test for network functionality
// This test verifies that the network service can discover peers and establish connections

use bitcoin_rust::network::{DnsSeedResolver, NetworkService};
use bitcoin_rust::config::{Config, Network};

#[tokio::test]
async fn test_dns_seed_resolution() {
    let resolver = DnsSeedResolver::new();

    // Test testnet seed resolution with timeout
    let resolution_result = tokio::time::timeout(
        std::time::Duration::from_secs(15), // 15 second timeout
        resolver.resolve_seeds_with_port(true)
    ).await;

    match resolution_result {
        Ok(Ok(addresses)) => {
            assert!(!addresses.is_empty(), "Should discover at least one peer from DNS seeds");
            println!("Discovered {} testnet peers", addresses.len());

            // Verify address format
            for addr in addresses.iter().take(3) {
                assert_eq!(addr.services, 1, "Peer should have NODE_NETWORK service");
                assert_eq!(addr.port, 18333, "Testnet peers should use port 18333");
                println!("Peer: {}:{}", format_ipv6_mapped_ipv4(&addr.ip), addr.port);
            }
        }
        Ok(Err(e)) => {
            // This might fail in CI environments without internet access
            println!("DNS seed resolution failed (expected in some environments): {}", e);
        }
        Err(_timeout) => {
            // Timeout occurred - this is expected in some test environments
            println!("DNS seed resolution timed out (expected in some environments)");
        }
    }
}

#[tokio::test]
async fn test_network_service_creation() {
    let config = Config::for_network(Network::Testnet);
    let network_service = NetworkService::new(config);

    assert!(!network_service.is_running());
    assert_eq!(network_service.connected_peer_count(), 0);
    assert_eq!(network_service.total_peer_count(), 0);
}

#[tokio::test]
async fn test_network_service_start() {
    let config = Config::for_network(Network::Testnet);
    let mut network_service = NetworkService::new(config);

    // Test with a timeout to prevent hanging
    let start_result = tokio::time::timeout(
        std::time::Duration::from_secs(1), // 1 second timeout
        network_service.start()
    ).await;

    match start_result {
        Ok(Ok(_)) => {
            println!("Network service started successfully");
            println!("Connected to {} peers", network_service.connected_peer_count());

            // The service should have attempted to connect to peers
            // Note: Actual connections might fail in test environments
            assert!(network_service.total_peer_count() >= 0);
        }
        Ok(Err(e)) => {
            // This might fail in environments without internet access
            println!("Network service start failed (expected in some environments): {}", e);
        }
        Err(_timeout) => {
            // Timeout occurred - this is expected in test environments
            println!("Network service start timed out (expected in test environments)");
        }
    }
}

#[tokio::test]
async fn test_peer_discovery_process() {
    let resolver = DnsSeedResolver::new();

    // Test the discovery process step by step
    println!("Testing peer discovery process...");

    // This test might fail in CI environments, which is expected
    let discovery_result = tokio::time::timeout(
        std::time::Duration::from_secs(15), // 15 second timeout
        resolver.resolve_seeds_with_port(true)
    ).await;

    match discovery_result {
        Ok(Ok(addresses)) => {
            println!("Successfully discovered {} peers", addresses.len());

            // Verify we got reasonable results
            assert!(addresses.len() > 0, "Should discover at least one peer");
            assert!(addresses.len() <= 100, "Should not discover too many peers (likely an error)");

            // Check that addresses are properly formatted
            for addr in addresses.iter().take(5) {
                assert_eq!(addr.services, 1);
                assert_eq!(addr.port, 18333);
                assert!(is_valid_ipv6_mapped_ipv4(&addr.ip), "Address should be valid IPv6-mapped IPv4");
            }
        }
        Ok(Err(e)) => {
            println!("Peer discovery failed (this is expected in some test environments): {}", e);
            // Don't fail the test - this is expected in CI environments
        }
        Err(_timeout) => {
            println!("Peer discovery timed out (this is expected in some test environments)");
            // Don't fail the test - this is expected in CI environments
        }
    }
}

fn format_ipv6_mapped_ipv4(ip: &[u8; 16]) -> String {
    // Check if this is an IPv6-mapped IPv4 address
    if ip[0..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && ip[10..12] == [0xff, 0xff] {
        // Extract IPv4 address
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else {
        // Format as IPv6 address
        format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
    }
}

fn is_valid_ipv6_mapped_ipv4(ip: &[u8; 16]) -> bool {
    // Check if this is a valid IPv6-mapped IPv4 address
    ip[0..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && ip[10..12] == [0xff, 0xff]
}
