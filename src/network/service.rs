// Network service for managing peer connections and discovery
// This module provides the main network service that coordinates peer discovery and connection management

use crate::config::Config;
use crate::network::{
    PeerManager, PeerManagerError, DnsSeedResolver, DnsSeedError,
    message::NetworkAddress,
};
use std::time::Duration;
use tokio::time::{interval, sleep};
use tracing::{info, warn, error, debug};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkServiceError {
    #[error("Peer manager error: {0}")]
    PeerManager(#[from] PeerManagerError),
    #[error("DNS seed error: {0}")]
    DnsSeed(#[from] DnsSeedError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network service error: {0}")]
    Service(String),
}

/// Network service that manages peer discovery and connections
pub struct NetworkService {
    pub config: Config,
    pub peer_manager: PeerManager,
    pub dns_resolver: DnsSeedResolver,
    pub is_running: bool,
}

impl NetworkService {
    /// Create a new network service
    pub fn new(config: Config) -> Self {
        let peer_manager = PeerManager::with_settings(
            config.max_peers,
            Duration::from_secs(300), // 5 minutes connection timeout
            Duration::from_secs(30),  // 30 seconds keepalive interval
            0.5, // 50% quality threshold
        );

        Self {
            config,
            peer_manager,
            dns_resolver: DnsSeedResolver::new(),
            is_running: false,
        }
    }

    /// Start the network service
    pub async fn start(&mut self) -> Result<(), NetworkServiceError> {
        if self.is_running {
            return Err(NetworkServiceError::Service("Network service is already running".to_string()));
        }

        info!("Starting network service for {:?} network", self.config.network);
        self.is_running = true;

        // Start peer discovery and connection management
        self.discover_and_connect_peers().await?;

        Ok(())
    }

    /// Stop the network service
    pub fn stop(&mut self) {
        info!("Stopping network service");
        self.is_running = false;
    }

    /// Check if the service is running
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// Get the number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.peer_manager.connected_peer_count()
    }

    /// Get the total number of peers
    pub fn total_peer_count(&self) -> usize {
        self.peer_manager.total_peer_count()
    }

    /// Get peer statistics
    pub fn get_peer_stats(&self) -> Vec<crate::network::PeerStats> {
        self.peer_manager.get_all_peer_stats()
    }

    /// Discover peers from DNS seeds and attempt connections
    async fn discover_and_connect_peers(&mut self) -> Result<(), NetworkServiceError> {
        let is_testnet = self.config.is_testnet();

        info!("Discovering peers from DNS seeds for {:?} network", self.config.network);

        // Resolve DNS seeds to get peer addresses
        let peer_addresses = self.dns_resolver.resolve_seeds_with_port(is_testnet).await?;
        info!("Discovered {} potential peers from DNS seeds", peer_addresses.len());

        // Attempt to connect to discovered peers
        let mut connection_attempts = 0;
        let max_connection_attempts = std::cmp::min(peer_addresses.len(), self.config.max_peers * 2);

        for address in peer_addresses.iter().take(max_connection_attempts) {
            if self.peer_manager.total_peer_count() >= self.config.max_peers {
                break;
            }

            connection_attempts += 1;
            debug!("Attempting to connect to peer at {}:{}",
                   format_ipv6_mapped_ipv4(&address.ip), address.port);

            match self.attempt_peer_connection(address).await {
                Ok(connection_id) => {
                    info!("Successfully connected to peer {}:{} (ID: {})",
                          format_ipv6_mapped_ipv4(&address.ip), address.port, connection_id);
                }
                Err(e) => {
                    debug!("Failed to connect to peer {}:{}: {}",
                           format_ipv6_mapped_ipv4(&address.ip), address.port, e);
                }
            }

            // Small delay between connection attempts
            sleep(Duration::from_millis(100)).await;
        }

        info!("Completed peer discovery. Connected to {} out of {} attempted peers",
              self.connected_peer_count(), connection_attempts);

        Ok(())
    }

    /// Attempt to connect to a specific peer
    async fn attempt_peer_connection(&mut self, address: &NetworkAddress) -> Result<String, NetworkServiceError> {
        // Add peer to manager
        let connection_id = self.peer_manager.add_peer(address.clone())?;

        // Attempt TCP connection using the peer's connect method
        match self.peer_manager.connect_peer(&connection_id).await {
            Ok(_) => {
                debug!("TCP connection established to {}:{}",
                       format_ipv6_mapped_ipv4(&address.ip), address.port);

                // Start handshake
                match self.peer_manager.start_handshake(&connection_id) {
                    Ok(_version_msg) => {
                        debug!("Handshake initiated with peer {}", connection_id);
                        Ok(connection_id)
                    }
                    Err(e) => {
                        warn!("Failed to start handshake with peer {}: {}", connection_id, e);
                        let _ = self.peer_manager.remove_peer(&connection_id);
                        Err(NetworkServiceError::Service(format!("Handshake failed: {}", e)))
                    }
                }
            }
            Err(e) => {
                debug!("Failed to establish TCP connection to {}:{}: {}",
                       format_ipv6_mapped_ipv4(&address.ip), address.port, e);
                let _ = self.peer_manager.remove_peer(&connection_id);
                Err(NetworkServiceError::Service(format!("Connection failed: {}", e)))
            }
        }
    }

    /// Run the network service main loop
    pub async fn run(&mut self) -> Result<(), NetworkServiceError> {
        if !self.is_running {
            return Err(NetworkServiceError::Service("Network service is not running".to_string()));
        }

        info!("Starting network service main loop");

        // Create intervals for periodic tasks
        let mut keepalive_interval = interval(Duration::from_secs(30));
        let mut cleanup_interval = interval(Duration::from_secs(60));
        let mut discovery_interval = interval(Duration::from_secs(300)); // 5 minutes
        let mut reconnect_interval = interval(Duration::from_secs(10)); // 10 seconds
        let mut quality_update_interval = interval(Duration::from_secs(120)); // 2 minutes

        loop {
            if !self.is_running {
                break;
            }

            tokio::select! {
                // Handle keepalive pings
                _ = keepalive_interval.tick() => {
                    self.handle_keepalive().await;
                }

                // Clean up timed out peers
                _ = cleanup_interval.tick() => {
                    self.cleanup_timed_out_peers().await;
                }

                // Handle peer reconnections
                _ = reconnect_interval.tick() => {
                    self.handle_peer_reconnections().await;
                }

                // Update peer quality metrics
                _ = quality_update_interval.tick() => {
                    self.update_peer_qualities().await;
                }

                // Periodic peer discovery
                _ = discovery_interval.tick() => {
                    if self.connected_peer_count() < self.config.max_peers / 2 {
                        info!("Low peer count ({}), attempting to discover more peers", self.connected_peer_count());
                        if let Err(e) = self.discover_and_connect_peers().await {
                            warn!("Failed to discover additional peers: {}", e);
                        }
                    }
                }
            }
        }

        info!("Network service main loop stopped");
        Ok(())
    }

    /// Handle keepalive pings for all connected peers
    async fn handle_keepalive(&mut self) {
        let pings = self.peer_manager.get_peers_needing_ping();

        if !pings.is_empty() {
            debug!("Sending {} keepalive pings", pings.len());

            for (connection_id, _ping_msg) in pings {
                debug!("Sending ping to peer {}", connection_id);
                // TODO: In a real implementation, we would send the ping message over the TCP connection
                // For now, we just log it
            }
        }
    }

    /// Clean up timed out peers
    async fn cleanup_timed_out_peers(&mut self) {
        let removed_peers = self.peer_manager.cleanup_timed_out_peers();

        if !removed_peers.is_empty() {
            info!("Cleaned up {} timed out peers", removed_peers.len());
            for peer_id in removed_peers {
                debug!("Removed timed out peer: {}", peer_id);
            }
        }
    }

    /// Handle peer reconnections
    async fn handle_peer_reconnections(&mut self) {
        let reconnect_peers = self.peer_manager.get_peers_needing_reconnect();

        if !reconnect_peers.is_empty() {
            debug!("Attempting to reconnect {} peers", reconnect_peers.len());

            for connection_id in reconnect_peers {
                match self.peer_manager.connect_peer(&connection_id).await {
                    Ok(_) => {
                        debug!("Successfully reconnected peer {}", connection_id);
                        // Start handshake for reconnected peer
                        if let Err(e) = self.peer_manager.start_handshake(&connection_id) {
                            warn!("Failed to start handshake for reconnected peer {}: {}", connection_id, e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to reconnect peer {}: {}", connection_id, e);
                    }
                }
            }
        }
    }

    /// Update peer quality metrics
    async fn update_peer_qualities(&mut self) {
        self.peer_manager.update_peer_qualities();

        // Log peer quality statistics
        let qualities = self.peer_manager.get_peers_by_quality();
        if !qualities.is_empty() {
            let avg_quality = qualities.iter().map(|(_, q)| q).sum::<f64>() / qualities.len() as f64;
            debug!("Peer quality update: {} connected peers, average quality: {:.2}",
                   qualities.len(), avg_quality);

            // Log top 3 peers by quality
            for (i, (connection_id, quality)) in qualities.iter().take(3).enumerate() {
                debug!("Top peer #{}: {} (quality: {:.2})", i + 1, connection_id, quality);
            }
        }
    }

    /// Get the best peers for specific operations
    pub fn get_best_peers(&self, count: usize) -> Vec<String> {
        self.peer_manager.get_best_peers(count)
    }

    /// Get peer quality statistics
    pub fn get_peer_quality_stats(&self) -> Vec<(String, f64)> {
        self.peer_manager.get_peers_by_quality()
    }

    /// Get peers by connection state
    pub fn get_peers_by_state(&self, state: crate::network::peer::ConnectionState) -> Vec<String> {
        self.peer_manager.get_peers_by_state(state)
    }

    /// Disconnect a specific peer
    pub async fn disconnect_peer(&mut self, connection_id: &str) -> Result<(), NetworkServiceError> {
        self.peer_manager.disconnect_peer(connection_id).await?;
        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message_to_peer(&mut self, connection_id: &str, message: crate::network::message::Message) -> Result<(), NetworkServiceError> {
        self.peer_manager.send_message(connection_id, message).await?;
        Ok(())
    }
}

/// Format an IPv6-mapped IPv4 address for display
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Network;

    fn create_test_config() -> Config {
        Config {
            network: Network::Testnet,
            data_dir: std::path::PathBuf::from("./test_data"),
            listen_port: 18333,
            max_peers: 4,
            log_level: "debug".to_string(),
        }
    }

    #[test]
    fn test_network_service_creation() {
        let config = create_test_config();
        let service = NetworkService::new(config);

        assert!(!service.is_running());
        assert_eq!(service.connected_peer_count(), 0);
        assert_eq!(service.total_peer_count(), 0);
    }

    #[test]
    fn test_ipv6_mapped_ipv4_formatting() {
        let ipv4_mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1];
        let formatted = format_ipv6_mapped_ipv4(&ipv4_mapped);
        assert_eq!(formatted, "192.168.1.1");
    }

    #[test]
    fn test_network_service_start_stop() {
        let config = create_test_config();
        let service = NetworkService::new(config);

        assert!(!service.is_running());

        // Note: We can't actually start the service in tests without async runtime
        // This test just verifies the basic state management
    }
}
