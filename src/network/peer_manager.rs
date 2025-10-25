// Peer connection pool management
// This module handles peer connections, keepalive, and message routing

use crate::network::message::{Message, NetworkAddress};
use crate::network::peer::{PeerConnection, PeerError, ConnectionState};
use crate::network::keepalive::KeepaliveError;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeerManagerError {
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Peer error: {0}")]
    Peer(#[from] PeerError),
    #[error("Handshake error: {0}")]
    Handshake(#[from] crate::network::handshake::HandshakeError),
    #[error("Keepalive error: {0}")]
    Keepalive(#[from] KeepaliveError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Maximum peers reached")]
    MaxPeersReached,
    #[error("Peer already exists: {0}")]
    PeerAlreadyExists(String),
}

/// Enhanced peer manager with individual peer connection management
#[derive(Debug)]
pub struct PeerManager {
    peers: HashMap<String, PeerConnection>,
    max_peers: usize,
    connection_timeout: Duration,
    keepalive_interval: Duration,
    peer_quality_threshold: f64,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            max_peers: 8, // Default max peers
            connection_timeout: Duration::from_secs(300), // 5 minutes
            keepalive_interval: Duration::from_secs(30), // 30 seconds
            peer_quality_threshold: 0.5, // 50% quality threshold
        }
    }

    /// Create a peer manager with custom settings
    pub fn with_settings(
        max_peers: usize,
        connection_timeout: Duration,
        keepalive_interval: Duration,
        peer_quality_threshold: f64,
    ) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            connection_timeout,
            keepalive_interval,
            peer_quality_threshold,
        }
    }

    /// Add a new peer connection
    pub fn add_peer(&mut self, address: NetworkAddress) -> Result<String, PeerManagerError> {
        if self.peers.len() >= self.max_peers {
            return Err(PeerManagerError::MaxPeersReached);
        }

        // Check if peer already exists
        for (id, peer) in &self.peers {
            if peer.address == address {
                return Err(PeerManagerError::PeerAlreadyExists(id.clone()));
            }
        }

        let peer = PeerConnection::new(address);
        let connection_id = peer.connection_id.clone();
        self.peers.insert(connection_id.clone(), peer);
        Ok(connection_id)
    }

    /// Add a peer connection with custom settings
    pub fn add_peer_with_settings(
        &mut self,
        address: NetworkAddress,
        max_reconnect_attempts: u32,
        reconnect_delay: Duration,
    ) -> Result<String, PeerManagerError> {
        if self.peers.len() >= self.max_peers {
            return Err(PeerManagerError::MaxPeersReached);
        }

        // Check if peer already exists
        for (id, peer) in &self.peers {
            if peer.address == address {
                return Err(PeerManagerError::PeerAlreadyExists(id.clone()));
            }
        }

        let peer = PeerConnection::with_settings(address, max_reconnect_attempts, reconnect_delay);
        let connection_id = peer.connection_id.clone();
        self.peers.insert(connection_id.clone(), peer);
        Ok(connection_id)
    }

    /// Remove a peer connection
    pub fn remove_peer(&mut self, connection_id: &str) -> Result<(), PeerManagerError> {
        self.peers.remove(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        Ok(())
    }

    /// Get a peer by connection ID
    pub fn get_peer(&self, connection_id: &str) -> Option<&PeerConnection> {
        self.peers.get(connection_id)
    }

    /// Get a mutable peer by connection ID
    pub fn get_peer_mut(&mut self, connection_id: &str) -> Option<&mut PeerConnection> {
        self.peers.get_mut(connection_id)
    }

    /// Connect to a peer
    pub async fn connect_peer(&mut self, connection_id: &str) -> Result<(), PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        peer.connect().await?;
        Ok(())
    }

    /// Start handshake for a peer
    pub fn start_handshake(&mut self, connection_id: &str) -> Result<Message, PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        Ok(peer.start_handshake()?)
    }

    /// Process a message for a specific peer
    pub fn process_message(&mut self, connection_id: &str, message: Message) -> Result<Option<Message>, PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        Ok(peer.process_message(message)?)
    }

    /// Send a message to a peer
    pub async fn send_message(&mut self, connection_id: &str, message: Message) -> Result<(), PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        peer.send_message(message).await?;
        Ok(())
    }

    /// Get all peers that should send pings
    pub fn get_peers_needing_ping(&mut self) -> Vec<(String, Message)> {
        let mut pings = Vec::new();

        for (connection_id, peer) in self.peers.iter_mut() {
            if peer.should_send_ping() {
                let ping_msg = peer.generate_ping();
                pings.push((connection_id.clone(), ping_msg));
            }
        }

        pings
    }

    /// Get peers that need reconnection
    pub fn get_peers_needing_reconnect(&self) -> Vec<String> {
        let mut reconnect_peers = Vec::new();

        for (connection_id, peer) in &self.peers {
            if peer.should_reconnect() {
                if let Some(time_until) = peer.time_until_reconnect() {
                    if time_until == Duration::ZERO {
                        reconnect_peers.push(connection_id.clone());
                    }
                }
            }
        }

        reconnect_peers
    }

    /// Clean up timed out peers
    pub fn cleanup_timed_out_peers(&mut self) -> Vec<String> {
        let mut removed_peers = Vec::new();

        self.peers.retain(|connection_id, peer| {
            let is_timed_out = peer.is_timed_out(self.connection_timeout) ||
                              !peer.is_alive();

            if is_timed_out {
                removed_peers.push(connection_id.clone());
                false
            } else {
                true
            }
        });

        removed_peers
    }

    /// Get peers sorted by quality
    pub fn get_peers_by_quality(&self) -> Vec<(String, f64)> {
        let mut peer_qualities: Vec<(String, f64)> = self.peers
            .iter()
            .filter(|(_, peer)| peer.state == ConnectionState::Connected)
            .map(|(id, peer)| {
                let quality = self.calculate_peer_quality(peer);
                (id.clone(), quality)
            })
            .collect();

        // Sort by quality (highest first)
        peer_qualities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        peer_qualities
    }

    /// Calculate peer quality score
    fn calculate_peer_quality(&self, peer: &PeerConnection) -> f64 {
        let mut score = 0.0;

        // Connection duration (longer is better)
        let duration_score = (peer.quality.connection_duration.as_secs() as f64) / 3600.0; // Normalize to hours
        score += duration_score.min(1.0) * 0.3;

        // Latency (lower is better)
        if let Some(latency) = peer.quality.latency_ms {
            let latency_score = (1000.0 - latency as f64) / 1000.0; // Normalize to 0-1
            score += latency_score.max(0.0) * 0.2;
        }

        // Message activity (more is better)
        let message_score = (peer.quality.messages_sent + peer.quality.messages_received) as f64 / 100.0;
        score += message_score.min(1.0) * 0.2;

        // Keepalive health
        if peer.is_alive() {
            score += 0.3;
        }

        score
    }

    /// Get the best peers for specific operations
    pub fn get_best_peers(&self, count: usize) -> Vec<String> {
        let peer_qualities = self.get_peers_by_quality();
        peer_qualities
            .into_iter()
            .take(count)
            .map(|(id, _)| id)
            .collect()
    }

    /// Get all peer statistics
    pub fn get_all_peer_stats(&self) -> Vec<crate::network::peer::PeerStats> {
        self.peers.values().map(|peer| peer.get_stats()).collect()
    }

    /// Get the number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.peers.values()
            .filter(|peer| peer.state == ConnectionState::Connected)
            .count()
    }

    /// Get the total number of peers
    pub fn total_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get all connection IDs
    pub fn get_connection_ids(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Get peers by state
    pub fn get_peers_by_state(&self, state: ConnectionState) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.state == state)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Update peer quality metrics
    pub fn update_peer_qualities(&mut self) {
        for peer in self.peers.values_mut() {
            peer.update_quality();
        }
    }

    /// Disconnect a peer
    pub async fn disconnect_peer(&mut self, connection_id: &str) -> Result<(), PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        peer.disconnect().await?;
        Ok(())
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::NetworkAddress;
    use crate::network::peer::ConnectionState;

    fn create_test_network_address() -> NetworkAddress {
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            port: 8333,
        }
    }

    #[test]
    fn test_peer_manager_creation() {
        let manager = PeerManager::new();
        assert_eq!(manager.total_peer_count(), 0);
        assert_eq!(manager.connected_peer_count(), 0);
    }

    #[test]
    fn test_add_peer() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");
        assert_eq!(manager.total_peer_count(), 1);
        assert!(manager.get_peer(&connection_id).is_some());
    }

    #[test]
    fn test_add_peer_with_settings() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer_with_settings(
            address,
            5,
            Duration::from_secs(10)
        ).expect("Failed to add peer with settings");

        assert_eq!(manager.total_peer_count(), 1);
        let peer = manager.get_peer(&connection_id).unwrap();
        assert_eq!(peer.max_reconnect_attempts, 5);
        assert_eq!(peer.reconnect_delay, Duration::from_secs(10));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");
        assert_eq!(manager.total_peer_count(), 1);

        manager.remove_peer(&connection_id).expect("Failed to remove peer");
        assert_eq!(manager.total_peer_count(), 0);
    }

    #[test]
    fn test_peer_handshake() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");

        // Manually set peer to handshaking state for testing
        if let Some(peer) = manager.get_peer_mut(&connection_id) {
            peer.state = ConnectionState::Handshaking;
        }

        let version_msg = manager.start_handshake(&connection_id).expect("Failed to start handshake");

        // Should be a version message
        if let Message::Version(_) = version_msg {
            // Good
        } else {
            panic!("Expected version message");
        }
    }

    #[test]
    fn test_peer_ping_pong() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");

        // Manually set peer to connected state for testing
        if let Some(peer) = manager.get_peer_mut(&connection_id) {
            peer.state = ConnectionState::Connected;
        }

        // Generate a ping
        let pings = manager.get_peers_needing_ping();
        assert!(!pings.is_empty());

        let (_, ping_msg) = &pings[0];
        if let Message::Ping(ping) = ping_msg {
            // Create a pong with the same nonce
            let pong_msg = Message::Pong(crate::network::message::PongMessage {
                nonce: ping.nonce
            });

            // Process the pong
            let response = manager.process_message(&connection_id, pong_msg)
                .expect("Failed to process pong");
            assert!(response.is_none()); // Pong should not generate a response
        } else {
            panic!("Expected ping message");
        }
    }

    #[test]
    fn test_peer_stats() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");
        let stats = manager.get_all_peer_stats();

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].connection_id, connection_id);
        assert_eq!(stats[0].state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_peer_quality_calculation() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let _connection_id = manager.add_peer(address).expect("Failed to add peer");

        // Get peer qualities
        let qualities = manager.get_peers_by_quality();
        assert_eq!(qualities.len(), 0); // No connected peers yet

        // Get best peers
        let best_peers = manager.get_best_peers(1);
        assert!(best_peers.is_empty()); // No connected peers yet
    }

    #[test]
    fn test_peer_states() {
        let mut manager = PeerManager::new();
        let address = create_test_network_address();

        let connection_id = manager.add_peer(address).expect("Failed to add peer");

        // Get peers by state
        let disconnected_peers = manager.get_peers_by_state(ConnectionState::Disconnected);
        assert_eq!(disconnected_peers.len(), 1);
        assert_eq!(disconnected_peers[0], connection_id);

        let connected_peers = manager.get_peers_by_state(ConnectionState::Connected);
        assert_eq!(connected_peers.len(), 0);
    }

    #[test]
    fn test_max_peers_limit() {
        let mut manager = PeerManager::with_settings(2, Duration::from_secs(300), Duration::from_secs(30), 0.5);

        let address1 = create_test_network_address();
        let address2 = NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 2],
            port: 8333,
        };

        // Add two peers (should succeed)
        let _id1 = manager.add_peer(address1).expect("Failed to add first peer");
        let _id2 = manager.add_peer(address2).expect("Failed to add second peer");
        assert_eq!(manager.total_peer_count(), 2);

        // Try to add a third peer (should fail)
        let address3 = NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 3],
            port: 8333,
        };

        let result = manager.add_peer(address3);
        assert!(result.is_err());
        if let Err(PeerManagerError::MaxPeersReached) = result {
            // Expected error
        } else {
            panic!("Expected MaxPeersReached error");
        }
    }
}
