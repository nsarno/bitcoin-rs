// Peer connection pool management
// This module handles peer connections, keepalive, and message routing

use crate::network::message::{Message, NetworkAddress};
use crate::network::handshake::HandshakeManager;
use crate::network::keepalive::{KeepaliveManager, KeepaliveError};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeerManagerError {
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("Handshake error: {0}")]
    Handshake(#[from] crate::network::handshake::HandshakeError),
    #[error("Keepalive error: {0}")]
    Keepalive(#[from] KeepaliveError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Peer connection state
#[derive(Debug, Clone, PartialEq)]
pub enum PeerState {
    /// Initial state - not connected
    Disconnected,
    /// Connected but handshake not complete
    Connecting,
    /// Handshake complete, ready for normal operation
    Connected,
    /// Connection failed
    Failed(String),
}

/// Individual peer connection
#[derive(Debug)]
pub struct Peer {
    pub address: NetworkAddress,
    pub state: PeerState,
    pub handshake_manager: Option<HandshakeManager>,
    pub keepalive_manager: KeepaliveManager,
    pub last_activity: SystemTime,
    pub connection_id: String,
}

impl Peer {
    /// Create a new peer connection
    pub fn new(address: NetworkAddress) -> Self {
        Self {
            address: address.clone(),
            state: PeerState::Disconnected,
            handshake_manager: Some(HandshakeManager::new(address)),
            keepalive_manager: KeepaliveManager::new(),
            last_activity: SystemTime::now(),
            connection_id: format!("peer_{}", rand::random::<u64>()),
        }
    }

    /// Start the handshake process
    pub fn start_handshake(&mut self) -> Result<Message, PeerManagerError> {
        if let Some(ref mut handshake) = self.handshake_manager {
            let version_msg = handshake.start_handshake();
            self.state = PeerState::Connecting;
            self.last_activity = SystemTime::now();
            Ok(version_msg)
        } else {
            Err(PeerManagerError::PeerNotFound("No handshake manager".to_string()))
        }
    }

    /// Process an incoming message
    pub fn process_message(&mut self, message: Message) -> Result<Option<Message>, PeerManagerError> {
        self.last_activity = SystemTime::now();

        // Handle keepalive messages
        match &message {
            Message::Ping(ping) => {
                // Respond with pong
                return Ok(Some(Message::Pong(crate::network::message::PongMessage {
                    nonce: ping.nonce
                })));
            }
            Message::Pong(pong) => {
                // Process pong in keepalive manager
                self.keepalive_manager.process_pong(pong)?;
                return Ok(None);
            }
            _ => {}
        }

        // Handle handshake messages
        if let Some(ref mut handshake) = self.handshake_manager {
            let response = handshake.process_message(message)?;

            if handshake.is_complete() {
                self.state = PeerState::Connected;
                self.handshake_manager = None; // No longer needed
            } else if handshake.is_failed() {
                self.state = PeerState::Failed("Handshake failed".to_string());
            }

            Ok(response)
        } else {
            // Handshake complete, handle other messages
            Ok(None)
        }
    }

    /// Check if peer should send a ping
    pub fn should_send_ping(&self) -> bool {
        self.keepalive_manager.should_send_ping()
    }

    /// Generate a ping message
    pub fn generate_ping(&mut self) -> Message {
        self.keepalive_manager.generate_ping()
    }

    /// Check if peer connection is alive
    pub fn is_alive(&self) -> bool {
        self.keepalive_manager.is_connection_alive() &&
        self.state == PeerState::Connected
    }

    /// Check if peer has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or_default() >= timeout
    }

    /// Get peer statistics
    pub fn get_stats(&self) -> PeerStats {
        let keepalive_stats = self.keepalive_manager.get_stats();
        PeerStats {
            connection_id: self.connection_id.clone(),
            state: self.state.clone(),
            address: self.address.clone(),
            pending_pings: keepalive_stats.pending_pings,
            is_alive: self.is_alive(),
            last_activity: self.last_activity,
        }
    }
}

/// Peer statistics
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub connection_id: String,
    pub state: PeerState,
    pub address: NetworkAddress,
    pub pending_pings: usize,
    pub is_alive: bool,
    pub last_activity: SystemTime,
}

/// Peer manager for handling multiple peer connections
#[derive(Debug)]
pub struct PeerManager {
    peers: HashMap<String, Peer>,
    max_peers: usize,
    connection_timeout: Duration,
    keepalive_interval: Duration,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            max_peers: 8, // Default max peers
            connection_timeout: Duration::from_secs(300), // 5 minutes
            keepalive_interval: Duration::from_secs(30), // 30 seconds
        }
    }

    /// Create a peer manager with custom settings
    pub fn with_settings(max_peers: usize, connection_timeout: Duration, keepalive_interval: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            connection_timeout,
            keepalive_interval,
        }
    }

    /// Add a new peer connection
    pub fn add_peer(&mut self, address: NetworkAddress) -> Result<String, PeerManagerError> {
        if self.peers.len() >= self.max_peers {
            return Err(PeerManagerError::PeerNotFound("Maximum peers reached".to_string()));
        }

        let peer = Peer::new(address);
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
    pub fn get_peer(&self, connection_id: &str) -> Option<&Peer> {
        self.peers.get(connection_id)
    }

    /// Get a mutable peer by connection ID
    pub fn get_peer_mut(&mut self, connection_id: &str) -> Option<&mut Peer> {
        self.peers.get_mut(connection_id)
    }

    /// Start handshake for a peer
    pub fn start_handshake(&mut self, connection_id: &str) -> Result<Message, PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        peer.start_handshake()
    }

    /// Process a message for a specific peer
    pub fn process_message(&mut self, connection_id: &str, message: Message) -> Result<Option<Message>, PeerManagerError> {
        let peer = self.peers.get_mut(connection_id)
            .ok_or_else(|| PeerManagerError::PeerNotFound(connection_id.to_string()))?;
        peer.process_message(message)
    }

    /// Get all peers that should send pings
    pub fn get_peers_needing_ping(&mut self) -> Vec<(String, Message)> {
        let mut pings = Vec::new();

        for (connection_id, peer) in self.peers.iter_mut() {
            if peer.should_send_ping() && peer.state == PeerState::Connected {
                let ping_msg = peer.generate_ping();
                pings.push((connection_id.clone(), ping_msg));
            }
        }

        pings
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

    /// Get all peer statistics
    pub fn get_all_peer_stats(&self) -> Vec<PeerStats> {
        self.peers.values().map(|peer| peer.get_stats()).collect()
    }

    /// Get the number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.peers.values()
            .filter(|peer| peer.state == PeerState::Connected)
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

    fn create_test_network_address() -> NetworkAddress {
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
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
            peer.state = PeerState::Connected;
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
        assert_eq!(stats[0].state, PeerState::Disconnected);
    }
}
