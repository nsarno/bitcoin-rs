// Individual peer connection management
// This module handles the lifecycle and state of individual peer connections

use crate::network::message::{Message, NetworkAddress};
use crate::network::handshake::HandshakeManager;
use crate::network::keepalive::{KeepaliveManager, KeepaliveError};
use std::time::{SystemTime, Duration};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeerError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Handshake error: {0}")]
    Handshake(#[from] crate::network::handshake::HandshakeError),
    #[error("Keepalive error: {0}")]
    Keepalive(#[from] KeepaliveError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Peer not connected")]
    NotConnected,
    #[error("Peer already connected")]
    AlreadyConnected,
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
}

/// Connection quality metrics for a peer
#[derive(Debug, Clone)]
pub struct ConnectionQuality {
    pub latency_ms: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub connection_duration: Duration,
    pub last_ping_time: Option<SystemTime>,
    pub last_pong_time: Option<SystemTime>,
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            latency_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            connection_duration: Duration::ZERO,
            last_ping_time: None,
            last_pong_time: None,
        }
    }
}

/// Peer connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Initial state - not connected
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Connected but handshake not complete
    Handshaking,
    /// Handshake complete, ready for normal operation
    Connected,
    /// Connection failed
    Failed(String),
    /// Connection closed
    Closed,
}

/// Individual peer connection with full lifecycle management
#[derive(Debug)]
pub struct PeerConnection {
    pub address: NetworkAddress,
    pub state: ConnectionState,
    pub connection_id: String,
    pub tcp_stream: Option<TcpStream>,
    pub handshake_manager: Option<HandshakeManager>,
    pub keepalive_manager: KeepaliveManager,
    pub quality: ConnectionQuality,
    pub last_activity: SystemTime,
    pub connection_start: SystemTime,
    pub reconnect_attempts: u32,
    pub max_reconnect_attempts: u32,
    pub reconnect_delay: Duration,
}

impl PeerConnection {
    /// Create a new peer connection
    pub fn new(address: NetworkAddress) -> Self {
        let now = SystemTime::now();
        Self {
            address: address.clone(),
            state: ConnectionState::Disconnected,
            connection_id: format!("peer_{}", rand::random::<u64>()),
            tcp_stream: None,
            handshake_manager: Some(HandshakeManager::new(address)),
            keepalive_manager: KeepaliveManager::new(),
            quality: ConnectionQuality::default(),
            last_activity: now,
            connection_start: now,
            reconnect_attempts: 0,
            max_reconnect_attempts: 3,
            reconnect_delay: Duration::from_secs(5),
        }
    }

    /// Create a peer connection with custom settings
    pub fn with_settings(
        address: NetworkAddress,
        max_reconnect_attempts: u32,
        reconnect_delay: Duration,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            address: address.clone(),
            state: ConnectionState::Disconnected,
            connection_id: format!("peer_{}", rand::random::<u64>()),
            tcp_stream: None,
            handshake_manager: Some(HandshakeManager::new(address)),
            keepalive_manager: KeepaliveManager::new(),
            quality: ConnectionQuality::default(),
            last_activity: now,
            connection_start: now,
            reconnect_attempts: 0,
            max_reconnect_attempts,
            reconnect_delay,
        }
    }

    /// Attempt to connect to the peer
    pub async fn connect(&mut self) -> Result<(), PeerError> {
        if self.state == ConnectionState::Connected {
            return Err(PeerError::AlreadyConnected);
        }

        if self.reconnect_attempts >= self.max_reconnect_attempts {
            return Err(PeerError::Connection("Max reconnect attempts reached".to_string()));
        }

        self.state = ConnectionState::Connecting;
        self.reconnect_attempts += 1;

        let socket_addr = self.format_socket_addr();

        match TcpStream::connect(&socket_addr).await {
            Ok(stream) => {
                self.tcp_stream = Some(stream);
                self.state = ConnectionState::Handshaking;
                self.connection_start = SystemTime::now();
                self.last_activity = SystemTime::now();
                self.quality.connection_duration = Duration::ZERO;
                Ok(())
            }
            Err(e) => {
                self.state = ConnectionState::Failed(format!("Connection failed: {}", e));
                Err(PeerError::Connection(format!("Failed to connect to {}: {}", socket_addr, e)))
            }
        }
    }

    /// Start the handshake process
    pub fn start_handshake(&mut self) -> Result<Message, PeerError> {
        if self.state != ConnectionState::Handshaking {
            return Err(PeerError::NotConnected);
        }

        if let Some(ref mut handshake) = self.handshake_manager {
            let version_msg = handshake.start_handshake();
            self.last_activity = SystemTime::now();
            Ok(version_msg)
        } else {
            Err(PeerError::Connection("No handshake manager available".to_string()))
        }
    }

    /// Process an incoming message
    pub fn process_message(&mut self, message: Message) -> Result<Option<Message>, PeerError> {
        self.last_activity = SystemTime::now();
        self.quality.messages_received += 1;

        // Handle keepalive messages
        match &message {
            Message::Ping(ping) => {
                self.quality.last_ping_time = Some(SystemTime::now());
                return Ok(Some(Message::Pong(crate::network::message::PongMessage {
                    nonce: ping.nonce
                })));
            }
            Message::Pong(pong) => {
                self.quality.last_pong_time = Some(SystemTime::now());
                self.keepalive_manager.process_pong(pong)?;

                // Calculate latency if we have ping time
                if let Some(ping_time) = self.quality.last_ping_time {
                    if let Ok(duration) = self.quality.last_pong_time.unwrap().duration_since(ping_time) {
                        self.quality.latency_ms = Some(duration.as_millis() as u64);
                    }
                }

                return Ok(None);
            }
            _ => {}
        }

        // Handle handshake messages
        if let Some(ref mut handshake) = self.handshake_manager {
            let response = handshake.process_message(message)?;

            if handshake.is_complete() {
                self.state = ConnectionState::Connected;
                self.handshake_manager = None; // No longer needed
                self.reconnect_attempts = 0; // Reset on successful connection
            } else if handshake.is_failed() {
                self.state = ConnectionState::Failed("Handshake failed".to_string());
            }

            Ok(response)
        } else {
            // Handshake complete, handle other messages

            // Transaction-related messages (inv, getdata, tx) are handled by relay service
            // They pass through here and will be processed by the relay service
            match &message {
                Message::Inv(_) | Message::GetData(_) | Message::Tx(_) => {
                    // Transaction messages require relay service processing
                    // Return None to indicate this message needs further handling
                    Ok(None)
                }
                _ => {
                    // Other messages (like headers, block) may be handled elsewhere
                    Ok(None)
                }
            }
        }
    }

    /// Send a message to the peer
    pub async fn send_message(&mut self, _message: Message) -> Result<(), PeerError> {
        if self.state != ConnectionState::Connected {
            return Err(PeerError::NotConnected);
        }

        if let Some(ref mut _stream) = self.tcp_stream {
            // TODO: Implement proper message serialization and sending
            // For now, we just update the quality metrics
            self.quality.messages_sent += 1;
            self.last_activity = SystemTime::now();
            Ok(())
        } else {
            Err(PeerError::NotConnected)
        }
    }

    /// Check if peer should send a ping
    pub fn should_send_ping(&self) -> bool {
        self.keepalive_manager.should_send_ping() && self.state == ConnectionState::Connected
    }

    /// Generate a ping message
    pub fn generate_ping(&mut self) -> Message {
        self.quality.last_ping_time = Some(SystemTime::now());
        self.keepalive_manager.generate_ping()
    }

    /// Check if peer connection is alive
    pub fn is_alive(&self) -> bool {
        self.keepalive_manager.is_connection_alive() &&
        self.state == ConnectionState::Connected
    }

    /// Check if peer has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or_default() >= timeout
    }

    /// Check if peer should be reconnected
    pub fn should_reconnect(&self) -> bool {
        (matches!(self.state, ConnectionState::Failed(_)) || self.state == ConnectionState::Closed) &&
        self.reconnect_attempts < self.max_reconnect_attempts
    }

    /// Get the time until next reconnect attempt
    pub fn time_until_reconnect(&self) -> Option<Duration> {
        if !self.should_reconnect() {
            return None;
        }

        let elapsed = SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or_default();

        if elapsed >= self.reconnect_delay {
            Some(Duration::ZERO)
        } else {
            Some(self.reconnect_delay - elapsed)
        }
    }

    /// Disconnect the peer
    pub async fn disconnect(&mut self) -> Result<(), PeerError> {
        if let Some(mut stream) = self.tcp_stream.take() {
            let _ = stream.shutdown().await;
        }

        self.state = ConnectionState::Closed;
        self.tcp_stream = None;
        self.last_activity = SystemTime::now();
        Ok(())
    }

    /// Check if this is a transaction-related message that needs relay service handling
    pub fn is_transaction_message(&self, message: &Message) -> bool {
        matches!(message, Message::Inv(_) | Message::GetData(_) | Message::Tx(_))
    }

    /// Update connection quality metrics
    pub fn update_quality(&mut self) {
        self.quality.connection_duration = SystemTime::now()
            .duration_since(self.connection_start)
            .unwrap_or_default();
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
            quality: self.quality.clone(),
            reconnect_attempts: self.reconnect_attempts,
        }
    }

    /// Format the socket address for connection
    fn format_socket_addr(&self) -> String {
        format!("{}:{}", self.format_ipv6_mapped_ipv4(&self.address.ip), self.address.port)
    }

    /// Format an IPv6-mapped IPv4 address for display
    fn format_ipv6_mapped_ipv4(&self, ip: &[u8; 16]) -> String {
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
}

/// Enhanced peer statistics
#[derive(Debug, Clone)]
pub struct PeerStats {
    pub connection_id: String,
    pub state: ConnectionState,
    pub address: NetworkAddress,
    pub pending_pings: usize,
    pub is_alive: bool,
    pub last_activity: SystemTime,
    pub quality: ConnectionQuality,
    pub reconnect_attempts: u32,
}

impl Default for PeerConnection {
    fn default() -> Self {
        Self::new(NetworkAddress {
            services: 0,
            ip: [0; 16],
            port: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::NetworkAddress;

    fn create_test_network_address() -> NetworkAddress {
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
            port: 8333,
        }
    }

    #[test]
    fn test_peer_connection_creation() {
        let address = create_test_network_address();
        let peer = PeerConnection::new(address.clone());

        assert_eq!(peer.address, address);
        assert_eq!(peer.state, ConnectionState::Disconnected);
        assert_eq!(peer.reconnect_attempts, 0);
        assert_eq!(peer.max_reconnect_attempts, 3);
    }

    #[test]
    fn test_peer_connection_with_settings() {
        let address = create_test_network_address();
        let peer = PeerConnection::with_settings(
            address.clone(),
            5,
            Duration::from_secs(10),
        );

        assert_eq!(peer.address, address);
        assert_eq!(peer.max_reconnect_attempts, 5);
        assert_eq!(peer.reconnect_delay, Duration::from_secs(10));
    }

    #[test]
    fn test_peer_should_reconnect() {
        let address = create_test_network_address();
        let mut peer = PeerConnection::new(address);

        // Initially should not reconnect
        assert!(!peer.should_reconnect());

        // Set to failed state
        peer.state = ConnectionState::Failed("Test failure".to_string());
        assert!(peer.should_reconnect());

        // Set max attempts reached
        peer.reconnect_attempts = peer.max_reconnect_attempts;
        assert!(!peer.should_reconnect());
    }

    #[test]
    fn test_peer_stats() {
        let address = create_test_network_address();
        let peer = PeerConnection::new(address);
        let stats = peer.get_stats();

        assert_eq!(stats.connection_id, peer.connection_id);
        assert_eq!(stats.state, ConnectionState::Disconnected);
        assert_eq!(stats.reconnect_attempts, 0);
    }

    #[test]
    fn test_connection_quality_default() {
        let quality = ConnectionQuality::default();
        assert_eq!(quality.latency_ms, None);
        assert_eq!(quality.bytes_sent, 0);
        assert_eq!(quality.bytes_received, 0);
        assert_eq!(quality.messages_sent, 0);
        assert_eq!(quality.messages_received, 0);
    }
}
