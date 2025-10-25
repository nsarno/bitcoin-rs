// Bitcoin P2P version handshake implementation
// This module handles the initial handshake between peers

use crate::network::message::{Message, VersionMessage, NetworkAddress, MessageError};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use thiserror::Error;

#[cfg(test)]
use std::cell::RefCell;

/// Get current system time - mockable in tests
#[cfg(not(test))]
fn now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
thread_local! {
    static MOCK_TIME: RefCell<Option<SystemTime>> = RefCell::new(None);
}

#[cfg(test)]
fn now() -> SystemTime {
    MOCK_TIME.with(|cell| {
        cell.borrow()
            .as_ref()
            .cloned()
            .unwrap_or_else(SystemTime::now)
    })
}

#[cfg(test)]
fn set_mock_time(time: SystemTime) {
    MOCK_TIME.with(|cell| *cell.borrow_mut() = Some(time));
}

#[cfg(test)]
fn clear_mock_time() {
    MOCK_TIME.with(|cell| *cell.borrow_mut() = None);
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Invalid version message: {0}")]
    InvalidVersion(String),
    #[error("Handshake timeout")]
    Timeout,
    #[error("Message error: {0}")]
    Message(#[from] MessageError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handshake state for a peer connection
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    /// Initial state - no messages exchanged
    Initial,
    /// Version message sent, waiting for peer's version
    VersionSent,
    /// Version message received, waiting to send verack
    VersionReceived,
    /// Verack sent, waiting for peer's verack
    VerackSent,
    /// Handshake complete
    Complete,
    /// Handshake failed
    Failed(String),
}

/// Handshake manager for a single peer connection
#[derive(Debug)]
pub struct HandshakeManager {
    state: HandshakeState,
    our_version: VersionMessage,
    peer_version: Option<VersionMessage>,
    start_time: SystemTime,
}

impl HandshakeManager {
    /// Create a new handshake manager
    pub fn new(peer_addr: NetworkAddress) -> Self {
        let current_time = now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Create our version message
        let our_version = VersionMessage {
            version: 70015, // Bitcoin protocol version
            services: 1,    // NODE_NETWORK service
            timestamp: current_time,
            addr_recv: peer_addr.clone(),
            addr_from: NetworkAddress {
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // Will be filled by peer
                port: 8333,
            },
            nonce: rand::thread_rng().gen(),
            user_agent: "/bitcoin-rust:0.1.0/".to_string(),
            start_height: 0, // We start from genesis
            relay: true,
        };

        Self {
            state: HandshakeState::Initial,
            our_version,
            peer_version: None,
            start_time: now(),
        }
    }

    /// Get the version message to send to the peer
    pub fn get_version_message(&self) -> Message {
        Message::Version(self.our_version.clone())
    }

    /// Process an incoming message during handshake
    pub fn process_message(&mut self, message: Message) -> Result<Option<Message>, HandshakeError> {
        match (&self.state, message) {
            (HandshakeState::Initial, Message::Version(version)) => {
                // Peer sent version first, we should respond with our version
                self.peer_version = Some(version);
                self.state = HandshakeState::VersionReceived;
                Ok(Some(self.get_version_message()))
            }
            (HandshakeState::VersionSent, Message::Version(version)) => {
                // We sent version, peer responded with version
                self.peer_version = Some(version);
                self.state = HandshakeState::VersionReceived;
                Ok(Some(Message::Verack))
            }
            (HandshakeState::VerackSent, Message::Verack) => {
                // Peer sent verack, handshake complete
                self.state = HandshakeState::Complete;
                Ok(None)
            }
            (HandshakeState::VersionReceived, Message::Verack) => {
                // Peer sent verack after we sent version, we should send our verack
                self.state = HandshakeState::Complete;
                Ok(Some(Message::Verack))
            }
            _ => {
                // Invalid message for current state
                self.state = HandshakeState::Failed("Invalid message sequence".to_string());
                Err(HandshakeError::InvalidVersion("Invalid message sequence".to_string()))
            }
        }
    }

    /// Start the handshake by sending version message
    pub fn start_handshake(&mut self) -> Message {
        self.state = HandshakeState::VersionSent;
        self.get_version_message()
    }

    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.state, HandshakeState::Complete)
    }

    /// Check if handshake failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, HandshakeState::Failed(_))
    }

    /// Get current handshake state
    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Get peer's version message
    pub fn peer_version(&self) -> Option<&VersionMessage> {
        self.peer_version.as_ref()
    }

    /// Get our version message
    pub fn our_version(&self) -> &VersionMessage {
        &self.our_version
    }

    /// Check if handshake has timed out
    pub fn is_timeout(&self, timeout_seconds: u64) -> bool {
        now()
            .duration_since(self.start_time)
            .unwrap_or_default()
            .as_secs() >= timeout_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::message::MessageCodec;

    fn create_test_network_address() -> NetworkAddress {
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1], // IPv4 mapped to IPv6
            port: 8333,
        }
    }

    #[test]
    fn test_handshake_manager_creation() {
        let peer_addr = create_test_network_address();
        let manager = HandshakeManager::new(peer_addr.clone());

        assert_eq!(manager.state(), &HandshakeState::Initial);
        assert!(manager.peer_version().is_none());
        assert!(!manager.is_complete());
        assert!(!manager.is_failed());
    }

    #[test]
    fn test_handshake_we_send_version_first() {
        let peer_addr = create_test_network_address();
        let mut manager = HandshakeManager::new(peer_addr);

        // We start the handshake
        let _version_msg = manager.start_handshake();
        assert_eq!(manager.state(), &HandshakeState::VersionSent);

        // Simulate peer responding with version
        let peer_version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: manager.our_version().addr_from.clone(),
            addr_from: manager.our_version().addr_recv.clone(),
            nonce: 987654321,
            user_agent: "/bitcoin-core:22.0/".to_string(),
            start_height: 100,
            relay: true,
        };

        let response = manager.process_message(Message::Version(peer_version.clone()));
        assert!(response.is_ok());
        assert_eq!(manager.state(), &HandshakeState::VersionReceived);
        assert!(manager.peer_version().is_some());

        // We should send verack
        if let Ok(Some(Message::Verack)) = response {
            // Good, we're sending verack
        } else {
            panic!("Expected to send verack message");
        }

        // Simulate peer sending verack
        let final_response = manager.process_message(Message::Verack);
        assert!(final_response.is_ok());
        assert_eq!(manager.state(), &HandshakeState::Complete);
        assert!(manager.is_complete());
    }

    #[test]
    fn test_handshake_peer_sends_version_first() {
        let peer_addr = create_test_network_address();
        let mut manager = HandshakeManager::new(peer_addr);

        // Peer sends version first
        let peer_version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: manager.our_version().addr_from.clone(),
            addr_from: manager.our_version().addr_recv.clone(),
            nonce: 987654321,
            user_agent: "/bitcoin-core:22.0/".to_string(),
            start_height: 100,
            relay: true,
        };

        let response = manager.process_message(Message::Version(peer_version.clone()));
        assert!(response.is_ok());
        assert_eq!(manager.state(), &HandshakeState::VersionReceived);
        assert!(manager.peer_version().is_some());

        // We should send our version
        if let Ok(Some(Message::Version(_))) = response {
            // Good, we're sending our version
        } else {
            panic!("Expected to send version message");
        }

        // Simulate peer sending verack
        let verack_response = manager.process_message(Message::Verack);
        assert!(verack_response.is_ok());
        assert_eq!(manager.state(), &HandshakeState::Complete);
        assert!(manager.is_complete());
    }

    #[test]
    fn test_handshake_invalid_message_sequence() {
        let peer_addr = create_test_network_address();
        let mut manager = HandshakeManager::new(peer_addr);

        // Try to send verack before version
        let result = manager.process_message(Message::Verack);
        assert!(result.is_err());
        assert!(manager.is_failed());
    }

    #[test]
    fn test_handshake_timeout() {
        // Set mock time to a known starting point BEFORE creating the manager
        let start_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        set_mock_time(start_time);

        let peer_addr = create_test_network_address();
        let manager = HandshakeManager::new(peer_addr);

        // Initially, should not timeout (elapsed time is 0)
        assert!(!manager.is_timeout(1)); // Should not timeout in 1 second
        assert!(!manager.is_timeout(3600)); // Should not timeout in 1 hour

        // Advance time by 2 seconds
        set_mock_time(start_time + std::time::Duration::from_secs(2));

        // Now should timeout with 1 second threshold, but not with 1 hour
        assert!(manager.is_timeout(1)); // Should timeout after 2 seconds with 1 second threshold
        assert!(!manager.is_timeout(3600)); // Should not timeout after 2 seconds with 1 hour threshold

        // Advance time by another hour
        set_mock_time(start_time + std::time::Duration::from_secs(3602));

        // Now should timeout with both thresholds
        assert!(manager.is_timeout(1)); // Should timeout after 1 hour + 2 seconds
        assert!(manager.is_timeout(3600)); // Should timeout after 1 hour + 2 seconds

        // Clean up
        clear_mock_time();
    }

    #[test]
    fn test_version_message_serialization_integration() {
        let peer_addr = create_test_network_address();
        let manager = HandshakeManager::new(peer_addr);
        let version_msg = manager.get_version_message();

        // Test serialization
        let serialized = MessageCodec::serialize(&version_msg).expect("Failed to serialize version");
        let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize version");

        assert_eq!(version_msg, deserialized);
    }

    #[test]
    fn test_handshake_with_serialized_messages() {
        let peer_addr = create_test_network_address();
        let mut manager = HandshakeManager::new(peer_addr);

        // Start handshake
        let our_version = manager.start_handshake();
        let _serialized_our_version = MessageCodec::serialize(&our_version).expect("Failed to serialize our version");

        // Simulate receiving peer's version
        let peer_version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: manager.our_version().addr_from.clone(),
            addr_from: manager.our_version().addr_recv.clone(),
            nonce: 987654321,
            user_agent: "/bitcoin-core:22.0/".to_string(),
            start_height: 100,
            relay: true,
        };

        let peer_version_msg = Message::Version(peer_version);
        let serialized_peer_version = MessageCodec::serialize(&peer_version_msg).expect("Failed to serialize peer version");

        // Deserialize and process
        let deserialized_peer_version = MessageCodec::deserialize(&serialized_peer_version).expect("Failed to deserialize peer version");
        let response = manager.process_message(deserialized_peer_version);

        assert!(response.is_ok());
        assert_eq!(manager.state(), &HandshakeState::VersionReceived);

        // We should send verack
        if let Ok(Some(verack_msg)) = response {
            let serialized_verack = MessageCodec::serialize(&verack_msg).expect("Failed to serialize verack");
            let deserialized_verack = MessageCodec::deserialize(&serialized_verack).expect("Failed to deserialize verack");
            assert_eq!(verack_msg, deserialized_verack);
        } else {
            panic!("Expected to send verack message");
        }
    }

    #[test]
    fn test_handshake_state_transitions() {
        let peer_addr = create_test_network_address();
        let mut manager = HandshakeManager::new(peer_addr);

        // Initial state
        assert_eq!(manager.state(), &HandshakeState::Initial);

        // Start handshake
        manager.start_handshake();
        assert_eq!(manager.state(), &HandshakeState::VersionSent);

        // Receive peer version
        let peer_version = VersionMessage {
            version: 70015,
            services: 1,
            timestamp: 1234567890,
            addr_recv: manager.our_version().addr_from.clone(),
            addr_from: manager.our_version().addr_recv.clone(),
            nonce: 987654321,
            user_agent: "/bitcoin-core:22.0/".to_string(),
            start_height: 100,
            relay: true,
        };

        manager.process_message(Message::Version(peer_version)).unwrap();
        assert_eq!(manager.state(), &HandshakeState::VersionReceived);

        // Receive verack
        manager.process_message(Message::Verack).unwrap();
        assert_eq!(manager.state(), &HandshakeState::Complete);
        assert!(manager.is_complete());
    }
}
