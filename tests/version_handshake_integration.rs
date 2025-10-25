// Integration tests for Bitcoin version handshake
// This file contains comprehensive tests for the version handshake protocol

use bitcoin_rs::network::handshake::{HandshakeManager, HandshakeState};
use bitcoin_rs::network::message::{Message, VersionMessage, NetworkAddress, MessageCodec, PingMessage};

/// Create a test network address for testing
fn create_test_network_address() -> NetworkAddress {
    NetworkAddress {
        services: 1,
        ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1], // IPv4 mapped to IPv6
        port: 8333,
    }
}

/// Create a test peer version message
fn create_test_peer_version() -> VersionMessage {
    VersionMessage {
        version: 70015,
        services: 1,
        timestamp: 1234567890,
        addr_recv: NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 8333,
        },
        addr_from: NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
            port: 8333,
        },
        nonce: 987654321,
        user_agent: "/bitcoin-core:22.0/".to_string(),
        start_height: 100,
        relay: true,
    }
}

#[test]
fn test_complete_handshake_flow_we_initiate() {
    // Test the complete handshake flow when we initiate the connection
    let peer_addr = create_test_network_address();
    let mut manager = HandshakeManager::new(peer_addr);

    // Step 1: We start the handshake by sending version
    let our_version_msg = manager.start_handshake();
    assert_eq!(manager.state(), &HandshakeState::VersionSent);

    // Verify our version message is properly formatted
    let serialized_our_version = MessageCodec::serialize(&our_version_msg).expect("Failed to serialize our version");
    let deserialized_our_version = MessageCodec::deserialize(&serialized_our_version).expect("Failed to deserialize our version");
    assert_eq!(our_version_msg, deserialized_our_version);

    // Step 2: Peer responds with their version
    let peer_version = create_test_peer_version();
    let peer_version_msg = Message::Version(peer_version.clone());

    // Serialize and deserialize to test the full message flow
    let serialized_peer_version = MessageCodec::serialize(&peer_version_msg).expect("Failed to serialize peer version");
    let deserialized_peer_version = MessageCodec::deserialize(&serialized_peer_version).expect("Failed to deserialize peer version");

    let response = manager.process_message(deserialized_peer_version);
    assert!(response.is_ok());
    assert_eq!(manager.state(), &HandshakeState::VersionReceived);
    assert!(manager.peer_version().is_some());

    // We should send verack
    if let Ok(Some(Message::Verack)) = response {
        // Good, we're sending verack
    } else {
        panic!("Expected to send verack message");
    }

    // Step 3: Peer sends verack
    let final_response = manager.process_message(Message::Verack);
    assert!(final_response.is_ok());
    assert_eq!(manager.state(), &HandshakeState::Complete);
    assert!(manager.is_complete());
}

#[test]
fn test_complete_handshake_flow_peer_initiates() {
    // Test the complete handshake flow when peer initiates the connection
    let peer_addr = create_test_network_address();
    let mut manager = HandshakeManager::new(peer_addr);

    // Step 1: Peer sends version first
    let peer_version = create_test_peer_version();
    let peer_version_msg = Message::Version(peer_version.clone());

    let response = manager.process_message(peer_version_msg);
    assert!(response.is_ok());
    assert_eq!(manager.state(), &HandshakeState::VersionReceived);
    assert!(manager.peer_version().is_some());

    // We should send our version
    if let Ok(Some(Message::Version(_))) = response {
        // Good, we're sending our version
    } else {
        panic!("Expected to send version message");
    }

    // Step 2: Peer sends verack
    let verack_response = manager.process_message(Message::Verack);
    assert!(verack_response.is_ok());
    assert_eq!(manager.state(), &HandshakeState::Complete);
    assert!(manager.is_complete());
}

#[test]
fn test_handshake_with_real_serialization() {
    // Test handshake with full message serialization/deserialization
    let peer_addr = create_test_network_address();
    let mut manager = HandshakeManager::new(peer_addr);

    // Start handshake
    let our_version = manager.start_handshake();
    let serialized_our_version = MessageCodec::serialize(&our_version).expect("Failed to serialize our version");
    let deserialized_our_version = MessageCodec::deserialize(&serialized_our_version).expect("Failed to deserialize our version");
    assert_eq!(our_version, deserialized_our_version);

    // Simulate receiving peer's version
    let peer_version = create_test_peer_version();
    let peer_version_msg = Message::Version(peer_version);
    let serialized_peer_version = MessageCodec::serialize(&peer_version_msg).expect("Failed to serialize peer version");
    let deserialized_peer_version = MessageCodec::deserialize(&serialized_peer_version).expect("Failed to deserialize peer version");

    // Process peer's version
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

    // Simulate peer sending verack
    let peer_verack = Message::Verack;
    let serialized_peer_verack = MessageCodec::serialize(&peer_verack).expect("Failed to serialize peer verack");
    let deserialized_peer_verack = MessageCodec::deserialize(&serialized_peer_verack).expect("Failed to deserialize peer verack");

    let final_response = manager.process_message(deserialized_peer_verack);
    assert!(final_response.is_ok());
    assert_eq!(manager.state(), &HandshakeState::Complete);
    assert!(manager.is_complete());
}

#[test]
fn test_handshake_error_handling() {
    let peer_addr = create_test_network_address();
    let mut manager = HandshakeManager::new(peer_addr.clone());

    // Test invalid message sequence
    let result = manager.process_message(Message::Verack);
    assert!(result.is_err());
    assert!(manager.is_failed());

    // Test with ping message during handshake
    let mut manager2 = HandshakeManager::new(peer_addr.clone());
    manager2.start_handshake();

    // This should fail because ping is not expected during handshake
    let ping_msg = Message::Ping(PingMessage { nonce: 12345 });
    let result = manager2.process_message(ping_msg);
    assert!(result.is_err());
    assert!(manager2.is_failed());
}

#[test]
fn test_handshake_state_consistency() {
    let peer_addr = create_test_network_address();
    let mut manager = HandshakeManager::new(peer_addr);

    // Initial state
    assert_eq!(manager.state(), &HandshakeState::Initial);
    assert!(!manager.is_complete());
    assert!(!manager.is_failed());

    // After starting handshake
    manager.start_handshake();
    assert_eq!(manager.state(), &HandshakeState::VersionSent);
    assert!(!manager.is_complete());
    assert!(!manager.is_failed());

    // After receiving peer version
    let peer_version = create_test_peer_version();
    manager.process_message(Message::Version(peer_version)).unwrap();
    assert_eq!(manager.state(), &HandshakeState::VersionReceived);
    assert!(!manager.is_complete());
    assert!(!manager.is_failed());

    // After receiving verack
    manager.process_message(Message::Verack).unwrap();
    assert_eq!(manager.state(), &HandshakeState::Complete);
    assert!(manager.is_complete());
    assert!(!manager.is_failed());
}

#[test]
fn test_version_message_content() {
    let peer_addr = create_test_network_address();
    let manager = HandshakeManager::new(peer_addr.clone());
    let our_version = manager.our_version();

    // Verify our version message has correct content
    assert_eq!(our_version.version, 70015);
    assert_eq!(our_version.services, 1);
    assert_eq!(our_version.user_agent, "/bitcoin-rs:0.1.0/");
    assert_eq!(our_version.start_height, 0);
    assert!(our_version.relay);
    assert_eq!(our_version.addr_recv, peer_addr);
}

#[test]
fn test_handshake_timeout_detection() {
    let peer_addr = create_test_network_address();
    let manager = HandshakeManager::new(peer_addr);

    // Test timeout detection
    assert!(!manager.is_timeout(1)); // Should not timeout in 1 second
    assert!(!manager.is_timeout(60)); // Should not timeout in 1 minute
    assert!(!manager.is_timeout(3600)); // Should not timeout in 1 hour
}
