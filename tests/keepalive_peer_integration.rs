// Bitcoin keepalive peer integration tests
// This file contains end-to-end tests for complete peer management workflows

use bitcoin_rust::network::message::{Message, NetworkAddress, MessageCodec, PongMessage};
use bitcoin_rust::network::peer_manager::{PeerManager, PeerState};
use std::time::Duration;

/// Create a test network address
fn create_test_network_address() -> NetworkAddress {
    NetworkAddress {
        services: 1,
        ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
        port: 8333,
    }
}

/// Test complete keepalive flow with peer manager
#[test]
fn test_complete_keepalive_flow() {
    let mut peer_manager = PeerManager::new();
    let address = create_test_network_address();

    // Add a peer
    let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");
    assert_eq!(peer_manager.total_peer_count(), 1);

    // Start handshake
    let version_msg = peer_manager.start_handshake(&connection_id).expect("Failed to start handshake");
    assert!(matches!(version_msg, Message::Version(_)));

    // Simulate peer responding with version
    let peer_version = bitcoin_rust::network::message::VersionMessage {
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
    };

    let peer_version_msg = Message::Version(peer_version);
    let response = peer_manager.process_message(&connection_id, peer_version_msg)
        .expect("Failed to process peer version");

    // Should send verack
    assert!(response.is_some());
    if let Some(Message::Verack) = response {
        // Good
    } else {
        panic!("Expected verack message");
    }

    // Simulate peer sending verack
    let verack_response = peer_manager.process_message(&connection_id, Message::Verack)
        .expect("Failed to process verack");

    // We should send our verack in response
    if let Some(Message::Verack) = verack_response {
        // Good, we're sending our verack
    } else {
        panic!("Expected to send verack message");
    }

    // Check that handshake is complete
    let peer = peer_manager.get_peer(&connection_id).expect("Peer not found");
    assert_eq!(peer.state, PeerState::Connected);

    // Now test keepalive functionality
    // Generate a ping
    let pings = peer_manager.get_peers_needing_ping();
    assert!(!pings.is_empty());

    let (_, ping_msg) = &pings[0];
    assert!(matches!(ping_msg, Message::Ping(_)));

    // Test ping serialization/deserialization
    let ping_serialized = MessageCodec::serialize(ping_msg).expect("Failed to serialize ping");
    let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
    assert_eq!(ping_msg, &ping_deserialized);

    // Extract nonce and create pong
    let ping_nonce = if let Message::Ping(ping) = ping_deserialized {
        ping.nonce
    } else {
        panic!("Expected ping message");
    };

    let pong_msg = Message::Pong(PongMessage { nonce: ping_nonce });

    // Test pong serialization/deserialization
    let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
    let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
    assert_eq!(pong_msg, pong_deserialized);

    // Process the pong
    let pong_response = peer_manager.process_message(&connection_id, pong_deserialized)
        .expect("Failed to process pong");
    assert!(pong_response.is_none()); // Pong should not generate a response

    // Verify peer is still alive
    let peer = peer_manager.get_peer(&connection_id).expect("Peer not found");
    assert!(peer.is_alive());

    // Get peer statistics
    let stats = peer_manager.get_all_peer_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].connection_id, connection_id);
    assert_eq!(stats[0].state, PeerState::Connected);
    assert!(stats[0].is_alive);
}

/// Test keepalive with multiple peers
#[test]
fn test_keepalive_multiple_peers() {
    let mut peer_manager = PeerManager::new();

    // Add multiple peers
    let addresses = vec![
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 2],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 3],
            port: 8333,
        },
    ];

    let mut connection_ids = Vec::new();
    for address in addresses {
        let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");
        connection_ids.push(connection_id);
    }

    assert_eq!(peer_manager.total_peer_count(), 3);

    // Set all peers to connected state for testing
    for connection_id in &connection_ids {
        if let Some(peer) = peer_manager.get_peer_mut(connection_id) {
            peer.state = PeerState::Connected;
        }
    }

    // Generate pings for all peers
    let pings = peer_manager.get_peers_needing_ping();
    assert_eq!(pings.len(), 3);

    // Process pongs for all peers
    for (connection_id, ping_msg) in pings {
        let ping_nonce = if let Message::Ping(ping) = ping_msg {
            ping.nonce
        } else {
            panic!("Expected ping message");
        };

        let pong_msg = Message::Pong(PongMessage { nonce: ping_nonce });
        let response = peer_manager.process_message(&connection_id, pong_msg)
            .expect("Failed to process pong");
        assert!(response.is_none());
    }

    // Verify all peers are alive
    let stats = peer_manager.get_all_peer_stats();
    assert_eq!(stats.len(), 3);
    for stat in stats {
        assert!(stat.is_alive);
        assert_eq!(stat.state, PeerState::Connected);
    }
}

/// Test keepalive error handling
#[test]
fn test_keepalive_error_handling() {
    let mut peer_manager = PeerManager::new();
    let address = create_test_network_address();

    let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");

    // Set peer to connected state
    if let Some(peer) = peer_manager.get_peer_mut(&connection_id) {
        peer.state = PeerState::Connected;
    }

    // Generate a ping
    let pings = peer_manager.get_peers_needing_ping();
    assert!(!pings.is_empty());

    let (_, ping_msg) = &pings[0];
    let ping_nonce = if let Message::Ping(ping) = ping_msg {
        ping.nonce
    } else {
        panic!("Expected ping message");
    };

    // Test pong with wrong nonce
    let wrong_pong = Message::Pong(PongMessage { nonce: 999999 });
    let response = peer_manager.process_message(&connection_id, wrong_pong);
    assert!(response.is_err()); // Should fail with wrong nonce

    // Test pong with correct nonce
    let correct_pong = Message::Pong(PongMessage { nonce: ping_nonce });
    let response = peer_manager.process_message(&connection_id, correct_pong)
        .expect("Failed to process correct pong");
    assert!(response.is_none());
}

/// Test keepalive message format compliance
#[test]
fn test_keepalive_message_format_compliance() {
    let mut peer_manager = PeerManager::new();
    let address = create_test_network_address();

    let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");

    // Set peer to connected state
    if let Some(peer) = peer_manager.get_peer_mut(&connection_id) {
        peer.state = PeerState::Connected;
    }

    // Generate a ping
    let pings = peer_manager.get_peers_needing_ping();
    assert!(!pings.is_empty());

    let (_, ping_msg) = &pings[0];

    // Test Bitcoin protocol compliance
    let serialized = MessageCodec::serialize(ping_msg).expect("Failed to serialize ping");

    // Verify message format
    assert!(serialized.len() >= 24, "Message should have at least 24 bytes (header)");

    // Check magic bytes (testnet: 0x0b110907)
    let magic = u32::from_le_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    assert_eq!(magic, 0x0b110907, "Magic bytes should be testnet magic");

    // Check command string
    let command_bytes = &serialized[4..16];
    let command_str = String::from_utf8_lossy(command_bytes);
    let command = command_str.trim_end_matches('\0');
    assert_eq!(command, "ping", "Command should be 'ping'");

    // Check payload length
    let payload_length = u32::from_le_bytes([serialized[16], serialized[17], serialized[18], serialized[19]]);
    assert_eq!(payload_length, 8, "Ping payload should be 8 bytes (nonce)");

    // Check checksum
    let checksum = &serialized[20..24];
    assert_eq!(checksum.len(), 4, "Checksum should be 4 bytes");

    // Verify payload contains nonce
    let payload = &serialized[24..];
    assert_eq!(payload.len(), 8, "Payload should be 8 bytes");

    // Test deserialization
    let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize ping");
    assert_eq!(ping_msg, &deserialized);
}

/// Test keepalive with custom settings
#[test]
fn test_keepalive_custom_settings() {
    let mut peer_manager = PeerManager::with_settings(
        4, // max_peers
        Duration::from_secs(120), // connection_timeout
        Duration::from_secs(15),  // keepalive_interval
    );

    assert_eq!(peer_manager.total_peer_count(), 0);

    // Test adding peers up to limit
    let addresses = vec![
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 2],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 3],
            port: 8333,
        },
        NetworkAddress {
            services: 1,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 4],
            port: 8333,
        },
    ];

    let mut connection_ids = Vec::new();
    for address in addresses {
        let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");
        connection_ids.push(connection_id);
    }

    assert_eq!(peer_manager.total_peer_count(), 4);

    // Try to add one more peer (should fail)
    let extra_address = NetworkAddress {
        services: 1,
        ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 5],
        port: 8333,
    };

    let result = peer_manager.add_peer(extra_address);
    assert!(result.is_err()); // Should fail due to max peers limit
}

/// Test keepalive statistics
#[test]
fn test_keepalive_statistics() {
    let mut peer_manager = PeerManager::new();
    let address = create_test_network_address();

    let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");

    // Get initial stats
    let stats = peer_manager.get_all_peer_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].connection_id, connection_id);
    assert_eq!(stats[0].state, PeerState::Disconnected);
    assert!(!stats[0].is_alive); // Not connected yet

    // Set peer to connected state
    if let Some(peer) = peer_manager.get_peer_mut(&connection_id) {
        peer.state = PeerState::Connected;
    }

    // Get updated stats
    let stats = peer_manager.get_all_peer_stats();
    assert_eq!(stats[0].state, PeerState::Connected);
    assert!(stats[0].is_alive);

    // Test peer counts
    assert_eq!(peer_manager.total_peer_count(), 1);
    assert_eq!(peer_manager.connected_peer_count(), 1);
}

/// Test keepalive with rapid ping/pong cycles
#[test]
fn test_keepalive_rapid_cycles() {
    let mut peer_manager = PeerManager::new();
    let address = create_test_network_address();

    let connection_id = peer_manager.add_peer(address).expect("Failed to add peer");

    // Set peer to connected state
    if let Some(peer) = peer_manager.get_peer_mut(&connection_id) {
        peer.state = PeerState::Connected;
    }

    // Perform multiple ping/pong cycles
    for i in 0..5 {
        // Generate ping (may be empty for subsequent cycles due to timing)
        let pings = peer_manager.get_peers_needing_ping();

        if !pings.is_empty() {
            let (_, ping_msg) = &pings[0];
            let ping_nonce = if let Message::Ping(ping) = ping_msg {
                ping.nonce
            } else {
                panic!("Expected ping message in cycle {}", i);
            };

            // Create and process pong
            let pong_msg = Message::Pong(PongMessage { nonce: ping_nonce });
            let response = peer_manager.process_message(&connection_id, pong_msg)
                .expect("Failed to process pong");
            assert!(response.is_none());
        }

        // Verify peer is still alive
        let peer = peer_manager.get_peer(&connection_id).expect("Peer not found");
        assert!(peer.is_alive(), "Peer should be alive after cycle {}", i);
    }
}
