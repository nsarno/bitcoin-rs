// Bitcoin keepalive message format tests
// This file contains tests for Bitcoin protocol message format compliance

use bitcoin_rust::network::message::{Message, PingMessage, PongMessage, MessageCodec};
use std::time::SystemTime;

/// Test ping message creation and serialization
#[test]
fn test_ping_message_creation() {
    let nonce = 123456789;
    let ping_msg = Message::Ping(PingMessage { nonce });

    // Test serialization
    let serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
    assert!(serialized.len() >= 24, "Serialized ping should have at least 24 bytes (header)");

    // Test deserialization
    let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize ping");
    assert_eq!(ping_msg, deserialized);
}

/// Test pong message creation and serialization
#[test]
fn test_pong_message_creation() {
    let nonce = 123456789;
    let pong_msg = Message::Pong(PongMessage { nonce });

    // Test serialization
    let serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
    assert!(serialized.len() >= 24, "Serialized pong should have at least 24 bytes (header)");

    // Test deserialization
    let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize pong");
    assert_eq!(pong_msg, deserialized);
}

/// Test ping-pong roundtrip with matching nonces
#[test]
fn test_ping_pong_roundtrip() {
    let nonce = 987654321;
    let ping_msg = Message::Ping(PingMessage { nonce });
    let pong_msg = Message::Pong(PongMessage { nonce });

    // Serialize ping
    let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
    let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
    assert_eq!(ping_msg, ping_deserialized);

    // Serialize pong
    let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
    let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
    assert_eq!(pong_msg, pong_deserialized);

    // Verify nonces match
    if let (Message::Ping(ping), Message::Pong(pong)) = (&ping_deserialized, &pong_deserialized) {
        assert_eq!(ping.nonce, pong.nonce, "Ping and pong nonces should match");
    } else {
        panic!("Expected ping and pong messages");
    }
}

/// Test ping message with different nonces
#[test]
fn test_ping_with_different_nonces() {
    let nonces = vec![0, 1, 42, 12345, 0xFFFFFFFF, 0x123456789ABCDEF0];

    for nonce in nonces {
        let ping_msg = Message::Ping(PingMessage { nonce });
        let pong_msg = Message::Pong(PongMessage { nonce });

        // Test serialization/deserialization
        let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
        let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
        assert_eq!(ping_msg, ping_deserialized);

        let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
        let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
        assert_eq!(pong_msg, pong_deserialized);

        // Verify nonce is preserved
        if let Message::Ping(deserialized_ping) = ping_deserialized {
            assert_eq!(deserialized_ping.nonce, nonce, "Nonce should be preserved");
        }
        if let Message::Pong(deserialized_pong) = pong_deserialized {
            assert_eq!(deserialized_pong.nonce, nonce, "Nonce should be preserved");
        }
    }
}

/// Test keepalive message format validation
#[test]
fn test_keepalive_message_format() {
    let nonce = 0x123456789ABCDEF0;
    let ping_msg = Message::Ping(PingMessage { nonce });

    // Serialize the message
    let serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");

    // Verify Bitcoin protocol format
    assert!(serialized.len() >= 24, "Serialized message should have at least 24 bytes (header)");

    // Check magic bytes (testnet magic: 0x0b110907)
    let magic = u32::from_le_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    assert_eq!(magic, 0x0b110907, "Magic bytes should be testnet magic");

    // Check command string (12 bytes, null-padded)
    let command_bytes = &serialized[4..16];
    let command_str = String::from_utf8_lossy(command_bytes);
    let command = command_str.trim_end_matches('\0');
    assert_eq!(command, "ping", "Command should be 'ping'");

    // Check payload length (4 bytes, little-endian)
    let payload_length = u32::from_le_bytes([serialized[16], serialized[17], serialized[18], serialized[19]]);
    assert_eq!(payload_length, 8, "Ping payload length should be 8 bytes (nonce)");

    // Check checksum (4 bytes)
    let checksum = &serialized[20..24];
    assert_eq!(checksum.len(), 4, "Checksum should be 4 bytes");

    // Verify payload contains the nonce
    let payload = &serialized[24..];
    assert_eq!(payload.len(), 8, "Payload should be 8 bytes");
    let payload_nonce = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7]
    ]);
    assert_eq!(payload_nonce, nonce, "Payload should contain the correct nonce");
}

/// Test pong message format validation
#[test]
fn test_pong_message_format() {
    let nonce = 0x123456789ABCDEF0;
    let pong_msg = Message::Pong(PongMessage { nonce });

    // Serialize the message
    let serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");

    // Verify Bitcoin protocol format
    assert!(serialized.len() >= 24, "Serialized message should have at least 24 bytes (header)");

    // Check magic bytes (testnet magic: 0x0b110907)
    let magic = u32::from_le_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    assert_eq!(magic, 0x0b110907, "Magic bytes should be testnet magic");

    // Check command string (12 bytes, null-padded)
    let command_bytes = &serialized[4..16];
    let command_str = String::from_utf8_lossy(command_bytes);
    let command = command_str.trim_end_matches('\0');
    assert_eq!(command, "pong", "Command should be 'pong'");

    // Check payload length (4 bytes, little-endian)
    let payload_length = u32::from_le_bytes([serialized[16], serialized[17], serialized[18], serialized[19]]);
    assert_eq!(payload_length, 8, "Pong payload length should be 8 bytes (nonce)");

    // Check checksum (4 bytes)
    let checksum = &serialized[20..24];
    assert_eq!(checksum.len(), 4, "Checksum should be 4 bytes");

    // Verify payload contains the nonce
    let payload = &serialized[24..];
    assert_eq!(payload.len(), 8, "Payload should be 8 bytes");
    let payload_nonce = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
        payload[4], payload[5], payload[6], payload[7]
    ]);
    assert_eq!(payload_nonce, nonce, "Payload should contain the correct nonce");
}

/// Test keepalive message command strings
#[test]
fn test_keepalive_command_strings() {
    let ping_msg = Message::Ping(PingMessage { nonce: 0 });
    let pong_msg = Message::Pong(PongMessage { nonce: 0 });

    assert_eq!(MessageCodec::get_command(&ping_msg), "ping");
    assert_eq!(MessageCodec::get_command(&pong_msg), "pong");
}

/// Test keepalive with random nonces (simulating real usage)
#[test]
fn test_keepalive_with_random_nonces() {
    use std::collections::HashSet;

    let mut seen_nonces = HashSet::new();
    let num_tests = 100;

    for _ in 0..num_tests {
        // Generate random nonce
        let nonce = rand::random::<u64>();

        // Ensure we don't have duplicate nonces (very unlikely but good practice)
        assert!(seen_nonces.insert(nonce), "Generated duplicate nonce");

        let ping_msg = Message::Ping(PingMessage { nonce });
        let pong_msg = Message::Pong(PongMessage { nonce });

        // Test serialization/deserialization
        let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
        let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
        assert_eq!(ping_msg, ping_deserialized);

        let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
        let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
        assert_eq!(pong_msg, pong_deserialized);

        // Verify nonce preservation
        if let Message::Ping(deserialized_ping) = ping_deserialized {
            assert_eq!(deserialized_ping.nonce, nonce, "Ping nonce should be preserved");
        }
        if let Message::Pong(deserialized_pong) = pong_deserialized {
            assert_eq!(deserialized_pong.nonce, nonce, "Pong nonce should be preserved");
        }
    }
}

/// Test keepalive message error handling
#[test]
fn test_keepalive_error_handling() {
    // Test with invalid data
    let invalid_data = vec![0x00, 0x01, 0x02, 0x03]; // Too short
    let result = MessageCodec::deserialize(&invalid_data);
    assert!(result.is_err(), "Should fail to deserialize invalid data");

    // Test with invalid magic bytes
    let invalid_message = vec![0xFF; 24]; // Valid length but wrong magic
    let result = MessageCodec::deserialize(&invalid_message);
    assert!(result.is_err(), "Should fail to deserialize with invalid magic bytes");

    // Test with valid header but invalid payload length
    let mut invalid_payload_message = vec![0x0b, 0x11, 0x09, 0x07]; // Magic bytes
    invalid_payload_message.extend_from_slice(b"ping\0\0\0\0\0\0\0"); // Command
    invalid_payload_message.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // Invalid payload length
    invalid_payload_message.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Checksum

    let result = MessageCodec::deserialize(&invalid_payload_message);
    assert!(result.is_err(), "Should fail to deserialize with invalid payload length");
}

/// Test keepalive message timing (for future keepalive logic)
#[test]
fn test_keepalive_timing() {
    let start_time = SystemTime::now();

    // Create ping message
    let nonce = 12345;
    let ping_msg = Message::Ping(PingMessage { nonce });

    // Serialize and deserialize
    let serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
    let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize ping");

    let end_time = SystemTime::now();
    let duration = end_time.duration_since(start_time).unwrap();

    // Verify message was processed quickly (should be microseconds)
    assert!(duration.as_micros() < 1000, "Keepalive message processing should be fast");

    // Verify message integrity
    assert_eq!(ping_msg, deserialized);
}

/// Test keepalive message size efficiency
#[test]
fn test_keepalive_message_size() {
    let nonce = 0x123456789ABCDEF0;
    let ping_msg = Message::Ping(PingMessage { nonce });
    let pong_msg = Message::Pong(PongMessage { nonce });

    // Serialize messages
    let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
    let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");

    // Verify message sizes are minimal
    assert_eq!(ping_serialized.len(), 32, "Ping message should be exactly 32 bytes (24 header + 8 payload)");
    assert_eq!(pong_serialized.len(), 32, "Pong message should be exactly 32 bytes (24 header + 8 payload)");

    // Verify both messages have same size
    assert_eq!(ping_serialized.len(), pong_serialized.len(), "Ping and pong messages should have same size");
}

/// Test keepalive message checksum validation
#[test]
fn test_keepalive_checksum_validation() {
    let nonce = 0x123456789ABCDEF0;
    let ping_msg = Message::Ping(PingMessage { nonce });

    // Serialize message
    let serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");

    // Extract checksum from message
    let message_checksum = &serialized[20..24];

    // Verify checksum is present and has correct length
    assert_eq!(message_checksum.len(), 4, "Checksum should be 4 bytes");

    // Test deserialization with correct checksum
    let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize ping");
    assert_eq!(ping_msg, deserialized);
}

/// Test keepalive message with edge case nonces
#[test]
fn test_keepalive_edge_case_nonces() {
    let edge_case_nonces = vec![
        0,                          // Minimum value
        1,                          // Small positive
        0x7FFFFFFFFFFFFFFF,         // Maximum positive i64
        0x8000000000000000,         // Minimum negative i64
        0xFFFFFFFFFFFFFFFF,        // Maximum u64
        0x123456789ABCDEF0,         // Mixed hex pattern
        0x0000000000000001,         // Single bit set
        0x8000000000000000,         // High bit set
    ];

    for nonce in edge_case_nonces {
        let ping_msg = Message::Ping(PingMessage { nonce });
        let pong_msg = Message::Pong(PongMessage { nonce });

        // Test serialization/deserialization
        let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
        let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
        assert_eq!(ping_msg, ping_deserialized);

        let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
        let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
        assert_eq!(pong_msg, pong_deserialized);

        // Verify nonce preservation
        if let Message::Ping(deserialized_ping) = ping_deserialized {
            assert_eq!(deserialized_ping.nonce, nonce, "Ping nonce should be preserved for edge case: {}", nonce);
        }
        if let Message::Pong(deserialized_pong) = pong_deserialized {
            assert_eq!(deserialized_pong.nonce, nonce, "Pong nonce should be preserved for edge case: {}", nonce);
        }
    }
}
