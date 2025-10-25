// Bitcoin message serialization/deserialization
// This module handles the Bitcoin P2P protocol message format

use bitcoin::{Network, BlockHash, Txid};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Unsupported message type: {0}")]
    UnsupportedMessageType(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Bitcoin P2P protocol message types
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Version(VersionMessage),
    Verack,
    Ping(PingMessage),
    Pong(PongMessage),
    GetHeaders(GetHeadersMessage),
    Headers(HeadersMessage),
    GetData(GetDataMessage),
    Block(BlockMessage),
    Inv(InvMessage),
    Tx(TxMessage),
}

/// Version message - first message sent in Bitcoin P2P protocol
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionMessage {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetworkAddress,
    pub addr_from: NetworkAddress,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
    pub relay: bool,
}

/// Network address structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkAddress {
    pub services: u64,
    pub ip: [u8; 16], // IPv6 address
    pub port: u16,
}

/// Ping message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingMessage {
    pub nonce: u64,
}

/// Pong message
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PongMessage {
    pub nonce: u64,
}

/// GetHeaders message
#[derive(Debug, Clone, PartialEq)]
pub struct GetHeadersMessage {
    pub version: i32,
    pub block_locator_hashes: Vec<BlockHash>,
    pub hash_stop: BlockHash,
}

/// Headers message
#[derive(Debug, Clone, PartialEq)]
pub struct HeadersMessage {
    pub headers: Vec<BlockHeader>,
}

/// Block header structure
#[derive(Debug, Clone, PartialEq)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_block_hash: BlockHash,
    pub merkle_root: BlockHash,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

/// GetData message
#[derive(Debug, Clone, PartialEq)]
pub struct GetDataMessage {
    pub inventory: Vec<InventoryVector>,
}

/// Inventory vector
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryVector {
    pub inv_type: u32,
    pub hash: [u8; 32],
}

/// Block message
#[derive(Debug, Clone, PartialEq)]
pub struct BlockMessage {
    pub block: bitcoin::Block,
}

/// Inv message
#[derive(Debug, Clone, PartialEq)]
pub struct InvMessage {
    pub inventory: Vec<InventoryVector>,
}

/// Transaction message
#[derive(Debug, Clone, PartialEq)]
pub struct TxMessage {
    pub tx: bitcoin::Transaction,
}

/// Bitcoin message serializer/deserializer
pub struct MessageCodec;

impl MessageCodec {
    /// Serialize a Bitcoin message to bytes
    pub fn serialize(message: &Message) -> Result<Vec<u8>, MessageError> {
        // TODO: Implement Bitcoin protocol serialization
        // This should include:
        // 1. Message header (magic bytes, command, length, checksum)
        // 2. Message payload serialization
        // 3. Proper endianness handling
        todo!("Implement Bitcoin message serialization")
    }

    /// Deserialize bytes to a Bitcoin message
    pub fn deserialize(data: &[u8]) -> Result<Message, MessageError> {
        // TODO: Implement Bitcoin protocol deserialization
        // This should include:
        // 1. Parse message header
        // 2. Verify checksum
        // 3. Deserialize message payload based on command
        // 4. Handle different message types
        todo!("Implement Bitcoin message deserialization")
    }

    /// Get the command string for a message type
    pub fn get_command(message: &Message) -> &'static str {
        match message {
            Message::Version(_) => "version",
            Message::Verack => "verack",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::GetHeaders(_) => "getheaders",
            Message::Headers(_) => "headers",
            Message::GetData(_) => "getdata",
            Message::Block(_) => "block",
            Message::Inv(_) => "inv",
            Message::Tx(_) => "tx",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use std::str::FromStr;

    #[test]
    fn test_version_message_serialization() {
        // Create a version message
        let version_msg = Message::Version(VersionMessage {
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
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 8333,
            },
            nonce: 123456789,
            user_agent: "/bitcoin-rust:0.1.0/".to_string(),
            start_height: 0,
            relay: true,
        });

        // Serialize the message
        let serialized = MessageCodec::serialize(&version_msg).expect("Failed to serialize version message");

        // Verify the serialized data has the correct Bitcoin protocol format
        assert!(serialized.len() >= 24, "Serialized message should have at least 24 bytes (header)");

        // Check magic bytes (testnet magic: 0x0b110907)
        let magic = u32::from_le_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
        assert_eq!(magic, 0x0b110907, "Magic bytes should be testnet magic");

        // Check command string (12 bytes, null-padded)
        let command_bytes = &serialized[4..16];
        let command_str = String::from_utf8_lossy(command_bytes);
        let command = command_str.trim_end_matches('\0');
        assert_eq!(command, "version", "Command should be 'version'");

        // Check payload length (4 bytes, little-endian)
        let payload_length = u32::from_le_bytes([serialized[16], serialized[17], serialized[18], serialized[19]]);
        assert!(payload_length > 0, "Payload length should be greater than 0");

        // Check checksum (4 bytes)
        let checksum = &serialized[20..24];
        assert_eq!(checksum.len(), 4, "Checksum should be 4 bytes");
    }

    #[test]
    fn test_version_message_roundtrip() {
        // Create a version message
        let original_msg = Message::Version(VersionMessage {
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
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 8333,
            },
            nonce: 123456789,
            user_agent: "/bitcoin-rust:0.1.0/".to_string(),
            start_height: 0,
            relay: true,
        });

        // Serialize and deserialize
        let serialized = MessageCodec::serialize(&original_msg).expect("Failed to serialize");
        let deserialized = MessageCodec::deserialize(&serialized).expect("Failed to deserialize");

        // Verify roundtrip
        assert_eq!(original_msg, deserialized, "Message should be identical after roundtrip");
    }

    #[test]
    fn test_verack_message_serialization() {
        let verack_msg = Message::Verack;

        let serialized = MessageCodec::serialize(&verack_msg).expect("Failed to serialize verack");

        // Verack should have minimal payload
        assert!(serialized.len() >= 24, "Serialized message should have at least 24 bytes (header)");

        // Check command
        let command_bytes = &serialized[4..16];
        let command_str = String::from_utf8_lossy(command_bytes);
        let command = command_str.trim_end_matches('\0');
        assert_eq!(command, "verack", "Command should be 'verack'");

        // Check payload length should be 0 for verack
        let payload_length = u32::from_le_bytes([serialized[16], serialized[17], serialized[18], serialized[19]]);
        assert_eq!(payload_length, 0, "Verack payload length should be 0");
    }

    #[test]
    fn test_ping_pong_messages() {
        let ping_msg = Message::Ping(PingMessage { nonce: 12345 });
        let pong_msg = Message::Pong(PongMessage { nonce: 12345 });

        // Test ping serialization
        let ping_serialized = MessageCodec::serialize(&ping_msg).expect("Failed to serialize ping");
        let ping_deserialized = MessageCodec::deserialize(&ping_serialized).expect("Failed to deserialize ping");
        assert_eq!(ping_msg, ping_deserialized);

        // Test pong serialization
        let pong_serialized = MessageCodec::serialize(&pong_msg).expect("Failed to serialize pong");
        let pong_deserialized = MessageCodec::deserialize(&pong_serialized).expect("Failed to deserialize pong");
        assert_eq!(pong_msg, pong_deserialized);
    }

    #[test]
    fn test_invalid_message_handling() {
        // Test with invalid data
        let invalid_data = vec![0x00, 0x01, 0x02, 0x03]; // Too short
        let result = MessageCodec::deserialize(&invalid_data);
        assert!(result.is_err(), "Should fail to deserialize invalid data");

        // Test with invalid magic bytes
        let mut invalid_message = vec![0xFF; 24]; // Valid length but wrong magic
        let result = MessageCodec::deserialize(&invalid_message);
        assert!(result.is_err(), "Should fail to deserialize with invalid magic bytes");
    }

    #[test]
    fn test_message_command_strings() {
        let version_msg = Message::Version(VersionMessage {
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
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 8333,
            },
            nonce: 123456789,
            user_agent: "/bitcoin-rust:0.1.0/".to_string(),
            start_height: 0,
            relay: true,
        });

        assert_eq!(MessageCodec::get_command(&version_msg), "version");
        assert_eq!(MessageCodec::get_command(&Message::Verack), "verack");
        assert_eq!(MessageCodec::get_command(&Message::Ping(PingMessage { nonce: 0 })), "ping");
        assert_eq!(MessageCodec::get_command(&Message::Pong(PongMessage { nonce: 0 })), "pong");
    }
}
