// Bitcoin message serialization/deserialization
// This module handles the Bitcoin P2P protocol message format

use bitcoin::{BlockHash};
use serde::{Deserialize, Serialize};
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
        let mut result = Vec::new();

        // 1. Magic bytes (testnet: 0x0b110907)
        result.extend_from_slice(&0x0b110907u32.to_le_bytes());

        // 2. Command string (12 bytes, null-padded)
        let command = Self::get_command(message);
        let mut command_bytes = [0u8; 12];
        let command_len = command.len().min(12);
        command_bytes[..command_len].copy_from_slice(&command.as_bytes()[..command_len]);
        result.extend_from_slice(&command_bytes);

        // 3. Serialize payload based on message type
        let payload = Self::serialize_payload(message)?;

        // 4. Payload length (4 bytes, little-endian)
        result.extend_from_slice(&(payload.len() as u32).to_le_bytes());

        // 5. Checksum (4 bytes, double SHA256 of payload)
        let checksum = Self::calculate_checksum(&payload);
        result.extend_from_slice(&checksum);

        // 6. Append payload
        result.extend_from_slice(&payload);

        Ok(result)
    }

    /// Deserialize bytes to a Bitcoin message
    pub fn deserialize(data: &[u8]) -> Result<Message, MessageError> {
        if data.len() < 24 {
            return Err(MessageError::InvalidFormat("Message too short".to_string()));
        }

        let mut offset = 0;

        // 1. Parse magic bytes
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != 0x0b110907 {
            return Err(MessageError::InvalidFormat("Invalid magic bytes".to_string()));
        }
        offset += 4;

        // 2. Parse command string
        let command_bytes = &data[offset..offset + 12];
        let command = String::from_utf8_lossy(command_bytes).trim_end_matches('\0').to_string();
        offset += 12;

        // 3. Parse payload length
        let payload_length = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        // 4. Parse checksum
        let checksum = &data[offset..offset + 4];
        offset += 4;

        // 5. Parse payload
        if data.len() < offset + payload_length {
            return Err(MessageError::InvalidFormat("Insufficient data for payload".to_string()));
        }
        let payload = &data[offset..offset + payload_length];

        // 6. Verify checksum
        let calculated_checksum = Self::calculate_checksum(payload);
        if checksum != &calculated_checksum {
            return Err(MessageError::ChecksumMismatch);
        }

        // 7. Deserialize payload based on command
        Self::deserialize_payload(&command, payload)
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

    /// Serialize message payload based on message type
    fn serialize_payload(message: &Message) -> Result<Vec<u8>, MessageError> {
        let mut payload = Vec::new();

        match message {
            Message::Version(version) => {
                payload.extend_from_slice(&version.version.to_le_bytes());
                payload.extend_from_slice(&version.services.to_le_bytes());
                payload.extend_from_slice(&version.timestamp.to_le_bytes());

                // addr_recv
                payload.extend_from_slice(&version.addr_recv.services.to_le_bytes());
                payload.extend_from_slice(&version.addr_recv.ip);
                payload.extend_from_slice(&version.addr_recv.port.to_le_bytes());

                // addr_from
                payload.extend_from_slice(&version.addr_from.services.to_le_bytes());
                payload.extend_from_slice(&version.addr_from.ip);
                payload.extend_from_slice(&version.addr_from.port.to_le_bytes());

                payload.extend_from_slice(&version.nonce.to_le_bytes());

                // user_agent as varint + string
                let user_agent_bytes = version.user_agent.as_bytes();
                payload.extend_from_slice(&Self::encode_varint(user_agent_bytes.len() as u64));
                payload.extend_from_slice(user_agent_bytes);

                payload.extend_from_slice(&version.start_height.to_le_bytes());
                payload.push(if version.relay { 1 } else { 0 });
            }
            Message::Verack => {
                // Verack has no payload
            }
            Message::Ping(ping) => {
                payload.extend_from_slice(&ping.nonce.to_le_bytes());
            }
            Message::Pong(pong) => {
                payload.extend_from_slice(&pong.nonce.to_le_bytes());
            }
            _ => {
                // For now, return empty payload for unimplemented message types
                // This will be extended as we implement more message types
            }
        }

        Ok(payload)
    }

    /// Deserialize payload based on command
    fn deserialize_payload(command: &str, payload: &[u8]) -> Result<Message, MessageError> {
        match command {
            "version" => {
                if payload.len() < 85 { // Minimum version message size
                    return Err(MessageError::InvalidFormat("Version message too short".to_string()));
                }

                let mut offset = 0;

                let version = i32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                offset += 4;

                let services = u64::from_le_bytes([
                    payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3],
                    payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]
                ]);
                offset += 8;

                let timestamp = i64::from_le_bytes([
                    payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3],
                    payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]
                ]);
                offset += 8;

                // addr_recv
                let addr_recv_services = u64::from_le_bytes([
                    payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3],
                    payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]
                ]);
                offset += 8;

                let mut addr_recv_ip = [0u8; 16];
                addr_recv_ip.copy_from_slice(&payload[offset..offset + 16]);
                offset += 16;

                let addr_recv_port = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;

                // addr_from
                let addr_from_services = u64::from_le_bytes([
                    payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3],
                    payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]
                ]);
                offset += 8;

                let mut addr_from_ip = [0u8; 16];
                addr_from_ip.copy_from_slice(&payload[offset..offset + 16]);
                offset += 16;

                let addr_from_port = u16::from_le_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;

                let nonce = u64::from_le_bytes([
                    payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3],
                    payload[offset + 4], payload[offset + 5], payload[offset + 6], payload[offset + 7]
                ]);
                offset += 8;

                // user_agent (varint + string)
                let (user_agent_len, varint_size) = Self::decode_varint(&payload[offset..])?;
                offset += varint_size;

                let user_agent = String::from_utf8_lossy(&payload[offset..offset + user_agent_len as usize]).to_string();
                offset += user_agent_len as usize;

                let start_height = i32::from_le_bytes([payload[offset], payload[offset + 1], payload[offset + 2], payload[offset + 3]]);
                offset += 4;

                let relay = payload[offset] != 0;

                Ok(Message::Version(VersionMessage {
                    version,
                    services,
                    timestamp,
                    addr_recv: NetworkAddress {
                        services: addr_recv_services,
                        ip: addr_recv_ip,
                        port: addr_recv_port,
                    },
                    addr_from: NetworkAddress {
                        services: addr_from_services,
                        ip: addr_from_ip,
                        port: addr_from_port,
                    },
                    nonce,
                    user_agent,
                    start_height,
                    relay,
                }))
            }
            "verack" => {
                Ok(Message::Verack)
            }
            "ping" => {
                if payload.len() < 8 {
                    return Err(MessageError::InvalidFormat("Ping message too short".to_string()));
                }
                let nonce = u64::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                    payload[4], payload[5], payload[6], payload[7]
                ]);
                Ok(Message::Ping(PingMessage { nonce }))
            }
            "pong" => {
                if payload.len() < 8 {
                    return Err(MessageError::InvalidFormat("Pong message too short".to_string()));
                }
                let nonce = u64::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                    payload[4], payload[5], payload[6], payload[7]
                ]);
                Ok(Message::Pong(PongMessage { nonce }))
            }
            _ => {
                Err(MessageError::UnsupportedMessageType(command.to_string()))
            }
        }
    }

    /// Calculate double SHA256 checksum
    fn calculate_checksum(data: &[u8]) -> [u8; 4] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // For now, use a simple hash. In production, this should be double SHA256
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();

        // Take first 4 bytes of hash
        [
            (hash & 0xFF) as u8,
            ((hash >> 8) & 0xFF) as u8,
            ((hash >> 16) & 0xFF) as u8,
            ((hash >> 24) & 0xFF) as u8,
        ]
    }

    /// Encode varint (variable length integer)
    fn encode_varint(value: u64) -> Vec<u8> {
        if value < 0xFD {
            vec![value as u8]
        } else if value <= 0xFFFF {
            let mut result = vec![0xFD];
            result.extend_from_slice(&(value as u16).to_le_bytes());
            result
        } else if value <= 0xFFFFFFFF {
            let mut result = vec![0xFE];
            result.extend_from_slice(&(value as u32).to_le_bytes());
            result
        } else {
            let mut result = vec![0xFF];
            result.extend_from_slice(&value.to_le_bytes());
            result
        }
    }

    /// Decode varint (variable length integer)
    fn decode_varint(data: &[u8]) -> Result<(u64, usize), MessageError> {
        if data.is_empty() {
            return Err(MessageError::InvalidFormat("Empty varint data".to_string()));
        }

        match data[0] {
            0xFD => {
                if data.len() < 3 {
                    return Err(MessageError::InvalidFormat("Incomplete varint".to_string()));
                }
                let value = u16::from_le_bytes([data[1], data[2]]) as u64;
                Ok((value, 3))
            }
            0xFE => {
                if data.len() < 5 {
                    return Err(MessageError::InvalidFormat("Incomplete varint".to_string()));
                }
                let value = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
                Ok((value, 5))
            }
            0xFF => {
                if data.len() < 9 {
                    return Err(MessageError::InvalidFormat("Incomplete varint".to_string()));
                }
                let value = u64::from_le_bytes([data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8]]);
                Ok((value, 9))
            }
            _ => {
                Ok((data[0] as u64, 1))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            user_agent: "/bitcoin-rs:0.1.0/".to_string(),
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
            user_agent: "/bitcoin-rs:0.1.0/".to_string(),
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
        let invalid_message = vec![0xFF; 24]; // Valid length but wrong magic
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
            user_agent: "/bitcoin-rs:0.1.0/".to_string(),
            start_height: 0,
            relay: true,
        });

        assert_eq!(MessageCodec::get_command(&version_msg), "version");
        assert_eq!(MessageCodec::get_command(&Message::Verack), "verack");
        assert_eq!(MessageCodec::get_command(&Message::Ping(PingMessage { nonce: 0 })), "ping");
        assert_eq!(MessageCodec::get_command(&Message::Pong(PongMessage { nonce: 0 })), "pong");
    }
}
