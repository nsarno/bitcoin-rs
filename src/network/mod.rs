// P2P networking module
// This module handles peer connections, message serialization, and network protocol

pub mod peer;
pub mod message;
pub mod peer_manager;
pub mod handshake;
pub mod keepalive;
pub mod dns_seeds;
pub mod service;

// Re-export commonly used types
pub use peer_manager::{PeerManager, PeerManagerError, PeerState, PeerStats};
pub use dns_seeds::{DnsSeedResolver, DnsSeedError};
pub use service::{NetworkService, NetworkServiceError};
