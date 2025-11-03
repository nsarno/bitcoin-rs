// P2P networking module
// This module handles peer connections, message serialization, and network protocol

pub mod peer;
pub mod message;
pub mod peer_manager;
pub mod handshake;
pub mod keepalive;
pub mod dns_seeds;
pub mod service;
pub mod relay;
pub mod relay_service;

// Re-export commonly used types
pub use peer_manager::{PeerManager, PeerManagerError};
pub use peer::{PeerConnection, PeerError, ConnectionState, ConnectionQuality, PeerStats};
pub use dns_seeds::{DnsSeedResolver, DnsSeedError};
pub use service::{NetworkService, NetworkServiceError};
pub use relay::TransactionRelayManager;
pub use relay_service::{TransactionRelayService, RelayAction, RelayServiceError, RelayResult};
