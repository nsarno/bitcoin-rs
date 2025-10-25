// Bitcoin P2P keepalive implementation
// This module handles ping/pong messages for connection keepalive

use crate::network::message::{Message, PingMessage, PongMessage};
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeepaliveError {
    #[error("Keepalive timeout")]
    Timeout,
    #[error("Invalid pong nonce")]
    InvalidPongNonce,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Keepalive manager for maintaining peer connections
#[derive(Debug)]
pub struct KeepaliveManager {
    pending_pings: HashMap<u64, SystemTime>,
    last_pong_time: Option<SystemTime>,
    ping_interval: Duration,
    pong_timeout: Duration,
    last_ping_time: Option<SystemTime>,
}

impl KeepaliveManager {
    /// Create a new keepalive manager with default settings
    pub fn new() -> Self {
        Self {
            pending_pings: HashMap::new(),
            last_pong_time: None,
            ping_interval: Duration::from_secs(30), // 30 seconds
            pong_timeout: Duration::from_secs(60),   // 60 seconds
            last_ping_time: None,
        }
    }

    /// Create a keepalive manager with custom settings
    pub fn with_settings(ping_interval: Duration, pong_timeout: Duration) -> Self {
        Self {
            pending_pings: HashMap::new(),
            last_pong_time: None,
            ping_interval,
            pong_timeout,
            last_ping_time: None,
        }
    }

    /// Generate a new ping message
    pub fn generate_ping(&mut self) -> Message {
        let nonce = rand::random::<u64>();
        let now = SystemTime::now();

        // Store the ping with timestamp
        self.pending_pings.insert(nonce, now);
        self.last_ping_time = Some(now);

        Message::Ping(PingMessage { nonce })
    }

    /// Process an incoming pong message
    pub fn process_pong(&mut self, pong: &PongMessage) -> Result<(), KeepaliveError> {
        let now = SystemTime::now();

        if self.pending_pings.contains_key(&pong.nonce) {
            // Remove the pending ping
            self.pending_pings.remove(&pong.nonce);
            self.last_pong_time = Some(now);
            Ok(())
        } else {
            Err(KeepaliveError::InvalidPongNonce)
        }
    }

    /// Check if we should send a ping (based on interval)
    pub fn should_send_ping(&self) -> bool {
        match self.last_pong_time {
            Some(last_pong) => {
                SystemTime::now()
                    .duration_since(last_pong)
                    .unwrap_or_default() >= self.ping_interval
            }
            None => {
                // No pong received yet, check if we've sent a ping recently
                match self.last_ping_time {
                    Some(last_ping) => {
                        SystemTime::now()
                            .duration_since(last_ping)
                            .unwrap_or_default() >= self.ping_interval
                    }
                    None => true, // Never sent a ping, send one now
                }
            }
        }
    }

    /// Check if we have timed out pings
    pub fn has_timed_out_pings(&self) -> bool {
        let now = SystemTime::now();
        self.pending_pings.values().any(|&ping_time| {
            now.duration_since(ping_time).unwrap_or_default() >= self.pong_timeout
        })
    }

    /// Get the number of pending pings
    pub fn pending_ping_count(&self) -> usize {
        self.pending_pings.len()
    }

    /// Clear timed out pings
    pub fn clear_timed_out_pings(&mut self) -> usize {
        let now = SystemTime::now();
        let initial_count = self.pending_pings.len();

        self.pending_pings.retain(|_, &mut ping_time| {
            now.duration_since(ping_time).unwrap_or_default() < self.pong_timeout
        });

        initial_count - self.pending_pings.len()
    }

    /// Get the time since last pong
    pub fn time_since_last_pong(&self) -> Option<Duration> {
        self.last_pong_time.map(|last_pong| {
            SystemTime::now()
                .duration_since(last_pong)
                .unwrap_or_default()
        })
    }

    /// Get the time since last ping
    pub fn time_since_last_ping(&self) -> Option<Duration> {
        self.last_ping_time.map(|last_ping| {
            SystemTime::now()
                .duration_since(last_ping)
                .unwrap_or_default()
        })
    }

    /// Check if the connection is alive (has recent pong or no timeout)
    pub fn is_connection_alive(&self) -> bool {
        match self.last_pong_time {
            Some(last_pong) => {
                let time_since_pong = SystemTime::now()
                    .duration_since(last_pong)
                    .unwrap_or_default();
                time_since_pong < self.pong_timeout
            }
            None => {
                // No pong received yet, check if we haven't been waiting too long
                match self.last_ping_time {
                    Some(last_ping) => {
                        let time_since_ping = SystemTime::now()
                            .duration_since(last_ping)
                            .unwrap_or_default();
                        time_since_ping < self.pong_timeout
                    }
                    None => true, // Haven't sent any pings yet
                }
            }
        }
    }

    /// Get keepalive statistics
    pub fn get_stats(&self) -> KeepaliveStats {
        KeepaliveStats {
            pending_pings: self.pending_ping_count(),
            last_pong_time: self.last_pong_time,
            last_ping_time: self.last_ping_time,
            is_alive: self.is_connection_alive(),
        }
    }

    /// Reset the keepalive manager
    pub fn reset(&mut self) {
        self.pending_pings.clear();
        self.last_pong_time = None;
        self.last_ping_time = None;
    }
}

/// Keepalive statistics
#[derive(Debug, Clone)]
pub struct KeepaliveStats {
    pub pending_pings: usize,
    pub last_pong_time: Option<SystemTime>,
    pub last_ping_time: Option<SystemTime>,
    pub is_alive: bool,
}

impl Default for KeepaliveManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_manager_creation() {
        let manager = KeepaliveManager::new();
        assert_eq!(manager.pending_ping_count(), 0);
        assert!(manager.last_pong_time.is_none());
        assert!(manager.last_ping_time.is_none());
        assert_eq!(manager.ping_interval, Duration::from_secs(30));
        assert_eq!(manager.pong_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_keepalive_manager_custom_settings() {
        let manager = KeepaliveManager::with_settings(
            Duration::from_secs(10),
            Duration::from_secs(20)
        );
        assert_eq!(manager.ping_interval, Duration::from_secs(10));
        assert_eq!(manager.pong_timeout, Duration::from_secs(20));
    }

    #[test]
    fn test_ping_generation() {
        let mut manager = KeepaliveManager::new();
        assert_eq!(manager.pending_ping_count(), 0);

        let ping_msg = manager.generate_ping();
        assert_eq!(manager.pending_ping_count(), 1);
        assert!(manager.last_ping_time.is_some());

        if let Message::Ping(ping) = ping_msg {
            assert!(manager.pending_pings.contains_key(&ping.nonce));
        } else {
            panic!("Expected ping message");
        }
    }

    #[test]
    fn test_pong_processing() {
        let mut manager = KeepaliveManager::new();

        // Generate a ping
        let ping_msg = manager.generate_ping();
        let ping_nonce = if let Message::Ping(ping) = ping_msg {
            ping.nonce
        } else {
            panic!("Expected ping message");
        };

        assert_eq!(manager.pending_ping_count(), 1);
        assert!(manager.last_pong_time.is_none());

        // Process matching pong
        let pong = PongMessage { nonce: ping_nonce };
        let result = manager.process_pong(&pong);
        assert!(result.is_ok());

        assert_eq!(manager.pending_ping_count(), 0);
        assert!(manager.last_pong_time.is_some());
    }

    #[test]
    fn test_pong_processing_wrong_nonce() {
        let mut manager = KeepaliveManager::new();

        // Generate a ping
        let _ping_msg = manager.generate_ping();
        assert_eq!(manager.pending_ping_count(), 1);

        // Process pong with wrong nonce
        let wrong_pong = PongMessage { nonce: 999999 };
        let result = manager.process_pong(&wrong_pong);
        assert!(result.is_err());
        assert_eq!(manager.pending_ping_count(), 1);
    }

    #[test]
    fn test_should_send_ping() {
        let mut manager = KeepaliveManager::new();

        // Initially should send ping
        assert!(manager.should_send_ping());

        // Generate a ping
        let _ping_msg = manager.generate_ping();

        // Should not send ping immediately after generating one
        assert!(!manager.should_send_ping());
    }

    #[test]
    fn test_connection_alive() {
        let mut manager = KeepaliveManager::new();

        // Initially should be alive (no pings sent yet)
        assert!(manager.is_connection_alive());

        // Generate a ping
        let _ping_msg = manager.generate_ping();

        // Should still be alive (just sent ping)
        assert!(manager.is_connection_alive());
    }

    #[test]
    fn test_clear_timed_out_pings() {
        let mut manager = KeepaliveManager::new();

        // Generate a ping
        let _ping_msg = manager.generate_ping();
        assert_eq!(manager.pending_ping_count(), 1);

        // Clear timed out pings (none should be timed out in this test)
        let cleared = manager.clear_timed_out_pings();
        assert_eq!(cleared, 0);
        assert_eq!(manager.pending_ping_count(), 1);
    }

    #[test]
    fn test_reset() {
        let mut manager = KeepaliveManager::new();

        // Generate a ping
        let _ping_msg = manager.generate_ping();
        assert_eq!(manager.pending_ping_count(), 1);
        assert!(manager.last_ping_time.is_some());

        // Reset
        manager.reset();
        assert_eq!(manager.pending_ping_count(), 0);
        assert!(manager.last_ping_time.is_none());
        assert!(manager.last_pong_time.is_none());
    }

    #[test]
    fn test_get_stats() {
        let mut manager = KeepaliveManager::new();

        let stats = manager.get_stats();
        assert_eq!(stats.pending_pings, 0);
        assert!(stats.last_pong_time.is_none());
        assert!(stats.last_ping_time.is_none());
        assert!(stats.is_alive);

        // Generate a ping
        let _ping_msg = manager.generate_ping();
        let stats = manager.get_stats();
        assert_eq!(stats.pending_pings, 1);
        assert!(stats.last_ping_time.is_some());
        assert!(stats.is_alive);
    }
}
