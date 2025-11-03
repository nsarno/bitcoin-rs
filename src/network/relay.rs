// Transaction relay management
// This module handles tracking which transactions peers know about and managing transaction request queues

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, Duration};

/// Tracks transaction inventory and request queue for relay management
pub struct TransactionRelayManager {
    /// Map of peer connection ID to set of transaction IDs the peer knows about
    peer_inventories: HashMap<String, HashSet<Txid>>,
    /// Map of transaction ID to set of peer IDs that have requested it
    pending_requests: HashMap<Txid, HashSet<String>>,
    /// Map of transaction ID to when it was requested (for timeout tracking)
    request_times: HashMap<Txid, SystemTime>,
    /// Maximum time to wait for a transaction before timing out (default: 2 minutes)
    request_timeout: Duration,
}

impl TransactionRelayManager {
    /// Create a new transaction relay manager
    pub fn new() -> Self {
        Self {
            peer_inventories: HashMap::new(),
            pending_requests: HashMap::new(),
            request_times: HashMap::new(),
            request_timeout: Duration::from_secs(120), // 2 minutes default
        }
    }

    /// Create a new transaction relay manager with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            peer_inventories: HashMap::new(),
            pending_requests: HashMap::new(),
            request_times: HashMap::new(),
            request_timeout: timeout,
        }
    }

    /// Record that a peer knows about a transaction (e.g., after receiving inv or tx)
    pub fn record_peer_transaction(&mut self, peer_id: &str, txid: &Txid) {
        self.peer_inventories
            .entry(peer_id.to_string())
            .or_insert_with(HashSet::new)
            .insert(*txid);
    }

    /// Record that multiple peers know about multiple transactions
    pub fn record_peer_transactions(&mut self, peer_id: &str, txids: &[Txid]) {
        let peer_set = self.peer_inventories
            .entry(peer_id.to_string())
            .or_insert_with(HashSet::new);
        for txid in txids {
            peer_set.insert(*txid);
        }
    }

    /// Check if a peer knows about a specific transaction
    pub fn peer_knows_transaction(&self, peer_id: &str, txid: &Txid) -> bool {
        self.peer_inventories
            .get(peer_id)
            .map(|inventory| inventory.contains(txid))
            .unwrap_or(false)
    }

    /// Get all transactions that a peer knows about
    pub fn get_peer_inventory(&self, peer_id: &str) -> Option<&HashSet<Txid>> {
        self.peer_inventories.get(peer_id)
    }

    /// Mark that a peer has requested a transaction (via getdata)
    pub fn record_transaction_request(&mut self, peer_id: &str, txid: &Txid) {
        self.pending_requests
            .entry(*txid)
            .or_insert_with(HashSet::new)
            .insert(peer_id.to_string());
        self.request_times.insert(*txid, SystemTime::now());
    }

    /// Mark that a transaction request has been fulfilled (transaction received)
    pub fn fulfill_transaction_request(&mut self, txid: &Txid) {
        self.pending_requests.remove(txid);
        self.request_times.remove(txid);
    }

    /// Check if a transaction is currently being requested
    pub fn is_request_pending(&self, txid: &Txid) -> bool {
        self.pending_requests.contains_key(txid)
    }

    /// Get all peers that have requested a specific transaction
    pub fn get_requesting_peers(&self, txid: &Txid) -> Option<&HashSet<String>> {
        self.pending_requests.get(txid)
    }

    /// Remove a peer's inventory (when peer disconnects)
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peer_inventories.remove(peer_id);

        // Clean up any pending requests from this peer
        let mut to_remove = Vec::new();
        for (txid, peers) in &mut self.pending_requests {
            peers.remove(peer_id);
            if peers.is_empty() {
                to_remove.push(*txid);
            }
        }
        for txid in to_remove {
            self.pending_requests.remove(&txid);
            self.request_times.remove(&txid);
        }
    }

    /// Clean up timed-out requests
    pub fn cleanup_timed_out_requests(&mut self) -> Vec<Txid> {
        let now = SystemTime::now();
        let mut timed_out = Vec::new();

        let to_remove: Vec<Txid> = self.request_times
            .iter()
            .filter_map(|(txid, request_time)| {
                if let Ok(elapsed) = now.duration_since(*request_time) {
                    if elapsed >= self.request_timeout {
                        Some(*txid)
                    } else {
                        None
                    }
                } else {
                    Some(*txid) // SystemTime error, assume timed out
                }
            })
            .collect();

        for txid in &to_remove {
            timed_out.push(*txid);
            self.pending_requests.remove(txid);
            self.request_times.remove(txid);
        }

        timed_out
    }

    /// Get peers that don't know about a transaction (for relay targeting)
    /// Returns a list of peer IDs that should receive an inv message for this transaction
    pub fn get_peers_unknown_transaction(&self, txid: &Txid, exclude_peers: &[&str]) -> Vec<String> {
        let exclude_set: HashSet<&str> = exclude_peers.iter().copied().collect();

        self.peer_inventories
            .iter()
            .filter_map(|(peer_id, inventory)| {
                // Skip excluded peers
                if exclude_set.contains(peer_id.as_str()) {
                    return None;
                }
                // Include peer if it doesn't know about this transaction
                if !inventory.contains(txid) {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get the number of peers tracking transactions
    pub fn peer_count(&self) -> usize {
        self.peer_inventories.len()
    }

    /// Get the number of pending requests
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Get all peer IDs that are currently tracked
    pub fn get_all_peer_ids(&self) -> Vec<String> {
        self.peer_inventories.keys().cloned().collect()
    }
}

impl Default for TransactionRelayManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_manager_creation() {
        let manager = TransactionRelayManager::new();
        assert_eq!(manager.peer_count(), 0);
        assert_eq!(manager.pending_request_count(), 0);
    }

    #[test]
    fn test_record_peer_transaction() {
        let mut manager = TransactionRelayManager::new();
        let txid = Txid::from_slice(&[0u8; 32]).unwrap();

        assert!(!manager.peer_knows_transaction("peer1", &txid));

        manager.record_peer_transaction("peer1", &txid);

        assert!(manager.peer_knows_transaction("peer1", &txid));
        assert!(!manager.peer_knows_transaction("peer2", &txid));
    }

    #[test]
    fn test_record_multiple_transactions() {
        let mut manager = TransactionRelayManager::new();
        let txid1 = Txid::from_slice(&[1u8; 32]).unwrap();
        let txid2 = Txid::from_slice(&[2u8; 32]).unwrap();
        let txids = vec![txid1, txid2];

        manager.record_peer_transactions("peer1", &txids);

        assert!(manager.peer_knows_transaction("peer1", &txid1));
        assert!(manager.peer_knows_transaction("peer1", &txid2));
    }

    #[test]
    fn test_transaction_request() {
        let mut manager = TransactionRelayManager::new();
        let txid = Txid::from_slice(&[0u8; 32]).unwrap();

        assert!(!manager.is_request_pending(&txid));

        manager.record_transaction_request("peer1", &txid);

        assert!(manager.is_request_pending(&txid));
        assert!(manager.get_requesting_peers(&txid).unwrap().contains("peer1"));

        manager.fulfill_transaction_request(&txid);

        assert!(!manager.is_request_pending(&txid));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = TransactionRelayManager::new();
        let txid = Txid::from_slice(&[0u8; 32]).unwrap();

        manager.record_peer_transaction("peer1", &txid);
        manager.record_transaction_request("peer1", &txid);

        assert!(manager.peer_knows_transaction("peer1", &txid));
        assert!(manager.is_request_pending(&txid));

        manager.remove_peer("peer1");

        assert!(!manager.peer_knows_transaction("peer1", &txid));
        assert!(!manager.is_request_pending(&txid));
    }

    #[test]
    fn test_get_peers_unknown_transaction() {
        let mut manager = TransactionRelayManager::new();
        let txid = Txid::from_slice(&[0u8; 32]).unwrap();

        manager.record_peer_transaction("peer1", &txid);
        // peer2 and peer3 don't know about the transaction

        let unknown_peers = manager.get_peers_unknown_transaction(&txid, &[]);
        assert_eq!(unknown_peers.len(), 0); // No peers registered yet

        // Add peer2 and peer3 without the transaction
        manager.record_peer_transaction("peer2", &Txid::from_slice(&[1u8; 32]).unwrap());
        manager.record_peer_transaction("peer3", &Txid::from_slice(&[2u8; 32]).unwrap());

        let unknown_peers = manager.get_peers_unknown_transaction(&txid, &[]);
        assert_eq!(unknown_peers.len(), 2);
        assert!(unknown_peers.contains(&"peer2".to_string()));
        assert!(unknown_peers.contains(&"peer3".to_string()));
        assert!(!unknown_peers.contains(&"peer1".to_string()));

        // Test exclusion
        let unknown_peers = manager.get_peers_unknown_transaction(&txid, &["peer2"]);
        assert_eq!(unknown_peers.len(), 1);
        assert!(!unknown_peers.contains(&"peer2".to_string()));
        assert!(unknown_peers.contains(&"peer3".to_string()));
    }
}

