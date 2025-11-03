// Transaction relay service
// This module orchestrates transaction relay: processing inv/getdata/tx messages,
// validating transactions, adding them to mempool, and propagating them to peers

use bitcoin::{Txid, Transaction};
use bitcoin::hashes::Hash;
use crate::network::message::{Message, InvMessage, GetDataMessage, TxMessage, InventoryVector};
use crate::network::message::inventory_type::MSG_TX;
use crate::network::relay::TransactionRelayManager;
use crate::mempool::{Mempool, MempoolEntry};
use crate::mempool::validation::validate_transaction_for_mempool;
use crate::blockchain::utxo::UtxoSet;
use crate::consensus::ConsensusParams;
use crate::mempool::error::MempoolError;
use std::time::SystemTime;
use tracing::{debug, warn, error};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayServiceError {
    #[error("Mempool error: {0}")]
    Mempool(#[from] MempoolError),
    #[error("Transaction validation failed: {0}")]
    Validation(String),
    #[error("Transaction not found in mempool")]
    TransactionNotFound,
}

/// Result type for relay service operations
pub type RelayResult<T> = Result<T, RelayServiceError>;

/// Represents an action to take after processing a message
#[derive(Debug, Clone)]
pub enum RelayAction {
    /// Send a message to a specific peer
    SendToPeer {
        peer_id: String,
        message: Message,
    },
    /// Send messages to multiple peers
    Broadcast {
        peer_ids: Vec<String>,
        message: Message,
    },
    /// No action needed
    None,
}

/// Transaction relay service that coordinates transaction propagation
pub struct TransactionRelayService {
    relay_manager: TransactionRelayManager,
    mempool: Mempool,
    utxo_set: UtxoSet,
    consensus_params: ConsensusParams,
    /// Function to get current chain height
    get_height: Box<dyn Fn() -> u32 + Send + Sync>,
}

impl TransactionRelayService {
    /// Create a new transaction relay service
    pub fn new(
        mempool: Mempool,
        utxo_set: UtxoSet,
        consensus_params: ConsensusParams,
        get_height: Box<dyn Fn() -> u32 + Send + Sync>,
    ) -> Self {
        Self {
            relay_manager: TransactionRelayManager::new(),
            mempool,
            utxo_set,
            consensus_params,
            get_height,
        }
    }

    /// Get a reference to the relay manager
    pub fn relay_manager(&self) -> &TransactionRelayManager {
        &self.relay_manager
    }

    /// Get a mutable reference to the relay manager
    pub fn relay_manager_mut(&mut self) -> &mut TransactionRelayManager {
        &mut self.relay_manager
    }

    /// Get a reference to the mempool
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Get a mutable reference to the mempool
    pub fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    /// Process an `inv` message from a peer
    ///
    /// Filters for transactions we don't have, records them in peer inventory,
    /// and returns actions to send `getdata` requests for unknown transactions.
    pub fn process_inv(&mut self, peer_id: &str, inv_msg: &InvMessage) -> RelayResult<Vec<RelayAction>> {
        let mut actions = Vec::new();
        let mut requested_txids = Vec::new();

        // Filter inventory for transaction types and check which ones we need
        for inv_vec in &inv_msg.inventory {
            if inv_vec.inv_type == MSG_TX {
                let txid = Txid::from_slice(&inv_vec.hash)
                    .map_err(|_| RelayServiceError::Validation("Invalid transaction hash".to_string()))?;
                // Record that peer knows about this transaction
                self.relay_manager.record_peer_transaction(peer_id, &txid);

                // Check if we already have this transaction in mempool
                if !self.mempool.contains(&txid) && !self.relay_manager.is_request_pending(&txid) {
                    // Request this transaction
                    requested_txids.push(txid);
                    self.relay_manager.record_transaction_request(peer_id, &txid);
                }
            }
        }

        // If we have transactions to request, send a getdata message
        if !requested_txids.is_empty() {
            let inventory: Vec<InventoryVector> = requested_txids
                .iter()
                .map(|txid| InventoryVector {
                    inv_type: MSG_TX,
                    hash: *txid.as_ref(),
                })
                .collect();

            let getdata_msg = Message::GetData(GetDataMessage { inventory });
            actions.push(RelayAction::SendToPeer {
                peer_id: peer_id.to_string(),
                message: getdata_msg,
            });

            debug!("Requesting {} transactions from peer {}", requested_txids.len(), peer_id);
        }

        Ok(actions)
    }

    /// Process a `getdata` message from a peer
    ///
    /// Looks up requested transactions in mempool and returns actions to send
    /// `tx` messages for transactions we have.
    pub fn process_getdata(&mut self, peer_id: &str, getdata_msg: &GetDataMessage) -> RelayResult<Vec<RelayAction>> {
        let mut actions = Vec::new();

        // Filter for transaction requests and send what we have
        for inv_vec in &getdata_msg.inventory {
            if inv_vec.inv_type == MSG_TX {
                let txid = Txid::from_slice(&inv_vec.hash)
                    .map_err(|_| RelayServiceError::Validation("Invalid transaction hash".to_string()))?;
                // Record that peer requested this transaction
                self.relay_manager.record_transaction_request(peer_id, &txid);

                // Check if we have this transaction in mempool
                if let Some(entry) = self.mempool.get(&txid) {
                    // Send the transaction
                    let tx_msg = Message::Tx(TxMessage {
                        tx: entry.tx.clone(),
                    });
                    actions.push(RelayAction::SendToPeer {
                        peer_id: peer_id.to_string(),
                        message: tx_msg,
                    });
                    debug!("Sending transaction {} to peer {}", txid, peer_id);
                } else {
                    debug!("Peer {} requested transaction {} but we don't have it", peer_id, txid);
                }
            }
        }

        Ok(actions)
    }

    /// Process a `tx` message from a peer
    ///
    /// Validates the transaction, adds it to mempool if valid, and returns
    /// actions to relay it to other peers that don't know about it.
    pub fn process_tx(&mut self, peer_id: &str, tx_msg: &TxMessage) -> RelayResult<Vec<RelayAction>> {
        let tx = &tx_msg.tx;
        let txid = tx.txid();

        // Record that this peer knows about the transaction
        self.relay_manager.record_peer_transaction(peer_id, &txid);

        // Check if we already have this transaction
        if self.mempool.contains(&txid) {
            debug!("Received duplicate transaction {} from peer {}", txid, peer_id);
            self.relay_manager.fulfill_transaction_request(&txid);
            return Ok(vec![RelayAction::None]);
        }

        // Validate the transaction
        let chain_height = (self.get_height)();
        let chain_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let fee = match validate_transaction_for_mempool(
            tx,
            &self.utxo_set,
            chain_height,
            chain_time,
            &self.consensus_params,
        ) {
            Ok(fee) => fee,
            Err(e) => {
                warn!("Transaction {} from peer {} failed validation: {}", txid, peer_id, e);
                self.relay_manager.fulfill_transaction_request(&txid);
                return Err(RelayServiceError::Validation(e.to_string()));
            }
        };

        // Create mempool entry with calculated fee
        let entry = MempoolEntry::with_fee(tx.clone(), fee);

        // Add to mempool
        match self.mempool.add_validated(entry) {
            Ok(_) => {
                debug!("Added transaction {} to mempool with fee {}", txid, fee.to_sat());
            }
            Err(MempoolError::DuplicateTransaction(_)) => {
                // Race condition: another peer sent it first
                debug!("Transaction {} already in mempool (race condition)", txid);
            }
            Err(e) => {
                warn!("Failed to add transaction {} to mempool: {}", txid, e);
                self.relay_manager.fulfill_transaction_request(&txid);
                return Err(RelayServiceError::Mempool(e));
            }
        }

        // Fulfill any pending requests for this transaction
        self.relay_manager.fulfill_transaction_request(&txid);

        // Relay to other peers that don't know about this transaction
        // Exclude the peer that sent it to us
        let peers_to_relay = self.relay_manager.get_peers_unknown_transaction(&txid, &[peer_id]);

        let mut actions = Vec::new();
        if !peers_to_relay.is_empty() {
            // Create inv message for relay
            let inv_msg = Message::Inv(InvMessage {
                inventory: vec![InventoryVector {
                    inv_type: MSG_TX,
                    hash: *txid.as_ref(),
                }],
            });

            // Record that we're about to tell these peers about the transaction
            for peer in &peers_to_relay {
                self.relay_manager.record_peer_transaction(peer, &txid);
            }

            actions.push(RelayAction::Broadcast {
                peer_ids: peers_to_relay,
                message: inv_msg,
            });

            debug!("Relaying transaction {} to {} peers", txid, actions[0].peer_count());
        }

        Ok(actions)
    }

    /// Notify the service that a peer has disconnected
    pub fn peer_disconnected(&mut self, peer_id: &str) {
        self.relay_manager.remove_peer(peer_id);
        debug!("Removed peer {} from relay manager", peer_id);
    }

    /// Clean up timed-out transaction requests
    pub fn cleanup_timed_out_requests(&mut self) -> Vec<Txid> {
        self.relay_manager.cleanup_timed_out_requests()
    }

    /// Announce a transaction to all peers (for locally created transactions)
    ///
    /// This should be called when the node creates or receives a transaction
    /// from an external source (like RPC).
    pub fn announce_transaction(&mut self, tx: &Transaction) -> RelayResult<Vec<RelayAction>> {
        let txid = tx.txid();

        // Check if already in mempool
        if self.mempool.contains(&txid) {
            debug!("Transaction {} already in mempool, skipping announcement", txid);
            return Ok(vec![RelayAction::None]);
        }

        // Validate the transaction first
        let chain_height = (self.get_height)();
        let chain_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let fee = validate_transaction_for_mempool(
            tx,
            &self.utxo_set,
            chain_height,
            chain_time,
            &self.consensus_params,
        )?;

        // Add to mempool
        let entry = MempoolEntry::with_fee(tx.clone(), fee);
        self.mempool.add_validated(entry)?;

        // Announce to all peers
        let all_peers = self.relay_manager.get_all_peer_ids();

        if !all_peers.is_empty() {
            let inv_msg = Message::Inv(InvMessage {
                inventory: vec![InventoryVector {
                    inv_type: MSG_TX,
                    hash: *txid.as_ref(),
                }],
            });

            // Record that all peers will be told about this transaction
            for peer in &all_peers {
                self.relay_manager.record_peer_transaction(peer, &txid);
            }

            Ok(vec![RelayAction::Broadcast {
                peer_ids: all_peers,
                message: inv_msg,
            }])
        } else {
            Ok(vec![RelayAction::None])
        }
    }
}

// Helper implementation for RelayAction
impl RelayAction {
    /// Get the number of peers this action will affect
    pub fn peer_count(&self) -> usize {
        match self {
            RelayAction::SendToPeer { .. } => 1,
            RelayAction::Broadcast { peer_ids, .. } => peer_ids.len(),
            RelayAction::None => 0,
        }
    }
}

