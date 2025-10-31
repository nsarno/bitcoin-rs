// Mempool implementation for storing unconfirmed transactions

use bitcoin::{Transaction, Txid, Amount};
use std::collections::HashMap;
use std::time::SystemTime;
use crate::mempool::error::MempoolError;

/// Represents an entry in the mempool with transaction and metadata
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction
    pub tx: Transaction,
    /// Transaction fee (None if fee cannot be calculated yet, e.g., missing UTXO data)
    pub fee: Option<Amount>,
    /// Size of the transaction in bytes when serialized
    pub size: usize,
    /// Time when this transaction was first seen
    pub first_seen: SystemTime,
}

impl MempoolEntry {
    /// Create a new mempool entry from a transaction
    pub fn new(tx: Transaction) -> Self {
        // Calculate serialized size
        let tx_bytes = bitcoin::consensus::encode::serialize(&tx);
        let size = tx_bytes.len();

        Self {
            tx,
            fee: None, // Fee calculation requires UTXO lookups, will be computed later
            size,
            first_seen: SystemTime::now(),
        }
    }

    /// Create a new mempool entry with a specific fee
    pub fn with_fee(tx: Transaction, fee: Amount) -> Self {
        let mut entry = Self::new(tx);
        entry.fee = Some(fee);
        entry
    }

    /// Get the transaction ID
    pub fn txid(&self) -> Txid {
        self.tx.txid()
    }
}

/// Mempool for storing unconfirmed transactions
pub struct Mempool {
    /// Map of transaction ID to mempool entry
    transactions: HashMap<Txid, MempoolEntry>,
    /// Total size of all transactions in bytes
    total_size: usize,
}

impl Mempool {
    /// Create a new empty mempool
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            total_size: 0,
        }
    }

    /// Add a transaction to the mempool
    ///
    /// Returns an error if the transaction is already in the mempool
    pub fn add(&mut self, tx: Transaction) -> Result<(), MempoolError> {
        let txid = tx.txid();

        // Check for duplicates
        if self.transactions.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction(txid));
        }

        // Create entry and update size
        let entry = MempoolEntry::new(tx);
        let entry_size = entry.size;

        self.transactions.insert(txid, entry);
        self.total_size += entry_size;

        Ok(())
    }

    /// Get a mempool entry by transaction ID
    pub fn get(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.transactions.get(txid)
    }

    /// Get a mutable reference to a mempool entry by transaction ID
    pub fn get_mut(&mut self, txid: &Txid) -> Option<&mut MempoolEntry> {
        self.transactions.get_mut(txid)
    }

    /// Remove a transaction from the mempool
    ///
    /// Returns the removed entry if it existed
    pub fn remove(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        if let Some(entry) = self.transactions.remove(txid) {
            self.total_size -= entry.size;
            Some(entry)
        } else {
            None
        }
    }

    /// Check if a transaction exists in the mempool
    pub fn contains(&self, txid: &Txid) -> bool {
        self.transactions.contains_key(txid)
    }

    /// Get the number of transactions in the mempool
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Get the total size of all transactions in the mempool (in bytes)
    pub fn total_size_bytes(&self) -> usize {
        self.total_size
    }

    /// Check if the mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Get an iterator over all mempool entries
    pub fn iter(&self) -> impl Iterator<Item = (&Txid, &MempoolEntry)> {
        self.transactions.iter()
    }

    /// Get a mutable iterator over all mempool entries
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&Txid, &mut MempoolEntry)> {
        self.transactions.iter_mut()
    }

    /// Remove all transactions from the mempool
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.total_size = 0;
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Transaction, TxIn, TxOut, OutPoint, ScriptBuf};
    use bitcoin::transaction::Version;
    use bitcoin::absolute::LockTime;

    fn create_test_transaction() -> Transaction {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

        Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_hex(&format!("01{:02x}", counter % 256)).unwrap(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000000 + counter as u64),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_mempool_entry_creation() {
        let tx = create_test_transaction();
        let entry = MempoolEntry::new(tx.clone());

        assert_eq!(entry.txid(), tx.txid());
        assert_eq!(entry.fee, None);
        assert!(entry.size > 0);
        assert!(entry.first_seen <= SystemTime::now());
    }

    #[test]
    fn test_mempool_entry_with_fee() {
        let tx = create_test_transaction();
        let fee = Amount::from_sat(1000);
        let entry = MempoolEntry::with_fee(tx.clone(), fee);

        assert_eq!(entry.txid(), tx.txid());
        assert_eq!(entry.fee, Some(fee));
        assert!(entry.size > 0);
    }

    #[test]
    fn test_mempool_new() {
        let mempool = Mempool::new();
        assert!(mempool.is_empty());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_size_bytes(), 0);
    }

    #[test]
    fn test_mempool_add() {
        let mut mempool = Mempool::new();
        let tx = create_test_transaction();
        let tx_size = bitcoin::consensus::encode::serialize(&tx).len();

        let result = mempool.add(tx.clone());
        assert!(result.is_ok());
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.total_size_bytes(), tx_size);
        assert!(mempool.contains(&tx.txid()));
    }

    #[test]
    fn test_mempool_duplicate_detection() {
        let mut mempool = Mempool::new();
        let tx = create_test_transaction();
        let txid = tx.txid();

        // Add transaction first time
        assert!(mempool.add(tx.clone()).is_ok());

        // Try to add duplicate
        let result = mempool.add(tx);
        assert!(result.is_err());
        if let Err(MempoolError::DuplicateTransaction(id)) = result {
            assert_eq!(id, txid);
        } else {
            panic!("Expected DuplicateTransaction error");
        }
    }

    #[test]
    fn test_mempool_get() {
        let mut mempool = Mempool::new();
        let tx = create_test_transaction();
        let txid = tx.txid();

        // Transaction not in mempool
        assert!(mempool.get(&txid).is_none());

        // Add transaction
        mempool.add(tx.clone()).unwrap();

        // Now it should be retrievable
        let entry = mempool.get(&txid);
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().txid(), txid);
    }

    #[test]
    fn test_mempool_remove() {
        let mut mempool = Mempool::new();
        let tx = create_test_transaction();
        let txid = tx.txid();
        let tx_size = bitcoin::consensus::encode::serialize(&tx).len();

        // Add transaction
        mempool.add(tx).unwrap();
        assert_eq!(mempool.size(), 1);
        assert_eq!(mempool.total_size_bytes(), tx_size);

        // Remove transaction
        let removed = mempool.remove(&txid);
        assert!(removed.is_some());
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_size_bytes(), 0);
        assert!(!mempool.contains(&txid));

        // Try to remove again (should return None)
        assert!(mempool.remove(&txid).is_none());
    }

    #[test]
    fn test_mempool_iter() {
        let mut mempool = Mempool::new();
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();
        let txid1 = tx1.txid();
        let txid2 = tx2.txid();

        mempool.add(tx1).unwrap();
        mempool.add(tx2).unwrap();

        let mut found_txids: Vec<Txid> = mempool.iter().map(|(txid, _)| *txid).collect();
        found_txids.sort();

        assert_eq!(found_txids.len(), 2);
        assert!(found_txids.contains(&txid1));
        assert!(found_txids.contains(&txid2));
    }

    #[test]
    fn test_mempool_clear() {
        let mut mempool = Mempool::new();
        let tx1 = create_test_transaction();
        let tx2 = create_test_transaction();

        mempool.add(tx1).unwrap();
        mempool.add(tx2).unwrap();
        assert_eq!(mempool.size(), 2);

        mempool.clear();
        assert_eq!(mempool.size(), 0);
        assert_eq!(mempool.total_size_bytes(), 0);
        assert!(mempool.is_empty());
    }

    #[test]
    fn test_mempool_size_tracking() {
        let mut mempool = Mempool::new();
        let tx1 = create_test_transaction();
        let tx1_txid = tx1.txid();
        let tx2 = create_test_transaction();
        let tx1_size = bitcoin::consensus::encode::serialize(&tx1).len();
        let tx2_size = bitcoin::consensus::encode::serialize(&tx2).len();

        mempool.add(tx1).unwrap();
        assert_eq!(mempool.total_size_bytes(), tx1_size);

        mempool.add(tx2).unwrap();
        assert_eq!(mempool.total_size_bytes(), tx1_size + tx2_size);

        mempool.remove(&tx1_txid);
        assert_eq!(mempool.total_size_bytes(), tx2_size);
    }
}

