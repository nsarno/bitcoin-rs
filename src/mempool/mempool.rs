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

    /// Calculate fee rate (fee per byte)
    ///
    /// Returns the fee rate in satoshis per byte, or None if fee is not set or size is zero.
    pub fn calculate_fee_rate(&self) -> Option<u64> {
        match (self.fee, self.size) {
            (Some(fee), size) if size > 0 => Some(fee.to_sat() / size as u64),
            _ => None,
        }
    }
}

impl PartialEq for MempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.txid() == other.txid()
    }
}

impl Eq for MempoolEntry {}

impl PartialOrd for MempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MempoolEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Primary sort: fee rate (descending - higher fee rate = higher priority)
        match (self.calculate_fee_rate(), other.calculate_fee_rate()) {
            (Some(self_rate), Some(other_rate)) => {
                match other_rate.cmp(&self_rate) {
                    std::cmp::Ordering::Equal => {
                        // Secondary sort: transaction ID for determinism
                        self.txid().cmp(&other.txid())
                    }
                    ord => ord,
                }
            }
            (Some(_), None) => std::cmp::Ordering::Less, // self has fee, other doesn't - self is higher priority
            (None, Some(_)) => std::cmp::Ordering::Greater, // other has fee, self doesn't - other is higher priority
            (None, None) => {
                // Both have no fee - sort by transaction ID for determinism
                self.txid().cmp(&other.txid())
            }
        }
    }
}

/// Mempool for storing unconfirmed transactions
pub struct Mempool {
    /// Map of transaction ID to mempool entry
    transactions: HashMap<Txid, MempoolEntry>,
    /// Total size of all transactions in bytes
    total_size: usize,
    /// Maximum mempool size in bytes (default: 300MB)
    max_size: usize,
}

impl Mempool {
    /// Create a new empty mempool with default size limit (300MB)
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            total_size: 0,
            max_size: 300 * 1024 * 1024, // 300MB default
        }
    }

    /// Create a new mempool with a custom maximum size
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            transactions: HashMap::new(),
            total_size: 0,
            max_size,
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

    /// Add a validated transaction to the mempool with its calculated fee
    ///
    /// This method is used when a transaction has already been validated and its fee calculated.
    /// It will evict low-priority transactions if the mempool exceeds its size limit.
    pub fn add_validated(&mut self, entry: MempoolEntry) -> Result<(), MempoolError> {
        let txid = entry.txid();

        // Check for duplicates
        if self.transactions.contains_key(&txid) {
            return Err(MempoolError::DuplicateTransaction(txid));
        }

        let entry_size = entry.size;

        // Check if adding this transaction would exceed the limit
        if self.total_size + entry_size > self.max_size {
            // Try to evict low-priority transactions to make room
            self.evict_low_priority(self.total_size + entry_size - self.max_size)?;
        }

        // If still too large, reject
        if self.total_size + entry_size > self.max_size {
            return Err(MempoolError::MempoolFull);
        }

        self.transactions.insert(txid, entry);
        self.total_size += entry_size;

        Ok(())
    }

    /// Get transactions sorted by priority (fee rate)
    ///
    /// Returns an iterator over transactions sorted by fee rate (highest first).
    pub fn get_by_priority(&self) -> impl Iterator<Item = (&Txid, &MempoolEntry)> {
        let mut entries: Vec<_> = self.transactions.iter().collect();
        // Sort by reverse order (since Ord is implemented for descending fee rate)
        entries.sort_by(|(_, a), (_, b)| b.cmp(a));
        entries.into_iter()
    }

    /// Get the transaction with the highest fee rate
    ///
    /// Returns None if the mempool is empty.
    pub fn get_highest_fee_rate(&self) -> Option<(&Txid, &MempoolEntry)> {
        self.transactions.iter()
            .max_by(|(_, a), (_, b)| b.cmp(a))
    }

    /// Evict low-priority transactions to make room
    ///
    /// Removes transactions with the lowest fee rates until at least `bytes_to_free` bytes
    /// have been freed. If it's not possible to free enough space, returns an error.
    pub fn evict_low_priority(&mut self, bytes_to_free: usize) -> Result<(), MempoolError> {
        if bytes_to_free == 0 {
            return Ok(());
        }

        // Collect all entries with their fee rates
        let mut entries: Vec<(Txid, MempoolEntry, Option<u64>)> = self.transactions
            .drain()
            .map(|(txid, entry)| {
                let fee_rate = entry.calculate_fee_rate();
                (txid, entry, fee_rate)
            })
            .collect();

        // Sort by fee rate (lowest first for eviction)
        entries.sort_by(|a, b| {
            match (a.2, b.2) {
                (Some(a_rate), Some(b_rate)) => a_rate.cmp(&b_rate),
                (Some(_), None) => std::cmp::Ordering::Less, // a has fee, b doesn't - a is higher priority
                (None, Some(_)) => std::cmp::Ordering::Greater, // b has fee, a doesn't - b is higher priority
                (None, None) => a.0.cmp(&b.0), // Both have no fee - sort by txid for determinism
            }
        });

        // Evict low-priority transactions until we've freed enough space
        let mut freed = 0;
        let mut to_keep = Vec::new();

        for (txid, entry, _) in entries.into_iter().rev() {
            if freed >= bytes_to_free {
                // We've freed enough space, keep this one
                to_keep.push((txid, entry));
            } else {
                // Evict this transaction
                freed += entry.size;
            }
        }

        // Check if we freed enough space
        if freed < bytes_to_free {
            // Not enough space could be freed - restore what we can
            for (txid, entry) in to_keep {
                let entry_size = entry.size;
                self.transactions.insert(txid, entry);
                self.total_size += entry_size;
            }
            return Err(MempoolError::MempoolFull);
        }

        // Restore the transactions we're keeping
        for (txid, entry) in to_keep {
            let entry_size = entry.size;
            self.transactions.insert(txid, entry);
            self.total_size += entry_size;
        }

        // Update total size (subtract what we freed)
        self.total_size -= freed;

        Ok(())
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

