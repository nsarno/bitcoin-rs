// UTXO (Unspent Transaction Output) set management
// This module handles tracking and validation of unspent transaction outputs

use bitcoin::{OutPoint, Amount, ScriptBuf};
use bitcoin::hashes::Hash;
use crate::storage::{BlockDatabase, DatabaseError};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtxoError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("UTXO not found: {0}")]
    UtxoNotFound(OutPoint),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Invalid UTXO data")]
    InvalidData,
}

/// Represents a single unspent transaction output
#[derive(Debug, Clone, PartialEq)]
pub struct UtxoEntry {
    /// The output value in satoshis
    pub value: Amount,
    /// The script that must be satisfied to spend this output
    pub script_pubkey: ScriptBuf,
    /// Block height when this output was created
    pub height: u32,
    /// Whether this output is from a coinbase transaction
    pub is_coinbase: bool,
}

impl UtxoEntry {
    /// Create a new UTXO entry
    pub fn new(value: Amount, script_pubkey: ScriptBuf, height: u32, is_coinbase: bool) -> Self {
        Self {
            value,
            script_pubkey,
            height,
            is_coinbase,
        }
    }

    /// Check if this UTXO is mature enough to be spent
    pub fn is_mature(&self, current_height: u32, coinbase_maturity: u32) -> bool {
        if !self.is_coinbase {
            true // Non-coinbase outputs are immediately spendable
        } else {
            current_height >= self.height + coinbase_maturity
        }
    }

    /// Serialize UTXO entry to bytes for database storage
    pub fn serialize(&self) -> Result<Vec<u8>, UtxoError> {
        let mut data = Vec::new();

        // Height (4 bytes, little endian)
        data.extend_from_slice(&self.height.to_le_bytes());

        // Value (8 bytes, little endian)
        data.extend_from_slice(&self.value.to_sat().to_le_bytes());

        // Script length (varint)
        let script_bytes = self.script_pubkey.as_bytes();
        let script_len = script_bytes.len();
        if script_len > 0xFFFF {
            return Err(UtxoError::Serialization("Script too long".to_string()));
        }

        // Simple varint encoding for script length (max 2 bytes)
        if script_len < 0x80 {
            data.push(script_len as u8);
        } else {
            data.push(0x80 | (script_len & 0x7F) as u8);
            data.push((script_len >> 7) as u8);
        }

        // Script bytes
        data.extend_from_slice(script_bytes);

        // Is coinbase flag (1 byte)
        data.push(if self.is_coinbase { 1 } else { 0 });

        Ok(data)
    }

    /// Deserialize UTXO entry from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, UtxoError> {
        if data.len() < 13 { // Minimum: height(4) + value(8) + script_len(1) + is_coinbase(1)
            return Err(UtxoError::InvalidData);
        }

        let mut offset = 0;

        // Height (4 bytes)
        let height = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Value (8 bytes)
        let value = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
        ]);
        offset += 8;

        // Script length (varint)
        let script_len = if data[offset] < 0x80 {
            let len = data[offset] as usize;
            offset += 1;
            len
        } else {
            let len = ((data[offset] & 0x7F) as usize) | ((data[offset + 1] as usize) << 7);
            offset += 2;
            len
        };

        // Script bytes
        if offset + script_len + 1 > data.len() {
            return Err(UtxoError::InvalidData);
        }
        let script_bytes = &data[offset..offset + script_len];
        offset += script_len;

        // Is coinbase flag
        let is_coinbase = data[offset] != 0;

        Ok(UtxoEntry {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes.to_vec()),
            height,
            is_coinbase,
        })
    }
}

/// High-level interface for UTXO set operations
pub struct UtxoSet {
    database: Arc<BlockDatabase>,
}

impl UtxoSet {
    /// Create a new UTXO set
    pub fn new(database: Arc<BlockDatabase>) -> Self {
        Self { database }
    }

    /// Get a UTXO by its outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, UtxoError> {
        let key = self.outpoint_to_key(outpoint);

        match self.database.db().get_cf(
            self.database.db().cf_handle("utxos").unwrap(),
            &key
        ).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))? {
            Some(data) => {
                let entry = UtxoEntry::deserialize(&data)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Check if a UTXO exists
    pub fn has_utxo(&self, outpoint: &OutPoint) -> Result<bool, UtxoError> {
        let key = self.outpoint_to_key(outpoint);

        match self.database.db().get_cf(
            self.database.db().cf_handle("utxos").unwrap(),
            &key
        ).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Store a new UTXO
    pub fn store_utxo(&self, outpoint: &OutPoint, entry: &UtxoEntry) -> Result<(), UtxoError> {
        let key = self.outpoint_to_key(outpoint);
        let data = entry.serialize()?;

        self.database.db().put_cf(
            self.database.db().cf_handle("utxos").unwrap(),
            &key,
            &data
        ).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))?;

        Ok(())
    }

    /// Remove a UTXO (mark as spent)
    pub fn remove_utxo(&self, outpoint: &OutPoint) -> Result<(), UtxoError> {
        let key = self.outpoint_to_key(outpoint);

        self.database.db().delete_cf(
            self.database.db().cf_handle("utxos").unwrap(),
            &key
        ).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))?;

        Ok(())
    }

    /// Apply a block to the UTXO set
    pub fn apply_block(&self, block: &bitcoin::Block, height: u32) -> Result<(), UtxoError> {
        use rocksdb::WriteBatch;

        let mut batch = WriteBatch::default();
        let utxos_cf = self.database.db().cf_handle("utxos").unwrap();

        // Process each transaction in the block
        for (_tx_index, tx) in block.txdata.iter().enumerate() {
            let is_coinbase = tx.is_coinbase();

            // Remove spent inputs (except for coinbase transactions)
            if !is_coinbase {
                for input in &tx.input {
                    let key = self.outpoint_to_key(&input.previous_output);
                    batch.delete_cf(utxos_cf, &key);
                }
            }

            // Add new outputs
            for (vout, output) in tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(tx.txid(), vout as u32);
                let entry = UtxoEntry::new(
                    output.value,
                    output.script_pubkey.clone(),
                    height,
                    is_coinbase,
                );

                let key = self.outpoint_to_key(&outpoint);
                let data = entry.serialize()?;
                batch.put_cf(utxos_cf, &key, &data);
            }
        }

        self.database.db().write(batch).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))?;
        Ok(())
    }

    /// Undo a block from the UTXO set (for reorgs)
    pub fn undo_block(&self, block: &bitcoin::Block) -> Result<(), UtxoError> {
        use rocksdb::WriteBatch;

        let mut batch = WriteBatch::default();
        let utxos_cf = self.database.db().cf_handle("utxos").unwrap();

        // Process transactions in reverse order
        for tx in block.txdata.iter().rev() {
            let is_coinbase = tx.is_coinbase();

            // Remove outputs that were added
            for (vout, _) in tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(tx.txid(), vout as u32);
                let key = self.outpoint_to_key(&outpoint);
                batch.delete_cf(utxos_cf, &key);
            }

            // Restore spent inputs (except for coinbase transactions)
            if !is_coinbase {
                // Note: This is a simplified implementation
                // In a full implementation, we'd need to store the previous UTXO state
                // For now, we'll just remove the outputs and leave inputs as spent
            }
        }

        self.database.db().write(batch).map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))?;
        Ok(())
    }

    /// Get UTXO statistics
    pub fn get_stats(&self) -> Result<UtxoStats, UtxoError> {
        let mut total_utxos = 0;
        let mut total_value = 0u64;
        let mut coinbase_utxos = 0;

        // Iterate through all UTXOs
        let utxos_cf = self.database.db().cf_handle("utxos").unwrap();
        let iter = self.database.db().iterator_cf(utxos_cf, rocksdb::IteratorMode::Start);

        for result in iter {
            let (_, value) = result.map_err(|e| UtxoError::Database(DatabaseError::RocksDB(e)))?;
            if let Ok(entry) = UtxoEntry::deserialize(&value) {
                total_utxos += 1;
                total_value += entry.value.to_sat();
                if entry.is_coinbase {
                    coinbase_utxos += 1;
                }
            }
        }

        Ok(UtxoStats {
            total_utxos,
            total_value,
            coinbase_utxos,
        })
    }

    /// Convert OutPoint to database key
    fn outpoint_to_key(&self, outpoint: &OutPoint) -> Vec<u8> {
        let mut key = Vec::with_capacity(36); // 32 bytes txid + 4 bytes vout
        key.extend_from_slice(&outpoint.txid.to_byte_array());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());
        key
    }

    /// Get the database reference for advanced operations
    pub fn database(&self) -> &Arc<BlockDatabase> {
        &self.database
    }
}

/// Statistics about the UTXO set
#[derive(Debug, Clone)]
pub struct UtxoStats {
    pub total_utxos: usize,
    pub total_value: u64,
    pub coinbase_utxos: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Transaction, TxIn, TxOut, OutPoint, ScriptBuf, Txid};
    use bitcoin::transaction::Version;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use tempfile::TempDir;
    use std::str::FromStr;

    fn create_test_utxo_entry() -> UtxoEntry {
        UtxoEntry::new(
            Amount::from_sat(1000000), // 0.01 BTC
            ScriptBuf::from_hex("76a9141234567890abcdef1234567890abcdef1234567890ab88ac").unwrap(),
            100,
            false,
        )
    }

    fn create_test_coinbase_utxo_entry() -> UtxoEntry {
        UtxoEntry::new(
            Amount::from_sat(5000000000), // 50 BTC
            ScriptBuf::new(),
            0,
            true,
        )
    }

    #[test]
    fn test_utxo_entry_serialization() {
        let entry = create_test_utxo_entry();
        let serialized = entry.serialize().unwrap();
        let deserialized = UtxoEntry::deserialize(&serialized).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_coinbase_utxo_entry_serialization() {
        let entry = create_test_coinbase_utxo_entry();
        let serialized = entry.serialize().unwrap();
        let deserialized = UtxoEntry::deserialize(&serialized).unwrap();

        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_utxo_maturity() {
        let coinbase_entry = create_test_coinbase_utxo_entry();
        let regular_entry = create_test_utxo_entry();

        // Regular UTXO is immediately mature
        assert!(regular_entry.is_mature(100, 100));

        // Coinbase UTXO needs 100 blocks maturity
        assert!(!coinbase_entry.is_mature(50, 100)); // Not mature yet
        assert!(coinbase_entry.is_mature(100, 100)); // Just mature
        assert!(coinbase_entry.is_mature(200, 100)); // Well mature
    }

    #[test]
    fn test_utxo_set_operations() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(BlockDatabase::open(temp_dir.path()).unwrap());
        let utxo_set = UtxoSet::new(db);

        let outpoint = OutPoint::new(
            Txid::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap(),
            0
        );
        let entry = create_test_utxo_entry();

        // Initially no UTXO
        assert!(!utxo_set.has_utxo(&outpoint).unwrap());

        // Store UTXO
        utxo_set.store_utxo(&outpoint, &entry).unwrap();

        // Now it exists
        assert!(utxo_set.has_utxo(&outpoint).unwrap());
        let retrieved = utxo_set.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(retrieved, entry);

        // Remove UTXO
        utxo_set.remove_utxo(&outpoint).unwrap();

        // Now it's gone
        assert!(!utxo_set.has_utxo(&outpoint).unwrap());
        assert!(utxo_set.get_utxo(&outpoint).unwrap().is_none());
    }

    #[test]
    fn test_apply_block() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(BlockDatabase::open(temp_dir.path()).unwrap());
        let utxo_set = UtxoSet::new(db);

        // Create a test block with one transaction
        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_hex("0101").unwrap(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(1),
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1234567890,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![tx],
        };

        // Apply the block
        utxo_set.apply_block(&block, 0).unwrap();

        // Check that the coinbase output was added
        let outpoint = OutPoint::new(block.txdata[0].txid(), 0);
        assert!(utxo_set.has_utxo(&outpoint).unwrap());

        let entry = utxo_set.get_utxo(&outpoint).unwrap().unwrap();
        assert_eq!(entry.value, Amount::from_sat(5000000000));
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn test_utxo_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(BlockDatabase::open(temp_dir.path()).unwrap());
        let utxo_set = UtxoSet::new(db);

        // Add some UTXOs
        let outpoint1 = OutPoint::new(
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
            0
        );
        let outpoint2 = OutPoint::new(
            Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
            0
        );

        let regular_entry = create_test_utxo_entry();
        let coinbase_entry = create_test_coinbase_utxo_entry();

        utxo_set.store_utxo(&outpoint1, &regular_entry).unwrap();
        utxo_set.store_utxo(&outpoint2, &coinbase_entry).unwrap();

        let stats = utxo_set.get_stats().unwrap();
        assert_eq!(stats.total_utxos, 2);
        assert_eq!(stats.total_value, 1000000 + 5000000000);
        assert_eq!(stats.coinbase_utxos, 1);
    }
}
