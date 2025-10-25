// Database implementation using RocksDB
// This module provides persistent storage for blockchain data

use bitcoin::{Block, BlockHash};
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("RocksDB error: {0}")]
    RocksDB(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Block not found: {0}")]
    BlockNotFound(BlockHash),
    #[error("Header not found: {0}")]
    HeaderNotFound(BlockHash),
    #[error("Invalid data format")]
    InvalidData,
}

/// Chain metadata stored in the database
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub tip_hash: BlockHash,
    pub tip_height: u32,
    pub best_chain_work: u64,
}

impl Default for ChainMetadata {
    fn default() -> Self {
        Self {
            tip_hash: BlockHash::all_zeros(),
            tip_height: 0,
            best_chain_work: 0,
        }
    }
}

/// Database for storing blockchain data
pub struct BlockDatabase {
    db: DB,
}

impl BlockDatabase {
    /// Open or create a new database at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DatabaseError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Define column families
        let column_families = vec![
            "blocks",
            "headers",
            "height_index",
            "prev_hash_index",
            "metadata",
        ];

        let db = DB::open_cf(&opts, path, &column_families)?;
        Ok(BlockDatabase { db })
    }

    /// Close the database
    pub fn close(self) -> Result<(), DatabaseError> {
        // RocksDB is closed automatically when DB is dropped
        Ok(())
    }

    /// Store a full block and update all indices
    pub fn store_block(&self, block: &Block) -> Result<(), DatabaseError> {
        let block_hash = block.block_hash();
        let header = &block.header;

        // Serialize block using bitcoin crate's consensus encoding
        let block_data = bitcoin::consensus::encode::serialize(block);
        let header_data = bitcoin::consensus::encode::serialize(header);

        let mut batch = WriteBatch::default();

        // Store full block
        batch.put_cf(self.db.cf_handle("blocks").unwrap(), block_hash.as_byte_array(), &block_data);

        // Store header
        batch.put_cf(self.db.cf_handle("headers").unwrap(), block_hash.as_byte_array(), &header_data);

        // Update previous hash index
        batch.put_cf(self.db.cf_handle("prev_hash_index").unwrap(), header.prev_blockhash.as_byte_array(), block_hash.as_byte_array());

        self.db.write(batch)?;
        Ok(())
    }

    /// Store only a block header
    pub fn store_header(&self, header: &Header) -> Result<(), DatabaseError> {
        let header_hash = header.block_hash();
        let header_data = bitcoin::consensus::encode::serialize(header);

        let mut batch = WriteBatch::default();
        batch.put_cf(self.db.cf_handle("headers").unwrap(), header_hash.as_byte_array(), &header_data);

        // Update previous hash index
        batch.put_cf(self.db.cf_handle("prev_hash_index").unwrap(), header.prev_blockhash.as_byte_array(), header_hash.as_byte_array());

        self.db.write(batch)?;
        Ok(())
    }

    /// Retrieve a full block by hash
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, DatabaseError> {
        match self.db.get_cf(self.db.cf_handle("blocks").unwrap(), hash.as_byte_array())? {
            Some(data) => {
                let block = bitcoin::consensus::encode::deserialize(&data)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Retrieve a block header by hash
    pub fn get_header(&self, hash: &BlockHash) -> Result<Option<Header>, DatabaseError> {
        match self.db.get_cf(self.db.cf_handle("headers").unwrap(), hash.as_byte_array())? {
            Some(data) => {
                let header = bitcoin::consensus::encode::deserialize(&data)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Retrieve a block by height (requires height index to be maintained)
    pub fn get_block_by_height(&self, height: u32) -> Result<Option<Block>, DatabaseError> {
        // First get the hash for this height
        let height_key = height.to_le_bytes();
        match self.db.get_cf(self.db.cf_handle("height_index").unwrap(), &height_key)? {
            Some(hash_data) => {
                if hash_data.len() != 32 {
                    return Err(DatabaseError::InvalidData);
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&hash_data);
                let block_hash = BlockHash::from_byte_array(hash_bytes);
                self.get_block(&block_hash)
            }
            None => Ok(None),
        }
    }

    /// Update the height index for a block
    pub fn update_height_index(&self, height: u32, block_hash: &BlockHash) -> Result<(), DatabaseError> {
        let height_key = height.to_le_bytes();
        self.db.put_cf(self.db.cf_handle("height_index").unwrap(), &height_key, block_hash.as_byte_array())?;
        Ok(())
    }

    /// Get the current chain tip metadata
    pub fn get_chain_tip(&self) -> Result<ChainMetadata, DatabaseError> {
        let tip_hash_key = b"tip_hash";
        let tip_height_key = b"tip_height";
        let best_work_key = b"best_chain_work";

        let tip_hash = match self.db.get_cf(self.db.cf_handle("metadata").unwrap(), tip_hash_key)? {
            Some(data) => {
                if data.len() != 32 {
                    return Err(DatabaseError::InvalidData);
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data);
                BlockHash::from_byte_array(hash_bytes)
            }
            None => BlockHash::all_zeros(),
        };

        let tip_height = match self.db.get_cf(self.db.cf_handle("metadata").unwrap(), tip_height_key)? {
            Some(data) => {
                if data.len() != 4 {
                    return Err(DatabaseError::InvalidData);
                }
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            }
            None => 0,
        };

        let best_chain_work = match self.db.get_cf(self.db.cf_handle("metadata").unwrap(), best_work_key)? {
            Some(data) => {
                if data.len() != 8 {
                    return Err(DatabaseError::InvalidData);
                }
                u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ])
            }
            None => 0,
        };

        Ok(ChainMetadata {
            tip_hash,
            tip_height,
            best_chain_work,
        })
    }

    /// Update the chain tip metadata
    pub fn update_chain_tip(&self, hash: &BlockHash, height: u32, work: u64) -> Result<(), DatabaseError> {
        let mut batch = WriteBatch::default();

        batch.put_cf(self.db.cf_handle("metadata").unwrap(), b"tip_hash", hash.as_byte_array());
        batch.put_cf(self.db.cf_handle("metadata").unwrap(), b"tip_height", &height.to_le_bytes());
        batch.put_cf(self.db.cf_handle("metadata").unwrap(), b"best_chain_work", &work.to_le_bytes());

        self.db.write(batch)?;
        Ok(())
    }

    /// Get all blocks that have a specific previous hash (for chain traversal)
    pub fn get_blocks_by_prev_hash(&self, prev_hash: &BlockHash) -> Result<Vec<BlockHash>, DatabaseError> {
        let mut hashes = Vec::new();

        // Get the direct child
        if let Some(child_hash_data) = self.db.get_cf(self.db.cf_handle("prev_hash_index").unwrap(), prev_hash.as_byte_array())? {
            if child_hash_data.len() == 32 {
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&child_hash_data);
                hashes.push(BlockHash::from_byte_array(hash_bytes));
            }
        }

        Ok(hashes)
    }

    /// Get database statistics
    pub fn get_stats(&self) -> Result<HashMap<String, String>, DatabaseError> {
        let mut stats = HashMap::new();

        // Get basic database stats
        if let Ok(property_value) = self.db.property_value(rocksdb::properties::STATS) {
            if let Some(value) = property_value {
                stats.insert("rocksdb.stats".to_string(), value);
            }
        }

        Ok(stats)
    }
}

impl Drop for BlockDatabase {
    fn drop(&mut self) {
        // RocksDB will be closed automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Block, Transaction, TxIn, TxOut, OutPoint, ScriptBuf};
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use tempfile::TempDir;

    fn create_test_block() -> Block {
        // Create a simple test block
        let header = Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };

        // Create a simple transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(5000000000), // 50 BTC in satoshis
                script_pubkey: ScriptBuf::new(),
            }],
        };

        Block {
            header,
            txdata: vec![tx],
        }
    }

    #[test]
    fn test_database_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        assert!(db_path.exists());
    }

    #[test]
    fn test_store_and_retrieve_block() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();
        let block_hash = block.block_hash();

        // Store the block
        db.store_block(&block).expect("Failed to store block");

        // Retrieve the block
        let retrieved_block = db.get_block(&block_hash).expect("Failed to retrieve block");
        assert!(retrieved_block.is_some());

        let retrieved_block = retrieved_block.unwrap();
        assert_eq!(retrieved_block.block_hash(), block_hash);
        assert_eq!(retrieved_block.txdata.len(), block.txdata.len());
    }

    #[test]
    fn test_store_and_retrieve_header() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();
        let header = block.header;
        let header_hash = header.block_hash();

        // Store the header
        db.store_header(&header).expect("Failed to store header");

        // Retrieve the header
        let retrieved_header = db.get_header(&header_hash).expect("Failed to retrieve header");
        assert!(retrieved_header.is_some());

        let retrieved_header = retrieved_header.unwrap();
        assert_eq!(retrieved_header.block_hash(), header_hash);
        assert_eq!(retrieved_header.version, header.version);
    }

    #[test]
    fn test_height_index() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();
        let block_hash = block.block_hash();

        // Store the block first
        db.store_block(&block).expect("Failed to store block");

        // Update height index
        db.update_height_index(100, &block_hash).expect("Failed to update height index");

        // Retrieve block by height
        let retrieved_block = db.get_block_by_height(100).expect("Failed to retrieve block by height");
        assert!(retrieved_block.is_some());
        assert_eq!(retrieved_block.unwrap().block_hash(), block_hash);
    }

    #[test]
    fn test_chain_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();
        let block_hash = block.block_hash();

        // Update chain tip
        db.update_chain_tip(&block_hash, 100, 1000).expect("Failed to update chain tip");

        // Retrieve chain metadata
        let metadata = db.get_chain_tip().expect("Failed to get chain tip");
        assert_eq!(metadata.tip_hash, block_hash);
        assert_eq!(metadata.tip_height, 100);
        assert_eq!(metadata.best_chain_work, 1000);
    }

    #[test]
    fn test_prev_hash_index() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();
        let block_hash = block.block_hash();
        let prev_hash = block.header.prev_blockhash;

        // Store the block (this should update the prev_hash index)
        db.store_block(&block).expect("Failed to store block");

        // Get blocks by previous hash
        let child_hashes = db.get_blocks_by_prev_hash(&prev_hash).expect("Failed to get blocks by prev hash");
        assert_eq!(child_hashes.len(), 1);
        assert_eq!(child_hashes[0], block_hash);
    }

    #[test]
    fn test_database_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");

        // Get stats (should not fail even with empty database)
        let stats = db.get_stats().expect("Failed to get database stats");
        assert!(stats.is_empty() || stats.contains_key("rocksdb.stats"));
    }

    #[test]
    fn test_nonexistent_block() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let nonexistent_hash = BlockHash::all_zeros();

        // Try to retrieve non-existent block
        let result = db.get_block(&nonexistent_hash).expect("Failed to query database");
        assert!(result.is_none());
    }

    #[test]
    fn test_serialization_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let block = create_test_block();

        // Store the block
        db.store_block(&block).expect("Failed to store block");

        // Retrieve and verify it's the same
        let retrieved_block = db.get_block(&block.block_hash()).expect("Failed to retrieve block").unwrap();

        // Verify key properties are preserved
        assert_eq!(retrieved_block.header.version, block.header.version);
        assert_eq!(retrieved_block.header.prev_blockhash, block.header.prev_blockhash);
        assert_eq!(retrieved_block.txdata.len(), block.txdata.len());
    }
}
