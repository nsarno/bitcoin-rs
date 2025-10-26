// Blockchain storage and validation
// This module provides the high-level blockchain interface

use bitcoin::{Block, BlockHash};
use bitcoin::block::Header;
use crate::storage::{BlockDatabase, DatabaseError};
use crate::blockchain::block_index::{BlockIndex, BlockIndexError, BlockIndexEntry};
use crate::blockchain::validation::{ValidationError, validate_block_pow, validate_header_pow};
use crate::consensus::ConsensusParams;
use std::path::Path;
use thiserror::Error;

pub mod block_index;
pub mod validation;

#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Block index error: {0}")]
    BlockIndex(#[from] BlockIndexError),
    #[error("Block not found: {0}")]
    BlockNotFound(BlockHash),
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
}

/// High-level blockchain interface combining database and index
pub struct Blockchain {
    index: BlockIndex,
    consensus_params: ConsensusParams,
}

impl Blockchain {
    /// Create a new blockchain instance with default testnet consensus parameters
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self, BlockchainError> {
        Self::new_with_consensus(data_dir, ConsensusParams::testnet())
    }

    /// Create a new blockchain instance with specific consensus parameters
    pub fn new_with_consensus<P: AsRef<Path>>(data_dir: P, consensus_params: ConsensusParams) -> Result<Self, BlockchainError> {
        let db = BlockDatabase::open(data_dir)?;
        let index = BlockIndex::new(db)?;

        Ok(Blockchain {
            index,
            consensus_params,
        })
    }

    /// Add a new block to the blockchain
    pub fn add_block(&mut self, block: &Block) -> Result<(), BlockchainError> {
        // Validate proof-of-work before accepting the block
        validate_block_pow(block, &self.consensus_params)?;

        // Store the full block in the database
        self.index.database().store_block(block)?;

        // Add the header to the index
        self.index.add_block(block.header)?;

        Ok(())
    }

    /// Add a new block to the blockchain without PoW validation (for testing)
    #[cfg(test)]
    pub fn add_block_without_pow(&mut self, block: &Block) -> Result<(), BlockchainError> {
        // Store the full block in the database
        self.index.database().store_block(block)?;

        // Add the header to the index
        self.index.add_block(block.header)?;

        Ok(())
    }

    /// Add only a block header (for headers-first sync)
    pub fn add_header(&mut self, header: &Header) -> Result<(), BlockchainError> {
        // Validate proof-of-work before accepting the header
        validate_header_pow(header, &self.consensus_params)?;

        self.index.add_block(header.clone())?;
        Ok(())
    }

    /// Add only a block header without PoW validation (for testing)
    #[cfg(test)]
    pub fn add_header_without_pow(&mut self, header: &Header) -> Result<(), BlockchainError> {
        self.index.add_block(header.clone())?;
        Ok(())
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, BlockchainError> {
        self.index.database().get_block(hash).map_err(Into::into)
    }

    /// Get a block header by hash
    pub fn get_header(&self, hash: &BlockHash) -> Result<Option<Header>, BlockchainError> {
        self.index.database().get_header(hash).map_err(Into::into)
    }

    /// Get a block by height
    pub fn get_block_by_height(&self, height: u32) -> Result<Option<Block>, BlockchainError> {
        self.index.database().get_block_by_height(height).map_err(Into::into)
    }

    /// Get block index entry by hash
    pub fn get_block_entry(&self, hash: &BlockHash) -> Option<&BlockIndexEntry> {
        self.index.get_by_hash(hash)
    }

    /// Get block index entry by height
    pub fn get_block_entry_by_height(&self, height: u32) -> Option<&BlockIndexEntry> {
        self.index.get_by_height(height)
    }

    /// Get the best block (chain tip)
    pub fn get_best_block(&self) -> Result<Option<Block>, BlockchainError> {
        if let Some(tip_entry) = self.index.get_best_tip() {
            self.get_block(&tip_entry.hash)
        } else {
            Ok(None)
        }
    }

    /// Get the best block header (chain tip)
    pub fn get_best_header(&self) -> Result<Option<Header>, BlockchainError> {
        if let Some(tip_entry) = self.index.get_best_tip() {
            Ok(Some(tip_entry.header.clone()))
        } else {
            Ok(None)
        }
    }

    /// Get the current chain height
    pub fn get_height(&self) -> u32 {
        self.index.get_best_height()
    }

    /// Get the current chain tip hash
    pub fn get_tip_hash(&self) -> Option<BlockHash> {
        self.index.get_best_tip().map(|entry| entry.hash)
    }

    /// Get an ancestor block at a specific height
    pub fn get_ancestor(&self, hash: &BlockHash, height: u32) -> Option<&BlockIndexEntry> {
        self.index.get_ancestor(hash, height)
    }

    /// Get blockchain statistics
    pub fn get_stats(&self) -> Result<std::collections::HashMap<String, String>, BlockchainError> {
        let mut stats = self.index.get_stats();

        // Add database stats
        let db_stats = self.index.database().get_stats()?;
        stats.extend(db_stats);

        Ok(stats)
    }

    /// Get the database reference for direct access (advanced usage)
    pub fn database(&self) -> &BlockDatabase {
        self.index.database()
    }

    /// Get the block index reference for direct access (advanced usage)
    pub fn index(&self) -> &BlockIndex {
        &self.index
    }

    /// Get the consensus parameters for this blockchain
    pub fn consensus_params(&self) -> &ConsensusParams {
        &self.consensus_params
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
        let header = Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };

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
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        Block {
            header,
            txdata: vec![tx],
        }
    }

    #[test]
    fn test_blockchain_creation() {
        let temp_dir = TempDir::new().unwrap();
        let blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        assert_eq!(blockchain.get_height(), 0);
        assert!(blockchain.get_tip_hash().is_none());

        // Check that it uses testnet consensus by default
        assert_eq!(blockchain.consensus_params().network_name, "testnet");
    }

    #[test]
    fn test_add_and_retrieve_block() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        let block = create_test_block();
        let block_hash = block.block_hash();

        // Add block without PoW validation (for testing)
        blockchain.add_block_without_pow(&block).expect("Failed to add block");

        // Retrieve block
        let retrieved_block = blockchain.get_block(&block_hash).expect("Failed to retrieve block");
        assert!(retrieved_block.is_some());
        assert_eq!(retrieved_block.unwrap().block_hash(), block_hash);

        // Check that it's the best block
        let best_block = blockchain.get_best_block().expect("Failed to get best block");
        assert!(best_block.is_some());
        assert_eq!(best_block.unwrap().block_hash(), block_hash);

        // Check height
        assert_eq!(blockchain.get_height(), 0);
    }

    #[test]
    fn test_pow_validation_integration() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        // Create a block with valid target (but not valid PoW)
        let block = create_test_block();

        // This should succeed using the test method that bypasses PoW
        blockchain.add_block_without_pow(&block).expect("Failed to add valid block");

        // Create a block with invalid target
        let mut invalid_block = create_test_block();
        invalid_block.header.bits = bitcoin::CompactTarget::from_consensus(0x1bffffff); // Invalid target

        // This should fail with validation error when using the real method
        let result = blockchain.add_block(&invalid_block);
        assert!(matches!(result, Err(BlockchainError::Validation(_))));
    }

    #[test]
    fn test_add_header_only() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        let block = create_test_block();
        let header = block.header;
        let header_hash = header.block_hash();

        // Add header only without PoW validation (for testing)
        blockchain.add_header_without_pow(&header).expect("Failed to add header");

        // Retrieve header
        let retrieved_header = blockchain.get_header(&header_hash).expect("Failed to retrieve header");
        assert!(retrieved_header.is_some());
        assert_eq!(retrieved_header.unwrap().block_hash(), header_hash);

        // Check that it's the best header
        let best_header = blockchain.get_best_header().expect("Failed to get best header");
        assert!(best_header.is_some());
        assert_eq!(best_header.unwrap().block_hash(), header_hash);
    }

    #[test]
    fn test_header_pow_validation() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        // Create a header with valid PoW
        let block = create_test_block();
        let header = block.header;

        // This should succeed (using test method that bypasses PoW)
        blockchain.add_header_without_pow(&header).expect("Failed to add valid header");

        // Create a header with invalid PoW
        let mut invalid_header = header;
        invalid_header.bits = bitcoin::CompactTarget::from_consensus(0x1cffffff); // Invalid target

        // This should fail with validation error when using the real method
        let result = blockchain.add_header(&invalid_header);
        assert!(matches!(result, Err(BlockchainError::Validation(_))));
    }

    #[test]
    fn test_block_chain_operations() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        // Create a chain of blocks
        let mut blocks = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();

        for i in 0..3 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            let block_hash = block.block_hash();
            blocks.push(block_hash);

            blockchain.add_block_without_pow(&block).expect("Failed to add block");
            prev_hash = block_hash;
        }

        // Check chain structure
        assert_eq!(blockchain.get_height(), 2); // 0-indexed, so 3 blocks = height 2

        // Check individual blocks
        for (i, &block_hash) in blocks.iter().enumerate() {
            let block_entry = blockchain.get_block_entry(&block_hash).expect("Block should be indexed");
            assert_eq!(block_entry.height, i as u32);
        }

        // Check height lookups
        for (i, &expected_hash) in blocks.iter().enumerate() {
            let block_entry = blockchain.get_block_entry_by_height(i as u32).expect("Should find block by height");
            assert_eq!(block_entry.hash, expected_hash);
        }
    }

    #[test]
    fn test_ancestor_lookup() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        // Create a chain of 5 blocks
        let mut blocks = Vec::new();
        let mut prev_hash = BlockHash::all_zeros();

        for i in 0..5 {
            let mut block = create_test_block();
            block.header.prev_blockhash = prev_hash;
            block.header.nonce = i;
            let block_hash = block.block_hash();
            blocks.push(block_hash);

            blockchain.add_block_without_pow(&block).expect("Failed to add block");
            prev_hash = block_hash;
        }

        // Test ancestor lookups
        let tip_hash = blocks[4];
        let ancestor_at_2 = blockchain.get_ancestor(&tip_hash, 2).expect("Should find ancestor at height 2");
        assert_eq!(ancestor_at_2.hash, blocks[2]);

        let ancestor_at_0 = blockchain.get_ancestor(&tip_hash, 0).expect("Should find ancestor at height 0");
        assert_eq!(ancestor_at_0.hash, blocks[0]);
    }

    #[test]
    fn test_blockchain_stats() {
        let temp_dir = TempDir::new().unwrap();
        let mut blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        // Add some blocks
        let block = create_test_block();
        blockchain.add_block_without_pow(&block).expect("Failed to add block");

        // Get stats
        let stats = blockchain.get_stats().expect("Failed to get stats");
        assert!(stats.contains_key("total_blocks"));
        assert!(stats.contains_key("best_height"));
    }

    #[test]
    fn test_nonexistent_block() {
        let temp_dir = TempDir::new().unwrap();
        let blockchain = Blockchain::new(temp_dir.path()).expect("Failed to create blockchain");

        let nonexistent_hash = BlockHash::all_zeros();
        let result = blockchain.get_block(&nonexistent_hash).expect("Failed to query blockchain");
        assert!(result.is_none());
    }
}
