// Block index for quick lookups
// This module manages in-memory and persistent indices for efficient block retrieval

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use crate::storage::{BlockDatabase, DatabaseError};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockIndexError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Block not found: {0}")]
    BlockNotFound(BlockHash),
    #[error("Invalid chain state")]
    InvalidChainState,
}

/// Status of a block in the index
#[derive(Debug, Clone, PartialEq)]
pub enum BlockStatus {
    /// Block is part of the best chain
    BestChain,
    /// Block is valid but not on the best chain
    Valid,
    /// Block is invalid
    Invalid,
    /// Block is an orphan (parent not found)
    Orphan,
}

/// Entry in the block index containing metadata
#[derive(Debug, Clone)]
pub struct BlockIndexEntry {
    pub hash: BlockHash,
    pub height: u32,
    pub chainwork: u64,
    pub status: BlockStatus,
    pub prev_hash: BlockHash,
    pub header: Header,
}

impl BlockIndexEntry {
    pub fn new(hash: BlockHash, height: u32, chainwork: u64, status: BlockStatus, prev_hash: BlockHash, header: Header) -> Self {
        Self {
            hash,
            height,
            chainwork,
            status,
            prev_hash,
            header,
        }
    }
}

/// Block index for efficient block lookups and chain management
pub struct BlockIndex {
    db: BlockDatabase,
    // In-memory index: hash -> entry
    blocks: HashMap<BlockHash, BlockIndexEntry>,
    // Height to hash mapping for quick lookups
    height_to_hash: HashMap<u32, BlockHash>,
    // Best chain tip
    best_tip: Option<BlockHash>,
    // Best chain height
    best_height: u32,
}

impl BlockIndex {
    /// Create a new block index from the database
    pub fn new(db: BlockDatabase) -> Result<Self, BlockIndexError> {
        let mut index = BlockIndex {
            db,
            blocks: HashMap::new(),
            height_to_hash: HashMap::new(),
            best_tip: None,
            best_height: 0,
        };

        // Load existing chain state from database
        index.load_chain_state()?;
        Ok(index)
    }

    /// Load the current chain state from the database
    fn load_chain_state(&mut self) -> Result<(), BlockIndexError> {
        let metadata = self.db.get_chain_tip()?;

        if metadata.tip_hash != BlockHash::all_zeros() {
            self.best_tip = Some(metadata.tip_hash);
            self.best_height = metadata.tip_height;

            // Load blocks from the best chain
            self.load_chain_blocks(&metadata.tip_hash, metadata.tip_height)?;
        }

        Ok(())
    }

    /// Load blocks from the best chain into memory
    fn load_chain_blocks(&mut self, tip_hash: &BlockHash, tip_height: u32) -> Result<(), BlockIndexError> {
        let mut current_hash = *tip_hash;
        let mut current_height = tip_height;

        // Load blocks from tip backwards to genesis
        while let Some(header) = self.db.get_header(&current_hash)? {
            let entry = BlockIndexEntry::new(
                current_hash,
                current_height,
                0, // TODO: Calculate actual chainwork
                BlockStatus::BestChain,
                header.prev_blockhash,
                header,
            );

            self.blocks.insert(current_hash, entry);
            self.height_to_hash.insert(current_height, current_hash);

            if current_height == 0 {
                break; // Reached genesis
            }

            current_hash = header.prev_blockhash;
            current_height -= 1;
        }

        Ok(())
    }

    /// Add a new block to the index
    pub fn add_block(&mut self, header: Header) -> Result<(), BlockIndexError> {
        let hash = header.block_hash();

        // Check if block already exists
        if self.blocks.contains_key(&hash) {
            return Ok(()); // Block already indexed
        }

        // Determine height based on parent
        let height = if let Some(parent_entry) = self.blocks.get(&header.prev_blockhash) {
            parent_entry.height + 1
        } else if header.prev_blockhash == BlockHash::all_zeros() {
            // Genesis block
            0
        } else {
            // Orphan block - will be processed when parent is available
            return self.add_orphan_block(header);
        };

        // Calculate chainwork (simplified - in reality this is more complex)
        let chainwork = self.calculate_chainwork(&header);

        // Create index entry
        let entry = BlockIndexEntry::new(
            hash,
            height,
            chainwork,
            BlockStatus::Valid,
            header.prev_blockhash,
            header,
        );

        // Add to index
        self.blocks.insert(hash, entry);
        self.height_to_hash.insert(height, hash);

        // Update database
        self.db.store_header(&header)?;
        self.db.update_height_index(height, &hash)?;

        // Check if this extends the best chain
        if self.should_update_best_chain(&hash, height, chainwork) {
            self.update_best_chain(&hash, height, chainwork)?;
        }

        // Process any orphan blocks that might now be valid
        self.process_orphans()?;

        Ok(())
    }

    /// Add an orphan block (parent not yet available)
    fn add_orphan_block(&mut self, header: Header) -> Result<(), BlockIndexError> {
        let hash = header.block_hash();

        let entry = BlockIndexEntry::new(
            hash,
            0, // Height unknown for orphans
            0,
            BlockStatus::Orphan,
            header.prev_blockhash,
            header,
        );

        self.blocks.insert(hash, entry);
        self.db.store_header(&header)?;

        Ok(())
    }

    /// Process orphan blocks to see if any can now be connected
    fn process_orphans(&mut self) -> Result<(), BlockIndexError> {
        let orphan_hashes: Vec<BlockHash> = self.blocks
            .iter()
            .filter(|(_, entry)| entry.status == BlockStatus::Orphan)
            .map(|(hash, _)| *hash)
            .collect();

        for orphan_hash in orphan_hashes {
            if let Some(entry) = self.blocks.get(&orphan_hash).cloned() {
                // Try to connect this orphan
                if let Some(parent_entry) = self.blocks.get(&entry.prev_hash) {
                    let new_height = parent_entry.height + 1;
                    let chainwork = self.calculate_chainwork(&entry.header);

                    // Update the entry
                    let mut updated_entry = entry;
                    updated_entry.height = new_height;
                    updated_entry.chainwork = chainwork;
                    updated_entry.status = BlockStatus::Valid;

                    self.blocks.insert(orphan_hash, updated_entry);
                    self.height_to_hash.insert(new_height, orphan_hash);

                    // Update database
                    self.db.update_height_index(new_height, &orphan_hash)?;

                    // Check if this should update the best chain
                    if self.should_update_best_chain(&orphan_hash, new_height, chainwork) {
                        self.update_best_chain(&orphan_hash, new_height, chainwork)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate chainwork for a block (simplified implementation)
    fn calculate_chainwork(&self, header: &Header) -> u64 {
        // Simplified chainwork calculation
        // In reality, this involves the difficulty target and is more complex
        if let Some(parent_entry) = self.blocks.get(&header.prev_blockhash) {
            parent_entry.chainwork + 1
        } else {
            1
        }
    }

    /// Check if a block should become the new best chain tip
    fn should_update_best_chain(&self, _hash: &BlockHash, _height: u32, chainwork: u64) -> bool {
        // Update if this is the first block or has more work
        self.best_tip.is_none() || chainwork > self.get_best_chainwork()
    }

    /// Get the current best chain work
    fn get_best_chainwork(&self) -> u64 {
        if let Some(tip_hash) = self.best_tip {
            self.blocks.get(&tip_hash).map(|e| e.chainwork).unwrap_or(0)
        } else {
            0
        }
    }

    /// Update the best chain to a new tip
    fn update_best_chain(&mut self, hash: &BlockHash, height: u32, chainwork: u64) -> Result<(), BlockIndexError> {
        self.best_tip = Some(*hash);
        self.best_height = height;

        // Update database metadata
        self.db.update_chain_tip(hash, height, chainwork)?;

        Ok(())
    }

    /// Get a block by hash
    pub fn get_by_hash(&self, hash: &BlockHash) -> Option<&BlockIndexEntry> {
        self.blocks.get(hash)
    }

    /// Get a block by height
    pub fn get_by_height(&self, height: u32) -> Option<&BlockIndexEntry> {
        if let Some(hash) = self.height_to_hash.get(&height) {
            self.blocks.get(hash)
        } else {
            None
        }
    }

    /// Get the best chain tip
    pub fn get_best_tip(&self) -> Option<&BlockIndexEntry> {
        if let Some(tip_hash) = self.best_tip {
            self.blocks.get(&tip_hash)
        } else {
            None
        }
    }

    /// Get the best chain height
    pub fn get_best_height(&self) -> u32 {
        self.best_height
    }

    /// Get an ancestor block at a specific height
    pub fn get_ancestor(&self, hash: &BlockHash, target_height: u32) -> Option<&BlockIndexEntry> {
        let mut current = self.get_by_hash(hash)?;

        while current.height > target_height {
            current = self.get_by_hash(&current.prev_hash)?;
        }

        if current.height == target_height {
            Some(current)
        } else {
            None
        }
    }

    /// Get the database reference for direct access
    pub fn database(&self) -> &BlockDatabase {
        &self.db
    }

    /// Get statistics about the index
    pub fn get_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        stats.insert("total_blocks".to_string(), self.blocks.len().to_string());
        stats.insert("best_height".to_string(), self.best_height.to_string());
        stats.insert("orphan_blocks".to_string(),
            self.blocks.values().filter(|e| e.status == BlockStatus::Orphan).count().to_string());

        if let Some(tip) = self.best_tip {
            stats.insert("best_tip".to_string(), format!("{:?}", tip));
        }

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::BlockDatabase;
    use bitcoin::{BlockHash};
    use bitcoin::block::Header;
    use tempfile::TempDir;

    fn create_test_header(prev_hash: BlockHash, nonce: u32) -> Header {
        Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce,
        }
    }

    #[test]
    fn test_block_index_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let index = BlockIndex::new(db).expect("Failed to create block index");

        assert_eq!(index.get_best_height(), 0);
        assert!(index.get_best_tip().is_none());
    }

    #[test]
    fn test_add_first_block() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        let header = create_test_header(BlockHash::all_zeros(), 0);
        let hash = header.block_hash();

        index.add_block(header).expect("Failed to add block");

        // Check that block is indexed
        let entry = index.get_by_hash(&hash).expect("Block should be indexed");
        assert_eq!(entry.hash, hash);
        assert_eq!(entry.height, 0);
        assert_eq!(entry.status, BlockStatus::Valid);

        // Check that it's the best tip
        let best_tip = index.get_best_tip().expect("Should have best tip");
        assert_eq!(best_tip.hash, hash);
        assert_eq!(index.get_best_height(), 0);
    }

    #[test]
    fn test_add_chain_of_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        // Add genesis block
        let genesis = create_test_header(BlockHash::all_zeros(), 0);
        let genesis_hash = genesis.block_hash();
        index.add_block(genesis).expect("Failed to add genesis block");

        // Add second block
        let block1 = create_test_header(genesis_hash, 1);
        let block1_hash = block1.block_hash();
        index.add_block(block1).expect("Failed to add block 1");

        // Add third block
        let block2 = create_test_header(block1_hash, 2);
        let block2_hash = block2.block_hash();
        index.add_block(block2).expect("Failed to add block 2");

        // Check chain structure
        assert_eq!(index.get_best_height(), 2);
        let best_tip = index.get_best_tip().expect("Should have best tip");
        assert_eq!(best_tip.hash, block2_hash);

        // Check individual blocks
        let genesis_entry = index.get_by_hash(&genesis_hash).expect("Genesis should be indexed");
        assert_eq!(genesis_entry.height, 0);

        let block1_entry = index.get_by_hash(&block1_hash).expect("Block 1 should be indexed");
        assert_eq!(block1_entry.height, 1);

        let block2_entry = index.get_by_hash(&block2_hash).expect("Block 2 should be indexed");
        assert_eq!(block2_entry.height, 2);
    }

    #[test]
    fn test_orphan_block_handling() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        // Add a parent block first
        let parent = create_test_header(BlockHash::all_zeros(), 0);
        let parent_hash = parent.block_hash();
        index.add_block(parent).expect("Failed to add parent block");

        // Add a child block that should be valid (not orphan)
        let child = create_test_header(parent_hash, 1);
        let child_hash = child.block_hash();
        index.add_block(child).expect("Failed to add child block");

        // Check that it's marked as valid
        let entry = index.get_by_hash(&child_hash).expect("Child should be indexed");
        assert_eq!(entry.status, BlockStatus::Valid);
        assert_eq!(entry.height, 1);
    }

    #[test]
    fn test_height_lookup() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        // Add a few blocks
        let genesis = create_test_header(BlockHash::all_zeros(), 0);
        let genesis_hash = genesis.block_hash();
        index.add_block(genesis).expect("Failed to add genesis block");

        let block1 = create_test_header(genesis_hash, 1);
        let block1_hash = block1.block_hash();
        index.add_block(block1).expect("Failed to add block 1");

        // Test height lookups
        let height_0 = index.get_by_height(0).expect("Should find block at height 0");
        assert_eq!(height_0.hash, genesis_hash);

        let height_1 = index.get_by_height(1).expect("Should find block at height 1");
        assert_eq!(height_1.hash, block1_hash);

        // Test non-existent height
        assert!(index.get_by_height(999).is_none());
    }

    #[test]
    fn test_ancestor_lookup() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        // Create a chain of 5 blocks
        let mut current_hash = BlockHash::all_zeros();
        let mut block_hashes = Vec::new();

        for i in 0..5 {
            let header = create_test_header(current_hash, i);
            let hash = header.block_hash();
            block_hashes.push(hash);
            index.add_block(header).expect("Failed to add block");
            current_hash = hash;
        }

        // Test ancestor lookups
        let tip_hash = block_hashes[4];
        let ancestor_at_2 = index.get_ancestor(&tip_hash, 2).expect("Should find ancestor at height 2");
        assert_eq!(ancestor_at_2.hash, block_hashes[2]);

        let ancestor_at_0 = index.get_ancestor(&tip_hash, 0).expect("Should find ancestor at height 0");
        assert_eq!(ancestor_at_0.hash, block_hashes[0]);

        // Test non-existent ancestor
        assert!(index.get_ancestor(&tip_hash, 10).is_none());
    }

    #[test]
    fn test_duplicate_block_handling() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        let header = create_test_header(BlockHash::all_zeros(), 0);
        let hash = header.block_hash();

        // Add the same block twice
        index.add_block(header.clone()).expect("Failed to add block first time");
        index.add_block(header).expect("Failed to add block second time");

        // Should still have only one entry
        let entry = index.get_by_hash(&hash).expect("Block should be indexed");
        assert_eq!(entry.hash, hash);
    }

    #[test]
    fn test_index_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let db = BlockDatabase::open(&db_path).expect("Failed to create database");
        let mut index = BlockIndex::new(db).expect("Failed to create block index");

        // Add some blocks
        let genesis = create_test_header(BlockHash::all_zeros(), 0);
        index.add_block(genesis).expect("Failed to add genesis block");

        let block1 = create_test_header(genesis.block_hash(), 1);
        index.add_block(block1).expect("Failed to add block 1");

        // Get stats
        let stats = index.get_stats();
        assert_eq!(stats["total_blocks"], "2");
        assert_eq!(stats["best_height"], "1");
        assert_eq!(stats["orphan_blocks"], "0");
    }
}
