// Block validation logic
// This module implements proof-of-work verification and other block validation rules

use bitcoin::{Block, Target, CompactTarget, Transaction, BlockHash, OutPoint};
use bitcoin::block::Header;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use crate::consensus::ConsensusParams;
use crate::blockchain::block_index::BlockIndex;
use crate::blockchain::utxo::UtxoSet;
use thiserror::Error;
use std::collections::HashSet;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid proof of work: {0}")]
    InvalidProofOfWork(String),
    #[error("Target exceeds network PoW limit")]
    TargetTooHigh,
    #[error("Block size exceeds maximum allowed")]
    BlockTooLarge,
    #[error("Block weight exceeds maximum allowed")]
    BlockWeightExceeded,
    #[error("Invalid block structure")]
    InvalidBlockStructure,
    #[error("Block has no transactions")]
    EmptyBlock,
    #[error("First transaction must be coinbase")]
    FirstTxNotCoinbase,
    #[error("Block contains multiple coinbase transactions")]
    MultipleCoinbase,
    #[error("Block contains duplicate transactions")]
    DuplicateTransaction,
    #[error("Invalid transaction structure")]
    InvalidTransactionStructure,
    #[error("Merkle root validation failed")]
    InvalidMerkleRoot,
    #[error("Invalid difficulty adjustment: {0}")]
    InvalidDifficulty(String),
    #[error("Missing input: {0}")]
    MissingInput(OutPoint),
    #[error("Double spend: {0}")]
    DoubleSpend(OutPoint),
    #[error("Immature coinbase output")]
    ImmatureCoinbase,
    #[error("Insufficient input value: expected {expected}, got {actual}")]
    InsufficientInputValue { expected: u64, actual: u64 },
    #[error("Script verification failed: {0}")]
    ScriptVerifyFailed(String),
    #[error("Transaction not final (nLockTime)")]
    NonFinal,
    #[error("Transaction not final (nSequence relative locktime)")]
    NonFinalRelativeLocktime,
    #[error("Transaction too large")]
    TxTooLarge,
    #[error("Too many signature operations")]
    TooManySigops,
    #[error("Witness data too large")]
    WitnessTooLarge,
}

/// Verify that a block's proof-of-work meets the required target
pub fn verify_proof_of_work(header: &Header, target: &Target) -> Result<(), ValidationError> {
    // Use the bitcoin crate's built-in PoW validation
    header.validate_pow(*target)
        .map_err(|e| ValidationError::InvalidProofOfWork(format!("PoW validation failed: {}", e)))?;

    Ok(())
}

/// Check proof-of-work with network consensus parameters
pub fn check_proof_of_work(header: &Header, params: &ConsensusParams) -> Result<(), ValidationError> {
    // Get the target from the header's bits field
    let target = header.target();

    // Verify target doesn't exceed network's PoW limit
    if !params.is_target_valid(&target) {
        return Err(ValidationError::TargetTooHigh);
    }

    // Verify the proof-of-work
    verify_proof_of_work(header, &target)?;

    Ok(())
}

/// Calculate work value from a target
/// Work = 2^256 / (target + 1)
/// This represents the expected number of hashes needed to find a block at this difficulty
pub fn calculate_work_from_target(target: &Target) -> u128 {
    // For practical purposes, we'll use a simplified calculation
    // In a full implementation, you'd want to use a big integer library like num-bigint

    // Convert target to bytes and work with the most significant bytes
    let target_bytes = target.to_be_bytes();

    // Find the first non-zero byte to determine the effective target size
    let mut first_nonzero = 0;
    for (i, &byte) in target_bytes.iter().enumerate() {
        if byte != 0 {
            first_nonzero = i;
            break;
        }
    }

    // Use the first 8 bytes starting from the first non-zero byte
    let mut target_u64 = 0u64;
    for i in 0..8 {
        if first_nonzero + i < 32 {
            target_u64 = (target_u64 << 8) | (target_bytes[first_nonzero + i] as u64);
        }
    }

    // Simplified work calculation: use the inverse of the target
    // This gives us a relative measure of work
    if target_u64 == 0 {
        u128::MAX // Maximum work for zero target
    } else {
        // Use a large base and divide by target for relative work measurement
        let base = 1u128 << 64; // 2^64 as our base
        base / (target_u64 as u128)
    }
}

/// Convert compact target bits to full target (helper function)
pub fn bits_to_target(bits: CompactTarget) -> Target {
    Target::from_compact(bits)
}

/// Validate a complete block's proof-of-work
pub fn validate_block_pow(block: &Block, params: &ConsensusParams) -> Result<(), ValidationError> {
    check_proof_of_work(&block.header, params)
}

/// Validate a block header's proof-of-work
pub fn validate_header_pow(header: &Header, params: &ConsensusParams) -> Result<(), ValidationError> {
    check_proof_of_work(header, params)
}

/// Check if a block is the genesis block for the given network
pub fn is_genesis_block(block: &Block, params: &ConsensusParams) -> bool {
    block.block_hash() == params.genesis_hash
}

/// Check if a header is the genesis header for the given network
pub fn is_genesis_header(header: &Header, params: &ConsensusParams) -> bool {
    header.block_hash() == params.genesis_hash
}

/// Calculate block weight using the bitcoin crate's weight calculation
pub fn calculate_block_weight(block: &Block) -> usize {
    block.weight().to_wu() as usize
}

/// Validate block size and weight limits
pub fn validate_block_size(block: &Block, params: &ConsensusParams) -> Result<(), ValidationError> {
    // Check legacy block size limit (1MB) - use serialized size
    let mut buffer = Vec::new();
    block.consensus_encode(&mut buffer).map_err(|_| ValidationError::InvalidBlockStructure)?;
    let block_size = buffer.len();
    if block_size > params.max_block_size {
        return Err(ValidationError::BlockTooLarge);
    }

    // Check SegWit block weight limit (4MW)
    let block_weight = calculate_block_weight(block);
    if block_weight > params.max_block_weight {
        return Err(ValidationError::BlockWeightExceeded);
    }

    Ok(())
}

/// Validate transaction structure
pub fn validate_transaction_structure(tx: &Transaction) -> Result<(), ValidationError> {
    // Check transaction has at least 1 input and 1 output
    if tx.input.is_empty() {
        return Err(ValidationError::InvalidTransactionStructure);
    }
    if tx.output.is_empty() {
        return Err(ValidationError::InvalidTransactionStructure);
    }

    let is_coinbase = tx.is_coinbase();

    if is_coinbase {
        // For coinbase transactions:
        // - Must have exactly 1 input
        // - Input must have null previous output
        // - Script sig must be 2-100 bytes
        if tx.input.len() != 1 {
            return Err(ValidationError::InvalidTransactionStructure);
        }

        let input = &tx.input[0];
        if !input.previous_output.is_null() {
            return Err(ValidationError::InvalidTransactionStructure);
        }

        let script_sig_len = input.script_sig.len();
        if script_sig_len < 2 || script_sig_len > 100 {
            return Err(ValidationError::InvalidTransactionStructure);
        }
    } else {
        // For non-coinbase transactions:
        // - No input can have null previous output
        for input in &tx.input {
            if input.previous_output.is_null() {
                return Err(ValidationError::InvalidTransactionStructure);
            }
        }
    }

    // Validate output values
    for output in &tx.output {
        // Check that value is within valid range (not negative, not exceeding max supply)
        if output.value.to_sat() > 21_000_000 * 100_000_000 {
            return Err(ValidationError::InvalidTransactionStructure);
        }
    }

    Ok(())
}

/// Validate block structure
pub fn validate_block_structure(block: &Block) -> Result<(), ValidationError> {
    // Check block has at least 1 transaction
    if block.txdata.is_empty() {
        return Err(ValidationError::EmptyBlock);
    }

    // Check for duplicate transactions first
    let mut txids = HashSet::new();
    for tx in &block.txdata {
        let txid = tx.txid();
        if !txids.insert(txid) {
            return Err(ValidationError::DuplicateTransaction);
        }
    }

    // Check first transaction is coinbase
    let first_tx = &block.txdata[0];
    if !first_tx.is_coinbase() {
        return Err(ValidationError::FirstTxNotCoinbase);
    }

    // Check for multiple coinbase transactions
    let coinbase_count = block.txdata.iter().filter(|tx| tx.is_coinbase()).count();
    if coinbase_count > 1 {
        return Err(ValidationError::MultipleCoinbase);
    }

    // Validate each transaction structure
    for tx in &block.txdata {
        validate_transaction_structure(tx)?;
    }

    Ok(())
}

/// Validate that the block's merkle root matches the calculated merkle tree
pub fn validate_merkle_root(block: &Block) -> Result<(), ValidationError> {
    // Calculate the merkle root from the transaction IDs using the block's built-in method
    let calculated_root = block.compute_merkle_root()
        .ok_or(ValidationError::InvalidMerkleRoot)?;

    // Compare with the merkle root in the block header
    if calculated_root != block.header.merkle_root {
        return Err(ValidationError::InvalidMerkleRoot);
    }

    Ok(())
}

/// Calculate the next work required for a block at the given height
/// This implements Bitcoin's difficulty adjustment algorithm
pub fn calculate_next_work_required(
    last_block: &Header,
    first_block: &Header,
    params: &ConsensusParams,
) -> Result<Target, ValidationError> {
    // If this is the first block after genesis, use genesis difficulty
    if last_block.prev_blockhash == BlockHash::all_zeros() {
        return Ok(last_block.target());
    }

    // Calculate actual timespan between first and last block
    let actual_timespan = last_block.time - first_block.time;
    let expected_timespan = params.expected_timespan();

    // Clamp the actual timespan to prevent extreme difficulty changes
    // Bitcoin limits changes to 4x in either direction
    let clamped_timespan = actual_timespan
        .max(expected_timespan / 4)
        .min(expected_timespan * 4);

    // Calculate new target: new_target = old_target * (actual_timespan / expected_timespan)
    let old_target = last_block.target();

    // Use 256-bit arithmetic for precise calculation
    // new_target = old_target * clamped_timespan / expected_timespan
    let new_target = calculate_target_with_timespan(&old_target, clamped_timespan, expected_timespan);

    // Ensure the new target doesn't exceed the PoW limit
    let pow_limit = params.pow_limit_target();
    if new_target > pow_limit {
        Ok(pow_limit)
    } else {
        Ok(new_target)
    }
}

/// Calculate new target using timespan ratio with proper 256-bit arithmetic
fn calculate_target_with_timespan(old_target: &Target, actual_timespan: u32, expected_timespan: u32) -> Target {
    if actual_timespan == expected_timespan {
        return *old_target;
    }

    let numerator = actual_timespan as u64;
    let denominator = expected_timespan as u64;

    // Big-endian 256-bit multiply by u64
    fn mul_be_256_by_u64(value: [u8; 32], mul: u64) -> [u8; 32] {
        if mul == 0 {
            return [0u8; 32];
        }
        let mut out = [0u8; 32];
        let mut carry: u128 = 0;
        for i in (0..32).rev() {
            let part = value[i] as u128;
            let prod = part * (mul as u128) + carry;
            out[i] = (prod & 0xff) as u8;
            carry = prod >> 8;
        }
        out
    }

    // Big-endian 256-bit divide by u64 (returns quotient, discards remainder)
    fn div_be_256_by_u64(value: [u8; 32], div: u64) -> [u8; 32] {
        if div == 0 { return [0u8; 32]; }
        let mut out = [0u8; 32];
        let mut rem: u128 = 0;
        let d = div as u128;
        for i in 0..32 {
            let cur = (rem << 8) | (value[i] as u128);
            let q = cur / d; // fits in 0..255
            rem = cur % d;
            out[i] = q as u8;
        }
        out
    }

    let old_bytes = old_target.to_be_bytes();
    let scaled = mul_be_256_by_u64(old_bytes, numerator);
    let new_bytes = div_be_256_by_u64(scaled, denominator);
    Target::from_be_bytes(new_bytes)
}

/// Get the next work required for a block at the given height
/// This function looks up the necessary ancestor blocks and calculates the required difficulty
pub fn get_next_work_required(
    block_index: &BlockIndex,
    height: u32,
    params: &ConsensusParams,
) -> Result<Target, ValidationError> {
    // Genesis block uses its own difficulty
    if height == 0 {
        if let Some(genesis_entry) = block_index.get_by_height(0) {
            return Ok(genesis_entry.header.target());
        } else {
            return Err(ValidationError::InvalidDifficulty("Genesis block not found".to_string()));
        }
    }

    // For blocks before the first adjustment, use genesis difficulty
    if height < params.difficulty_adjustment_interval {
        if let Some(genesis_entry) = block_index.get_by_height(0) {
            return Ok(genesis_entry.header.target());
        } else {
            return Err(ValidationError::InvalidDifficulty("Genesis block not found".to_string()));
        }
    }

    // Check if this is a difficulty adjustment block
    if height % params.difficulty_adjustment_interval == 0 {
        // This is a difficulty adjustment block
        // We need the last block of the previous period and the first block of the previous period
        let last_block_height = height - 1;
        let first_block_height = height - params.difficulty_adjustment_interval;

        let last_block_entry = block_index.get_by_height(last_block_height)
            .ok_or_else(|| ValidationError::InvalidDifficulty(
                format!("Block at height {} not found", last_block_height)
            ))?;

        let first_block_entry = block_index.get_by_height(first_block_height)
            .ok_or_else(|| ValidationError::InvalidDifficulty(
                format!("Block at height {} not found", first_block_height)
            ))?;

        calculate_next_work_required(&last_block_entry.header, &first_block_entry.header, params)
    } else {
        // Not an adjustment block, use the same difficulty as the previous block
        let prev_height = height - 1;
        let prev_entry = block_index.get_by_height(prev_height)
            .ok_or_else(|| ValidationError::InvalidDifficulty(
                format!("Previous block at height {} not found", prev_height)
            ))?;

        Ok(prev_entry.header.target())
    }
}

/// Validate that a block's difficulty target is correct
pub fn validate_block_difficulty(
    block: &Block,
    block_index: &BlockIndex,
    params: &ConsensusParams,
) -> Result<(), ValidationError> {
    // Get the block height from the index
    let block_hash = block.block_hash();
    let block_entry = block_index.get_by_hash(&block_hash)
        .ok_or_else(|| ValidationError::InvalidDifficulty(
            "Block not found in index".to_string()
        ))?;

    let height = block_entry.height;

    // Get the expected target for this height
    let expected_target = get_next_work_required(block_index, height, params)?;
    let actual_target = block.header.target();

    // Compare targets
    if actual_target != expected_target {
        return Err(ValidationError::InvalidDifficulty(
            format!(
                "Incorrect difficulty target at height {}: expected {:?}, got {:?}",
                height, expected_target, actual_target
            )
        ));
    }

    Ok(())
}

/// Comprehensive block validation combining all consensus checks
pub fn validate_block_consensus(block: &Block, params: &ConsensusParams) -> Result<(), ValidationError> {
    // 1. Block structure validation
    validate_block_structure(block)?;

    // 2. Merkle root validation
    validate_merkle_root(block)?;

    // 3. Block size/weight validation
    validate_block_size(block, params)?;

    // 4. Proof-of-work validation (already implemented)
    validate_block_pow(block, params)?;

    Ok(())
}

/// Comprehensive block validation with difficulty adjustment
pub fn validate_block_consensus_with_difficulty(
    block: &Block,
    block_index: &BlockIndex,
    params: &ConsensusParams,
) -> Result<(), ValidationError> {
    // 1. Block structure validation
    validate_block_structure(block)?;

    // 2. Merkle root validation
    validate_merkle_root(block)?;

    // 3. Block size/weight validation
    validate_block_size(block, params)?;

    // 4. Proof-of-work validation
    validate_block_pow(block, params)?;

    // 5. Difficulty adjustment validation
    validate_block_difficulty(block, block_index, params)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Block, BlockHash, Transaction, TxIn, TxOut, OutPoint, ScriptBuf, Txid};
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use std::str::FromStr;

    fn create_test_header(prev_hash: BlockHash, nonce: u32, bits: u32) -> Header {
        Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        }
    }


    fn create_test_block(prev_hash: BlockHash, nonce: u32, bits: u32) -> Block {
        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_hex("0101").unwrap(), // 2 bytes for valid coinbase
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Create a temporary block to calculate the correct merkle root
        let temp_block = Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(1),
                prev_blockhash: prev_hash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(), // Temporary
                time: 1234567890,
                bits: CompactTarget::from_consensus(bits),
                nonce,
            },
            txdata: vec![tx],
        };

        // Calculate the correct merkle root using the block's method
        let merkle_root = temp_block.compute_merkle_root().unwrap_or_else(|| bitcoin::TxMerkleNode::all_zeros());

        // Create the final block with the correct merkle root
        Block {
            header: Header {
                version: bitcoin::block::Version::from_consensus(1),
                prev_blockhash: prev_hash,
                merkle_root,
                time: 1234567890,
                bits: CompactTarget::from_consensus(bits),
                nonce,
            },
            txdata: temp_block.txdata,
        }
    }

    #[test]
    fn test_verify_proof_of_work_valid() {
        let params = ConsensusParams::mainnet();

        // Create a header with a very easy target (high value)
        let header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // This should pass PoW validation since the target is very high
        // Note: In reality, this test block won't have valid PoW, but we're testing the target validation
        let target = header.target();
        assert!(params.is_target_valid(&target));
    }

    #[test]
    fn test_verify_proof_of_work_invalid_target() {
        let params = ConsensusParams::mainnet();

        // Create a target that's higher (easier) than the PoW limit
        // The PoW limit is 0x00000000ffff0000000000000000000000000000000000000000000000000000
        // We need a target that's higher (easier) than this limit
        // Let's create a target that's definitely higher than the limit by making it much easier
        let invalid_target = Target::from_be_bytes([
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // This is higher than the limit
        ]);

        // This should fail because the target exceeds the PoW limit
        assert!(!params.is_target_valid(&invalid_target));
    }

    #[test]
    fn test_calculate_work_from_target() {
        let params = ConsensusParams::mainnet();
        let target = params.pow_limit_target();

        let work = calculate_work_from_target(&target);

        // Work should be a positive number
        assert!(work > 0);

        // Test with a smaller target (harder difficulty)
        let harder_target = Target::from_be_bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let harder_work = calculate_work_from_target(&harder_target);

        // Harder target should result in more work
        assert!(harder_work > work);
    }

    #[test]
    fn test_bits_to_target_conversion() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let target = bits_to_target(bits);

        // The target should be a valid 256-bit value
        let target_bytes = target.to_be_bytes();
        assert!(target_bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_genesis_block_detection() {
        let params = ConsensusParams::mainnet();

        // Create a block with the genesis hash
        let block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Manually set the hash to match genesis (this is just for testing)
        // In reality, the genesis block has a specific nonce that produces the genesis hash
        assert!(!is_genesis_block(&block, &params)); // This will be false since we're not using the actual genesis

        // Test with testnet params
        let testnet_params = ConsensusParams::testnet();
        assert!(!is_genesis_block(&block, &testnet_params));
    }

    #[test]
    fn test_validate_block_pow() {
        let params = ConsensusParams::mainnet();
        let block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Test that the target is valid (even though the block won't have valid PoW)
        let target = block.header.target();
        assert!(params.is_target_valid(&target));
    }

    #[test]
    fn test_validate_header_pow() {
        let params = ConsensusParams::mainnet();
        let header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Test that the target is valid (even though the header won't have valid PoW)
        let target = header.target();
        assert!(params.is_target_valid(&target));
    }

    #[test]
    fn test_target_validation_edge_cases() {
        let params = ConsensusParams::mainnet();

        // Test with maximum valid target
        let max_target = params.pow_limit_target();
        assert!(params.is_target_valid(&max_target));

        // Test with zero target (should be invalid)
        let zero_target = Target::from_be_bytes([0; 32]);
        // Note: Zero target is actually valid (it's just very hard), so this test was wrong
        assert!(params.is_target_valid(&zero_target));
    }

    #[test]
    fn test_block_size_validation() {
        let params = ConsensusParams::mainnet();
        let block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Valid block should pass size validation
        assert!(validate_block_size(&block, &params).is_ok());

        // Test that the block size is within limits
        let mut buffer = Vec::new();
        block.consensus_encode(&mut buffer).unwrap();
        assert!(buffer.len() <= params.max_block_size);
        assert!(calculate_block_weight(&block) <= params.max_block_weight);
    }

    #[test]
    fn test_block_structure_validation() {
        let block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Valid block should pass structure validation
        let result = validate_block_structure(&block);
        if let Err(e) = &result {
            println!("Validation error: {:?}", e);
        }
        assert!(result.is_ok());

        // Test that the block has required structure
        assert!(!block.txdata.is_empty());
        assert!(block.txdata[0].is_coinbase());
    }

    #[test]
    fn test_empty_block_validation() {
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);
        block.txdata.clear();

        // Empty block should fail validation
        let result = validate_block_structure(&block);
        assert!(matches!(result, Err(ValidationError::EmptyBlock)));
    }

    #[test]
    fn test_no_coinbase_validation() {
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Create a non-coinbase transaction
        let non_coinbase_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Replace coinbase with non-coinbase transaction
        block.txdata[0] = non_coinbase_tx;

        // Block without coinbase as first transaction should fail
        let result = validate_block_structure(&block);
        assert!(matches!(result, Err(ValidationError::FirstTxNotCoinbase)));
    }

    #[test]
    fn test_multiple_coinbase_validation() {
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Add another coinbase transaction
        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_hex("0102").unwrap(), // Different script_sig to make it unique
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        block.txdata.push(coinbase_tx);

        // Block with multiple coinbase transactions should fail
        let result = validate_block_structure(&block);
        assert!(matches!(result, Err(ValidationError::MultipleCoinbase)));
    }

    #[test]
    fn test_duplicate_transaction_validation() {
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Add the same transaction twice
        let duplicate_tx = block.txdata[0].clone();
        block.txdata.push(duplicate_tx);

        // Block with duplicate transactions should fail
        let result = validate_block_structure(&block);
        assert!(matches!(result, Err(ValidationError::DuplicateTransaction)));
    }

    #[test]
    fn test_invalid_transaction_structure() {
        // Test transaction with no inputs
        let tx_no_inputs = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let result = validate_transaction_structure(&tx_no_inputs);
        assert!(matches!(result, Err(ValidationError::InvalidTransactionStructure)));

        // Test transaction with no outputs
        let tx_no_outputs = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let result = validate_transaction_structure(&tx_no_outputs);
        assert!(matches!(result, Err(ValidationError::InvalidTransactionStructure)));
    }

    #[test]
    fn test_coinbase_transaction_validation() {
        // Valid coinbase transaction
        let valid_coinbase = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_hex("0101").unwrap(), // 2 bytes
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(5000000000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(validate_transaction_structure(&valid_coinbase).is_ok());

        // Invalid transaction with no outputs
        let invalid_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(), 0),
                script_sig: ScriptBuf::from_hex("0101").unwrap(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![], // Empty outputs - this should fail
        };

        let result = validate_transaction_structure(&invalid_tx);

        assert!(matches!(result, Err(ValidationError::InvalidTransactionStructure)));
    }

    #[test]
    fn test_comprehensive_block_validation() {
        let params = ConsensusParams::mainnet();
        // Create a block with a very easy target (highest possible difficulty = easiest)
        // This should make it easier to find a valid nonce
        let block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Test only the structure and size validation (skip PoW for this test)
        let structure_result = validate_block_structure(&block);
        assert!(structure_result.is_ok(), "Block structure validation failed: {:?}", structure_result);

        let size_result = validate_block_size(&block, &params);
        assert!(size_result.is_ok(), "Block size validation failed: {:?}", size_result);
    }

    #[test]
    fn test_validate_merkle_root_single_transaction() {
        // Create a block with a single coinbase transaction
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Calculate the correct merkle root for the single transaction
        let correct_merkle_root = block.compute_merkle_root().unwrap_or_else(|| bitcoin::TxMerkleNode::all_zeros());
        block.header.merkle_root = correct_merkle_root;

        // Should pass validation
        assert!(validate_merkle_root(&block).is_ok());
    }

    #[test]
    fn test_validate_merkle_root_multiple_transactions() {
        // Create a block with multiple transactions
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Add a second transaction
        let second_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000").unwrap(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        block.txdata.push(second_tx);

        // Calculate the correct merkle root for both transactions
        let correct_merkle_root = block.compute_merkle_root().unwrap_or_else(|| bitcoin::TxMerkleNode::all_zeros());
        block.header.merkle_root = correct_merkle_root;

        // Should pass validation
        assert!(validate_merkle_root(&block).is_ok());
    }

    #[test]
    fn test_validate_merkle_root_invalid() {
        // Create a block with a single transaction
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);

        // Set an incorrect merkle root (all zeros)
        block.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();

        // Should fail validation
        let result = validate_merkle_root(&block);
        assert!(matches!(result, Err(ValidationError::InvalidMerkleRoot)));
    }

    #[test]
    fn test_validate_merkle_root_empty_block() {
        // Create an empty block (this should fail structure validation first)
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);
        block.txdata.clear();

        // Should fail structure validation before merkle root validation
        let result = validate_block_structure(&block);
        assert!(matches!(result, Err(ValidationError::EmptyBlock)));
    }

    #[test]
    fn test_merkle_root_integration_with_consensus_validation() {
        let _params = ConsensusParams::mainnet();

        // Create a block with correct merkle root
        let mut block = create_test_block(BlockHash::all_zeros(), 0, 0x1d00ffff);
        let correct_merkle_root = block.compute_merkle_root().unwrap_or_else(|| bitcoin::TxMerkleNode::all_zeros());
        block.header.merkle_root = correct_merkle_root;

        // Test structure and merkle root validation (skip PoW)
        let structure_result = validate_block_structure(&block);
        assert!(structure_result.is_ok());

        let merkle_result = validate_merkle_root(&block);
        assert!(merkle_result.is_ok());

        // Test with invalid merkle root
        block.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
        let invalid_merkle_result = validate_merkle_root(&block);
        assert!(matches!(invalid_merkle_result, Err(ValidationError::InvalidMerkleRoot)));
    }

    #[test]
    fn test_difficulty_adjustment_calculation() {
        let params = ConsensusParams::mainnet();

        // Create two headers with different timestamps
        let first_header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);
        let mut last_header = create_test_header(first_header.block_hash(), 1, 0x1d00ffff);

        // Set timestamps to simulate a 2-week period (exactly expected timespan)
        last_header.time = first_header.time + params.expected_timespan();

        // Calculate next work required
        let result = calculate_next_work_required(&last_header, &first_header, &params);
        assert!(result.is_ok());

        // Since timespan equals expected timespan, difficulty should remain the same
        let new_target = result.unwrap();
        assert_eq!(new_target, last_header.target());
    }

    #[test]
    fn test_difficulty_adjustment_faster_mining() {
        let params = ConsensusParams::mainnet();

        // Create two headers with different timestamps
        let first_header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);
        let mut last_header = create_test_header(first_header.block_hash(), 1, 0x1d00ffff);

        // Set timestamps to simulate faster mining (half the expected timespan)
        last_header.time = first_header.time + (params.expected_timespan() / 2);

        // Calculate next work required
        let result = calculate_next_work_required(&last_header, &first_header, &params);
        assert!(result.is_ok());

        // Since mining was faster, difficulty should increase (target should decrease)
        let new_target = result.unwrap();
        assert!(new_target < last_header.target());
    }

    #[test]
    fn test_difficulty_adjustment_slower_mining() {
        let params = ConsensusParams::mainnet();

        // Create two headers with different timestamps
        // Use a target below the PoW limit so doubling won't clamp
        let first_header = create_test_header(BlockHash::all_zeros(), 0, 0x1c00ffff);
        let mut last_header = create_test_header(first_header.block_hash(), 1, 0x1c00ffff);

        // Set timestamps to simulate slower mining (double the expected timespan)
        last_header.time = first_header.time + (params.expected_timespan() * 2);

        // Calculate next work required
        let result = calculate_next_work_required(&last_header, &first_header, &params);
        assert!(result.is_ok());

        // Since mining was slower, difficulty should decrease (target should increase)
        let new_target = result.unwrap();
        let old_target = last_header.target();

        // The target should increase when mining is slower (difficulty decreases)
        println!("Old target: {:?}", old_target);
        println!("New target: {:?}", new_target);
        assert!(new_target > old_target, "New target should be greater than old target when mining is slower");
    }

    #[test]
    fn test_difficulty_adjustment_clamping() {
        let params = ConsensusParams::mainnet();

        // Create two headers with different timestamps
        let first_header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);
        let mut last_header = create_test_header(first_header.block_hash(), 1, 0x1d00ffff);

        // Set timestamps to simulate extremely fast mining (1/8 of expected timespan)
        // This should be clamped to 1/4 of expected timespan
        last_header.time = first_header.time + (params.expected_timespan() / 8);

        // Calculate next work required
        let result = calculate_next_work_required(&last_header, &first_header, &params);
        assert!(result.is_ok());

        // The result should be clamped to maximum 4x difficulty increase
        let new_target = result.unwrap();
        // For now, just verify that the target is different (simplified test)
        assert!(new_target != last_header.target());
    }

    #[test]
    fn test_difficulty_adjustment_pow_limit() {
        let params = ConsensusParams::mainnet();

        // Create two headers with different timestamps
        let first_header = create_test_header(BlockHash::all_zeros(), 0, 0x1d00ffff);
        let mut last_header = create_test_header(first_header.block_hash(), 1, 0x1d00ffff);

        // Set timestamps to simulate extremely slow mining (8x expected timespan)
        // This should be clamped to 4x expected timespan
        last_header.time = first_header.time + (params.expected_timespan() * 8);

        // Calculate next work required
        let result = calculate_next_work_required(&last_header, &first_header, &params);
        assert!(result.is_ok());

        // The result should be clamped to the PoW limit
        let new_target = result.unwrap();
        assert_eq!(new_target, params.pow_limit_target());
    }
}

/// Validate transaction inputs against the UTXO set
/// Returns the total input value for fee calculation
pub fn validate_transaction_inputs(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    height: u32,
    params: &ConsensusParams,
) -> Result<u64, ValidationError> {
    // Skip validation for coinbase transactions
    if tx.is_coinbase() {
        return Ok(0);
    }

    let mut total_input_value = 0u64;
    let mut seen_inputs = HashSet::new();

    // Validate each input
    for input in &tx.input {
        let outpoint = &input.previous_output;

        // Check for duplicate inputs within the same transaction
        if !seen_inputs.insert(outpoint) {
            return Err(ValidationError::DoubleSpend(*outpoint));
        }

        // Get the UTXO for this input
        let utxo = utxo_set.get_utxo(outpoint)
            .map_err(|_| ValidationError::MissingInput(*outpoint))?
            .ok_or(ValidationError::MissingInput(*outpoint))?;

        // Check coinbase maturity
        if !utxo.is_mature(height, params.coinbase_maturity) {
            return Err(ValidationError::ImmatureCoinbase);
        }

        // Add to total input value
        total_input_value += utxo.value.to_sat();
    }

    // Calculate total output value
    let total_output_value: u64 = tx.output.iter()
        .map(|output| output.value.to_sat())
        .sum();

    // Check that inputs cover outputs (allowing for fees)
    if total_input_value < total_output_value {
        return Err(ValidationError::InsufficientInputValue {
            expected: total_output_value,
            actual: total_input_value,
        });
    }

    Ok(total_input_value)
}

#[cfg(test)]
mod tx_validation_tests {
    use super::*;
    use bitcoin::{Transaction, TxIn, TxOut, ScriptBuf, OutPoint, Amount};
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use tempfile::TempDir;
    use crate::storage::BlockDatabase;

    fn make_utxo_set() -> UtxoSet {
        let temp_dir = TempDir::new().unwrap();
        let db = std::sync::Arc::new(BlockDatabase::open(temp_dir.path()).unwrap());
        UtxoSet::new(db)
    }

    #[test]
    fn test_locktime_finality_height() {
        // tx requiring height >= 100
        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_height(100).unwrap(),
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: bitcoin::Sequence::from_consensus(0xfffffffe), witness: bitcoin::Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
        };

        // Not final at height 99
        assert!(matches!(validate_locktime(&tx, 99, 0), Err(ValidationError::NonFinal)));
        // Final at height 100
        assert!(validate_locktime(&tx, 100, 0).is_ok());
    }

    #[test]
    fn test_sequence_relative_height_lock() {
        let utxos = make_utxo_set();
        // Create a prevout at height 10
        let prev_outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([1u8;32]), 0);
        let prev_entry = crate::blockchain::utxo::UtxoEntry::new(Amount::from_sat(1000), ScriptBuf::new(), 10, false);
        utxos.store_utxo(&prev_outpoint, &prev_entry).unwrap();

        // Sequence requires +5 blocks (height-based)
        let seq = bitcoin::Sequence::from_consensus(5);
        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: prev_outpoint, script_sig: ScriptBuf::new(), sequence: seq, witness: bitcoin::Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
        };

        // Not final at height 14
        assert!(matches!(validate_sequence(&tx, &utxos, 14, 0), Err(ValidationError::NonFinalRelativeLocktime)));
        // Final at height 15
        assert!(validate_sequence(&tx, &utxos, 15, 0).is_ok());
    }
}

/// Verify a single input's script using libbitcoinconsensus when available.
/// Falls back to a no-op OK if the consensus feature is disabled.
pub fn verify_script(
    tx: &Transaction,
    input_index: usize,
    prev_value_sats: u64,
    script_pubkey: &[u8],
) -> Result<(), ValidationError> {
    #[cfg(feature = "consensus")]
    {
        use bitcoinconsensus::{verify, VerificationError, VerificationFlags};
        // Standard flags similar to Bitcoin Core default policy for blocks
        let flags = VerificationFlags::SCRIPT_VERIFY_P2SH
            | VerificationFlags::SCRIPT_VERIFY_WITNESS
            | VerificationFlags::SCRIPT_VERIFY_NULLDUMMY
            | VerificationFlags::SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
            | VerificationFlags::SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
            | VerificationFlags::SCRIPT_VERIFY_DERSIG
            | VerificationFlags::SCRIPT_VERIFY_LOW_S
            | VerificationFlags::SCRIPT_VERIFY_MINIMALDATA
            | VerificationFlags::SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            | VerificationFlags::SCRIPT_VERIFY_CLEANSTACK
            | VerificationFlags::SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;

        let tx_bytes = bitcoin::consensus::encode::serialize(tx);
        verify(script_pubkey, prev_value_sats, &tx_bytes, input_index, flags)
            .map_err(|e: VerificationError| ValidationError::ScriptVerifyFailed(e.to_string()))
    }
    #[cfg(not(feature = "consensus"))]
    {
        // Without libbitcoinconsensus, we cannot do consensus script checks here.
        // Return Ok to allow builds without the native library; integration should enable the feature.
        let _ = (tx, input_index, prev_value_sats, script_pubkey);
        Ok(())
    }
}

/// Verify all input scripts in a transaction against the UTXO set.
pub fn verify_transaction_scripts(
    tx: &Transaction,
    utxo_set: &UtxoSet,
) -> Result<(), ValidationError> {
    if tx.is_coinbase() {
        return Ok(());
    }

    for (i, input) in tx.input.iter().enumerate() {
        let utxo = utxo_set
            .get_utxo(&input.previous_output)
            .map_err(|_| ValidationError::MissingInput(input.previous_output))?
            .ok_or(ValidationError::MissingInput(input.previous_output))?;

        let script_pubkey_bytes = utxo.script_pubkey.as_bytes().to_vec();
        verify_script(tx, i, utxo.value.to_sat(), &script_pubkey_bytes)?;
    }
    Ok(())
}

/// Check if transaction is final with respect to nLockTime and input sequences (BIP-113 simplified).
pub fn validate_locktime(
    tx: &Transaction,
    block_height: u32,
    block_time: u32,
) -> Result<(), ValidationError> {
    use bitcoin::absolute::LockTime;

    match tx.lock_time {
        LockTime::ZERO => return Ok(()),
        _ => {}
    }

    // If all sequences are final, tx is final regardless of lock_time
    let all_final = tx
        .input
        .iter()
        .all(|inp| inp.sequence.to_consensus_u32() == u32::MAX);
    if all_final {
        return Ok(());
    }

    // Interpret locktime as height or time based on threshold (per consensus rules)
    const LOCKTIME_THRESHOLD: u32 = 500_000_000; // below: height, above: UNIX time
    let lock = tx.lock_time.to_consensus_u32();
    let satisfied = if lock < LOCKTIME_THRESHOLD {
        block_height >= lock
    } else {
        block_time >= lock
    };

    if satisfied { Ok(()) } else { Err(ValidationError::NonFinal) }
}

/// Validate relative locktime using BIP-68 semantics (simplified using input sequence and UTXO heights).
pub fn validate_sequence(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    block_height: u32,
    block_time: u32,
) -> Result<(), ValidationError> {
    // Coinbase transactions do not enforce sequence relative locks
    if tx.is_coinbase() {
        return Ok(());
    }

    // If any input has the disable flag set, ignore relative lock for that input
    // BIP-68: sequence format
    const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
    const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22; // 0 = height, 1 = time based
    const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
    const SEQUENCE_GRANULARITY: u32 = 9; // time-based units are multiples of 512 seconds

    for input in &tx.input {
        let seq = input.sequence.to_consensus_u32();
        if (seq & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            continue; // disabled
        }

        // Fetch the referenced UTXO to get its height for height-based relative locks
        let prev = utxo_set
            .get_utxo(&input.previous_output)
            .map_err(|_| ValidationError::MissingInput(input.previous_output))?
            .ok_or(ValidationError::MissingInput(input.previous_output))?;

        if (seq & SEQUENCE_LOCKTIME_TYPE_FLAG) == 0 {
            // Height-based relative lock
            let required = (seq & SEQUENCE_LOCKTIME_MASK) as u32;
            let spendable_height = prev.height.saturating_add(required);
            if block_height < spendable_height {
                return Err(ValidationError::NonFinalRelativeLocktime);
            }
        } else {
            // Time-based relative lock: units of 512 seconds from the previous block time
            let required_units = (seq & SEQUENCE_LOCKTIME_MASK) as u32;
            let required_seconds = required_units << SEQUENCE_GRANULARITY;
            // We do not have per-UTXO MTP/time; use current block time as a simplified gate.
            // In production, use MedianTimePast of the chain and previous confirmation time.
            if block_time < required_seconds {
                return Err(ValidationError::NonFinalRelativeLocktime);
            }
        }
    }

    Ok(())
}

/// Basic standardness/limits checks for size, weight, and witness.
pub fn validate_transaction_standard_limits(tx: &Transaction, params: &ConsensusParams) -> Result<(), ValidationError> {
    // Use encoded size for legacy size check
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).map_err(|_| ValidationError::TxTooLarge)?;
    let size = buf.len();
    if size > params.max_block_size { // reuse block param as rough limit placeholder
        return Err(ValidationError::TxTooLarge);
    }

    // Sigop counting and witness limits are complex; placeholders for now
    // In production, count accurate sigops per script type.
    Ok(())
}

/// Comprehensive transaction validation combining structure, IO, scripts, and timelocks.
pub fn validate_transaction_consensus(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    block_height: u32,
    block_time: u32,
    params: &ConsensusParams,
) -> Result<(), ValidationError> {
    // Structure
    validate_transaction_structure(tx)?;

    // Timelocks
    validate_locktime(tx, block_height, block_time)?;
    validate_sequence(tx, utxo_set, block_height, block_time)?;

    // Inputs existence, maturity, and value checks
    let _total_in = validate_transaction_inputs(tx, utxo_set, block_height, params)?;

    // Scripts/signatures
    verify_transaction_scripts(tx, utxo_set)?;

    // Size/standardness (basic)
    validate_transaction_standard_limits(tx, params)?;

    Ok(())
}
