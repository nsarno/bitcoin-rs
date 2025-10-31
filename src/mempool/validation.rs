// Transaction validation logic for mempool

use bitcoin::{Transaction, Amount, OutPoint};
use crate::blockchain::utxo::UtxoSet;
use crate::consensus::ConsensusParams;
use crate::blockchain::validation::{
    validate_transaction_structure,
    verify_transaction_scripts,
    validate_locktime,
    validate_sequence,
    validate_transaction_standard_limits,
};
use crate::mempool::error::MempoolError;
use std::collections::HashSet;

/// Validate a transaction for inclusion in the mempool
///
/// This performs all necessary checks including structure, UTXO availability,
/// double-spend prevention, timelocks, scripts, and fee calculation.
pub fn validate_transaction_for_mempool(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    chain_height: u32,
    chain_time: u32,
    params: &ConsensusParams,
) -> Result<Amount, MempoolError> {
    // Validate transaction structure
    validate_transaction_structure(tx)
        .map_err(|e| MempoolError::InvalidTransaction(format!("Structure validation failed: {}", e)))?;

    // Validate timelocks
    validate_locktime(tx, chain_height, chain_time)
        .map_err(|_| MempoolError::NonFinalTransaction)?;

    validate_sequence(tx, utxo_set, chain_height, chain_time)
        .map_err(|_| MempoolError::NonFinalTransaction)?;

    // Check inputs exist and validate against UTXO set
    let mut seen_inputs = HashSet::new();
    let mut total_input_value = 0u64;

    for input in &tx.input {
        let outpoint = &input.previous_output;

        // Check for duplicate inputs within the same transaction
        if !seen_inputs.insert(outpoint) {
            return Err(MempoolError::DoubleSpend(*outpoint));
        }

        // Get the UTXO for this input
        let utxo = utxo_set
            .get_utxo(outpoint)
            .map_err(|_| MempoolError::MissingUtxo(*outpoint))?
            .ok_or_else(|| MempoolError::MissingUtxo(*outpoint))?;

        // Check coinbase maturity
        if !utxo.is_mature(chain_height, params.coinbase_maturity) {
            return Err(MempoolError::ImmatureCoinbase);
        }

        // Add to total input value
        total_input_value += utxo.value.to_sat();
    }

    // Calculate total output value
    let total_output_value: u64 = tx.output.iter()
        .map(|output| output.value.to_sat())
        .sum();

    // Check that inputs cover outputs (allow for fees)
    if total_input_value < total_output_value {
        return Err(MempoolError::InsufficientFee);
    }

    // Calculate fee
    let fee_sats = total_input_value - total_output_value;
    let fee = Amount::from_sat(fee_sats);

    // Verify scripts/signatures
    verify_transaction_scripts(tx, utxo_set)
        .map_err(|e| MempoolError::InvalidScript(format!("Script verification failed: {}", e)))?;

    // Validate standard limits
    validate_transaction_standard_limits(tx, params)
        .map_err(|e| MempoolError::InvalidTransaction(format!("Standard limits validation failed: {}", e)))?;

    Ok(fee)
}

/// Calculate transaction fee by looking up UTXOs
///
/// Returns the fee amount, or an error if UTXOs are missing.
pub fn calculate_transaction_fee(
    tx: &Transaction,
    utxo_set: &UtxoSet,
) -> Result<Amount, MempoolError> {
    // Skip coinbase transactions
    if tx.is_coinbase() {
        return Ok(Amount::ZERO);
    }

    let mut total_input_value = 0u64;

    for input in &tx.input {
        let utxo = utxo_set
            .get_utxo(&input.previous_output)
            .map_err(|_| MempoolError::MissingUtxo(input.previous_output))?
            .ok_or_else(|| MempoolError::MissingUtxo(input.previous_output))?;

        total_input_value += utxo.value.to_sat();
    }

    let total_output_value: u64 = tx.output.iter()
        .map(|output| output.value.to_sat())
        .sum();

    if total_input_value < total_output_value {
        return Err(MempoolError::InsufficientFee);
    }

    let fee_sats = total_input_value - total_output_value;
    Ok(Amount::from_sat(fee_sats))
}
