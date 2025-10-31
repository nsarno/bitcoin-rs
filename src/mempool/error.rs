// Error types for mempool operations

use bitcoin::{Txid, OutPoint};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Duplicate transaction: {0}")]
    DuplicateTransaction(Txid),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Mempool is full")]
    MempoolFull,
    #[error("Missing UTXO: {0}")]
    MissingUtxo(OutPoint),
    #[error("Double spend: {0}")]
    DoubleSpend(OutPoint),
    #[error("Insufficient fee")]
    InsufficientFee,
    #[error("Immature coinbase output")]
    ImmatureCoinbase,
    #[error("Invalid script: {0}")]
    InvalidScript(String),
    #[error("Non-final transaction")]
    NonFinalTransaction,
}

