// Error types for mempool operations

use bitcoin::Txid;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Duplicate transaction: {0}")]
    DuplicateTransaction(Txid),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Mempool is full")]
    MempoolFull,
}

