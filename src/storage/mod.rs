// Database layer for persistent storage

pub mod db;

pub use db::{BlockDatabase, DatabaseError, ChainMetadata};
