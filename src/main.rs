use anyhow::Result;
use tracing::info;

mod config;
mod network;
mod blockchain;
mod mempool;
mod consensus;
mod storage;
mod rpc;

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting Bitcoin Rust node...");

    // Load configuration
    let config = Config::load()?;
    info!("Loaded configuration for network: {:?}", config.network);

    // TODO: Initialize and start the node components
    // This will be implemented in subsequent phases

    info!("Bitcoin Rust node started successfully");

    // Keep the main thread alive
    tokio::signal::ctrl_c().await?;
    info!("Shutting down Bitcoin Rust node...");

    Ok(())
}
