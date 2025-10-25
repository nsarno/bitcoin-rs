use anyhow::Result;
use tracing::info;
use std::sync::Arc;
use tokio::sync::Mutex;

mod config;
mod network;
mod blockchain;
mod mempool;
mod consensus;
mod storage;
mod rpc;

use config::Config;
use network::{NetworkService, NetworkServiceError};

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

    // Initialize and start the network service
    let mut network_service = NetworkService::new(config.clone());

    // Start the network service
    if let Err(e) = network_service.start().await {
        tracing::error!("Failed to start network service: {}", e);
        return Err(e.into());
    }

    info!("Bitcoin Rust node started successfully");
    info!("Network service is running with {} connected peers", network_service.connected_peer_count());

    // Start the network service main loop in a separate task
    let network_service_arc = Arc::new(Mutex::new(network_service));
    let network_service_clone = network_service_arc.clone();

    let network_task = tokio::spawn(async move {
        let mut service = network_service_clone.lock().await;
        if let Err(e) = service.run().await {
            tracing::error!("Network service error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal...");
        }
        _ = network_task => {
            info!("Network service task completed");
        }
    }

    // Stop the network service
    {
        let mut service = network_service_arc.lock().await;
        service.stop();
        info!("Network service stopped");
    }

    info!("Shutting down Bitcoin Rust node...");
    Ok(())
}
