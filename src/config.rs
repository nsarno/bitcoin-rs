use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Network {
    Testnet,
    Mainnet,
}

impl Default for Network {
    fn default() -> Self {
        Network::Testnet
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: Network,
    pub data_dir: PathBuf,
    pub listen_port: u16,
    pub max_peers: usize,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: Network::Testnet,
            data_dir: PathBuf::from("./data"),
            listen_port: 18333, // Testnet default port
            max_peers: 8,
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    #[allow(dead_code)]
    pub fn load() -> Result<Self> {
        // For now, return default config
        // TODO: Load from config file or environment variables
        let config = Config::default();
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn for_network(network: Network) -> Self {
        let (listen_port, data_dir) = match network {
            Network::Testnet => (18333, PathBuf::from("./data/testnet")),
            Network::Mainnet => (8333, PathBuf::from("./data/mainnet")),
        };

        Self {
            network,
            data_dir,
            listen_port,
            max_peers: 8,
            log_level: "info".to_string(),
        }
    }

    #[allow(dead_code)]
    pub fn is_testnet(&self) -> bool {
        matches!(self.network, Network::Testnet)
    }

    #[allow(dead_code)]
    pub fn is_mainnet(&self) -> bool {
        matches!(self.network, Network::Mainnet)
    }
}
