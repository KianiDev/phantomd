use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub ca_dir: PathBuf,
    pub socket_path: PathBuf,
    pub cert_cache_ttl_secs: u64,
    pub ad_block_enabled: bool,
    pub forward_non_doh: bool,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, anyhow::Error> {
        let content = fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: "0.0.0.0:8443".parse().unwrap(),
            ca_dir: PathBuf::from("/var/lib/phantomd-mitm/ca"),
            socket_path: PathBuf::from("/tmp/phantomd_doh.sock"),
            cert_cache_ttl_secs: 3600,
            ad_block_enabled: false,
            forward_non_doh: true,
        }
    }
}