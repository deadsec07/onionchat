use crate::storage::Storage;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub tor: TorConfig,
    #[serde(default)]
    pub app: RuntimeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    #[serde(default = "default_control_host")]
    pub control_host: String,
    #[serde(default = "default_control_port")]
    pub control_port: u16,
    #[serde(default = "default_socks_host")]
    pub socks_host: String,
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_onion_virtual_port")]
    pub onion_virtual_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            tor: TorConfig::default(),
            app: RuntimeConfig::default(),
        }
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            control_host: default_control_host(),
            control_port: default_control_port(),
            socks_host: default_socks_host(),
            socks_port: default_socks_port(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            onion_virtual_port: default_onion_virtual_port(),
            log_level: default_log_level(),
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

impl AppConfig {
    pub fn load_or_create(storage: &Storage) -> Result<Self> {
        if storage.paths.config_file.exists() {
            Self::load_from_path(&storage.paths.config_file)
        } else {
            let config = Self::default();
            config.save(storage)?;
            Ok(config)
        }
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        let config =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(config)
    }

    pub fn save(&self, storage: &Storage) -> Result<()> {
        let raw = toml::to_string_pretty(self).context("failed to render config")?;
        storage.write_atomic(&storage.paths.config_file, raw.as_bytes())
    }
}

fn default_control_host() -> String {
    "127.0.0.1".to_string()
}

fn default_control_port() -> u16 {
    9051
}

fn default_socks_host() -> String {
    "127.0.0.1".to_string()
}

fn default_socks_port() -> u16 {
    9050
}

fn default_onion_virtual_port() -> u16 {
    17654
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_max_message_bytes() -> usize {
    4096
}

#[cfg(test)]
mod tests {
    use super::AppConfig;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parses_partial_config_with_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
                [tor]
                control_port = 9151
            "#,
        )
        .unwrap();

        let config = AppConfig::load_from_path(&path).unwrap();
        assert_eq!(config.tor.control_port, 9151);
        assert_eq!(config.tor.socks_port, 9050);
        assert_eq!(config.app.onion_virtual_port, 17654);
    }
}
