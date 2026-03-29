use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Storage {
    pub paths: AppPaths,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub identity_file: PathBuf,
    pub peers_file: PathBuf,
}

impl Storage {
    pub fn discover() -> Result<Self> {
        let root = if let Ok(override_root) = std::env::var("ONIONCHAT_CONFIG_DIR") {
            PathBuf::from(override_root)
        } else {
            let dirs = ProjectDirs::from("io", "onionchat", "onionchat")
                .context("could not determine config directory")?;
            dirs.config_dir().to_path_buf()
        };

        let storage = Self {
            paths: AppPaths {
                config_file: root.join("config.toml"),
                identity_file: root.join("identity.json"),
                peers_file: root.join("peers.json"),
                root,
            },
        };
        storage.ensure()?;
        Ok(storage)
    }

    #[cfg(test)]
    pub fn from_root(root: PathBuf) -> Result<Self> {
        let storage = Self {
            paths: AppPaths {
                config_file: root.join("config.toml"),
                identity_file: root.join("identity.json"),
                peers_file: root.join("peers.json"),
                root,
            },
        };
        storage.ensure()?;
        Ok(storage)
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.paths.root)
            .with_context(|| format!("failed to create {}", self.paths.root.display()))
    }

    pub fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let raw = serde_json::to_vec_pretty(value).context("failed to serialize json")?;
        self.write_atomic(path, &raw)
    }

    pub fn write_atomic(&self, path: &Path, contents: &[u8]) -> Result<()> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))
    }
}
