use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::OnionChatError;
use crate::transport::validate_peer_onion;

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
    pub groups_file: PathBuf,
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
                groups_file: root.join("groups.json"),
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
                groups_file: root.join("groups.json"),
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

    pub fn load_peer_book(&self) -> Result<PeerBook> {
        if self.paths.peers_file.exists() {
            self.read_json(&self.paths.peers_file)
        } else {
            Ok(PeerBook::default())
        }
    }

    pub fn save_peer_book(&self, peers: &PeerBook) -> Result<()> {
        self.write_json(&self.paths.peers_file, peers)
    }

    pub fn load_group_book(&self) -> Result<GroupBook> {
        if self.paths.groups_file.exists() {
            self.read_json(&self.paths.groups_file)
        } else {
            Ok(GroupBook::default())
        }
    }

    pub fn save_group_book(&self, groups: &GroupBook) -> Result<()> {
        self.write_json(&self.paths.groups_file, groups)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerBook {
    pub peers: Vec<PeerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupBook {
    pub groups: Vec<GroupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub onion: String,
    pub display_name: Option<String>,
    pub signing_public_key: Option<String>,
    pub added_at_unix: u64,
    pub last_used_unix: u64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    pub created_at_unix: u64,
}

impl PeerBook {
    pub fn upsert(
        &mut self,
        onion: &str,
        display_name: Option<String>,
        signing_public_key: Option<String>,
        source: &str,
    ) -> Result<()> {
        let onion = validate_peer_onion(onion)?;
        let now = now_unix();
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.onion == onion) {
            if display_name.is_some() {
                existing.display_name = display_name;
            }
            if signing_public_key.is_some() {
                existing.signing_public_key = signing_public_key;
            }
            existing.last_used_unix = now;
            existing.source = source.to_string();
            return Ok(());
        }

        self.peers.push(PeerRecord {
            onion,
            display_name,
            signing_public_key,
            added_at_unix: now,
            last_used_unix: now,
            source: source.to_string(),
        });
        self.peers.sort_by(|a, b| a.onion.cmp(&b.onion));
        Ok(())
    }

    pub fn touch(&mut self, onion: &str) {
        if let Ok(onion) = validate_peer_onion(onion) {
            if let Some(existing) = self.peers.iter_mut().find(|peer| peer.onion == onion) {
                existing.last_used_unix = now_unix();
            }
        }
    }

    pub fn find(&self, onion: &str) -> Option<&PeerRecord> {
        let onion = validate_peer_onion(onion).ok()?;
        self.peers.iter().find(|peer| peer.onion == onion)
    }
}

impl GroupBook {
    pub fn create_group(&mut self, name: String, members: Vec<String>) -> Result<GroupRecord> {
        if members.is_empty() {
            return Err(OnionChatError::EmptyGroup.into());
        }

        let mut normalized = members
            .into_iter()
            .map(|member| validate_peer_onion(&member))
            .collect::<Result<Vec<_>>>()?;
        normalized.sort();
        normalized.dedup();

        let group = GroupRecord {
            id: hex::encode(rand::random::<[u8; 8]>()),
            name,
            members: normalized,
            created_at_unix: now_unix(),
        };
        self.groups.push(group.clone());
        self.groups
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        Ok(group)
    }

    pub fn find(&self, group_id: &str) -> Option<&GroupRecord> {
        self.groups.iter().find(|group| group.id == group_id)
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
