use crate::config::AppConfig;
use crate::error::OnionChatError;
use crate::storage::Storage;
use crate::tor::TorController;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub service_id: String,
    pub private_key: String,
    pub created_at_unix: u64,
}

impl Identity {
    pub async fn create(storage: &Storage, config: &AppConfig) -> Result<Self> {
        let mut tor = TorController::connect(config).await?;
        tor.authenticate().await?;
        let created = tor
            .create_persistent_identity(config.app.onion_virtual_port)
            .await?;
        let identity = Self {
            service_id: created.service_id,
            private_key: created.private_key,
            created_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        identity.save(storage)?;
        let _ = tor.delete_onion(&identity.service_id).await;
        Ok(identity)
    }

    pub fn load(storage: &Storage) -> Result<Self> {
        if !storage.paths.identity_file.exists() {
            return Err(OnionChatError::MissingIdentity.into());
        }
        storage.read_json(&storage.paths.identity_file)
    }

    pub fn save(&self, storage: &Storage) -> Result<()> {
        storage.write_json(&storage.paths.identity_file, self)
    }

    pub fn onion_address(&self) -> String {
        format!("{}.onion", self.service_id)
    }

    pub fn summary(&self, storage: &Storage) -> String {
        format!(
            "onion: {}\nconfig_dir: {}\nidentity_file: {}",
            self.onion_address(),
            storage.paths.root.display(),
            storage.paths.identity_file.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Identity;
    use crate::storage::Storage;
    use tempfile::tempdir;

    #[test]
    fn identity_round_trip() {
        let dir = tempdir().unwrap();
        let storage = Storage::from_root(dir.path().to_path_buf()).unwrap();
        let identity = Identity {
            service_id: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345".into(),
            private_key: "ED25519-V3:dummy".into(),
            created_at_unix: 123,
        };
        identity.save(&storage).unwrap();

        let loaded = Identity::load(&storage).unwrap();
        assert_eq!(loaded.service_id, identity.service_id);
        assert_eq!(loaded.private_key, identity.private_key);
    }
}
