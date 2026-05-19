use crate::config::AppConfig;
use crate::error::OnionChatError;
use crate::storage::Storage;
use crate::tor::TorController;
use anyhow::Result;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub service_id: String,
    pub private_key: String,
    #[serde(default)]
    pub signing_secret_key: String,
    #[serde(default)]
    pub signing_public_key: String,
    #[serde(default)]
    pub encryption_secret_key: String,
    #[serde(default)]
    pub encryption_public_key: String,
    pub created_at_unix: u64,
}

impl Identity {
    pub async fn create(storage: &Storage, config: &AppConfig) -> Result<Self> {
        let mut tor = TorController::connect(config).await?;
        tor.authenticate().await?;
        let created = tor
            .create_persistent_identity(config.app.onion_virtual_port)
            .await?;
        let (signing_secret_key, signing_public_key) = generate_signing_material();
        let (encryption_secret_key, encryption_public_key) = generate_encryption_material();
        let identity = Self {
            service_id: created.service_id,
            private_key: created.private_key,
            signing_secret_key,
            signing_public_key,
            encryption_secret_key,
            encryption_public_key,
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
        let mut identity: Identity = storage.read_json(&storage.paths.identity_file)?;
        let mut changed = false;
        if identity.signing_secret_key.is_empty() || identity.signing_public_key.is_empty() {
            let (secret, public) = generate_signing_material();
            identity.signing_secret_key = secret;
            identity.signing_public_key = public;
            changed = true;
        }
        if identity.encryption_secret_key.is_empty() || identity.encryption_public_key.is_empty() {
            let (secret, public) = generate_encryption_material();
            identity.encryption_secret_key = secret;
            identity.encryption_public_key = public;
            changed = true;
        }
        if changed {
            identity.save(storage)?;
        }
        Ok(identity)
    }

    pub fn save(&self, storage: &Storage) -> Result<()> {
        storage.write_json(&storage.paths.identity_file, self)
    }

    pub fn onion_address(&self) -> String {
        format!("{}.onion", self.service_id)
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.signing_secret_key)
            .map_err(|_| OnionChatError::InvalidInvite)?;
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| OnionChatError::InvalidInvite)?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn sign_bytes(&self, bytes: &[u8]) -> Result<String> {
        let key = self.signing_key()?;
        let signature = key.sign(bytes);
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    pub fn encryption_secret_key(&self) -> Result<StaticSecret> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(&self.encryption_secret_key)
            .map_err(|_| OnionChatError::MessageEncryptionFailed)?;
        let bytes: [u8; 32] = secret
            .try_into()
            .map_err(|_| OnionChatError::MessageEncryptionFailed)?;
        Ok(StaticSecret::from(bytes))
    }

    pub fn summary(&self, storage: &Storage) -> String {
        format!(
            "onion: {}\nsigning_public_key: {}\nencryption_public_key: {}\nconfig_dir: {}\nidentity_file: {}",
            self.onion_address(),
            self.signing_public_key,
            self.encryption_public_key,
            storage.paths.root.display(),
            storage.paths.identity_file.display()
        )
    }
}

fn generate_signing_material() -> (String, String) {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verify_key = signing_key.verifying_key();
    (
        base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(verify_key.to_bytes()),
    )
}

fn generate_encryption_material() -> (String, String) {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let secret_key = StaticSecret::from(secret);
    let public_key = EncryptionPublicKey::from(&secret_key);
    (
        base64::engine::general_purpose::STANDARD.encode(secret_key.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes()),
    )
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
            signing_secret_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            signing_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            encryption_secret_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            encryption_public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            created_at_unix: 123,
        };
        identity.save(&storage).unwrap();

        let loaded = Identity::load(&storage).unwrap();
        assert_eq!(loaded.service_id, identity.service_id);
        assert_eq!(loaded.private_key, identity.private_key);
    }
}
