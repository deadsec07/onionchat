use crate::config::AppConfig;
use crate::error::OnionChatError;
use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: u8,
    pub from: String,
    pub timestamp_unix: u64,
    pub payload: MessagePayload,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessagePayload {
    Direct {
        nonce: String,
        ciphertext: String,
    },
    Group {
        group_id: String,
        group_name: String,
        nonce: String,
        ciphertext: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactCard {
    pub version: u8,
    pub display_name: String,
    pub onion: String,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteFile {
    pub card: ContactCard,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInvite {
    pub version: u8,
    pub group_id: String,
    pub group_name: String,
    pub owner: String,
    pub owner_signing_public_key: String,
    pub members: Vec<String>,
    pub revision: u64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteFile {
    pub group: GroupInvite,
    pub signature: String,
}

impl MessageEnvelope {
    pub fn direct(from: String, nonce: String, ciphertext: String) -> Self {
        Self::new(from, MessagePayload::Direct { nonce, ciphertext })
    }

    pub fn group(
        from: String,
        group_id: String,
        group_name: String,
        nonce: String,
        ciphertext: String,
    ) -> Self {
        Self::new(
            from,
            MessagePayload::Group {
                group_id,
                group_name,
                nonce,
                ciphertext,
            },
        )
    }

    fn new(from: String, payload: MessagePayload) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            from,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            payload,
            signature: String::new(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SignedEnvelope<'a> {
            version: u8,
            from: &'a str,
            timestamp_unix: u64,
            payload: &'a MessagePayload,
        }

        serde_json::to_vec(&SignedEnvelope {
            version: self.version,
            from: &self.from,
            timestamp_unix: self.timestamp_unix,
            payload: &self.payload,
        })
        .context("failed to serialize signed message")
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let signature = signing_key.sign(&self.canonical_bytes()?);
        self.signature = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        Ok(())
    }
}

pub fn encode_frame(message: &MessageEnvelope, config: &AppConfig) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(message).context("failed to serialize message")?;
    if payload.len() > config.app.max_message_bytes {
        return Err(OnionChatError::MessageTooLarge(payload.len()).into());
    }

    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_frame(bytes: &[u8], config: &AppConfig) -> Result<MessageEnvelope> {
    if bytes.len() > config.app.max_message_bytes {
        return Err(OnionChatError::MessageTooLarge(bytes.len()).into());
    }
    let envelope = serde_json::from_slice(bytes).context("failed to decode message frame")?;
    Ok(envelope)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &MessageEnvelope,
    config: &AppConfig,
) -> Result<()> {
    let frame = encode_frame(message, config)?;
    writer.write_all(&frame).await.context("write failed")?;
    writer.flush().await.context("flush failed")?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    config: &AppConfig,
) -> Result<MessageEnvelope> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .await
        .context("failed to read frame length")?;
    let size = u32::from_be_bytes(len) as usize;
    if size > config.app.max_message_bytes {
        return Err(OnionChatError::MessageTooLarge(size).into());
    }

    let mut payload = vec![0u8; size];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read frame payload")?;
    decode_frame(&payload, config)
}

pub fn sanitize_terminal(input: &str) -> String {
    input
        .chars()
        .filter(|ch| *ch == '\n' || *ch == '\t' || !ch.is_control())
        .collect()
}

pub fn sanitize_label(input: &str) -> String {
    sanitize_terminal(input).trim().chars().take(80).collect()
}

pub fn validate_peer_onion(input: &str) -> Result<String> {
    let candidate = input.trim().trim_end_matches(".onion").to_lowercase();
    let is_valid = candidate.len() == 56
        && candidate
            .chars()
            .all(|ch| matches!(ch, 'a'..='z' | '2'..='7'));

    if is_valid {
        Ok(candidate)
    } else {
        Err(OnionChatError::InvalidOnionAddress.into())
    }
}

impl ContactCard {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize contact card")
    }
}

impl GroupInvite {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("failed to serialize group invite")
    }
}

pub fn verify_invite(invite: &InviteFile) -> Result<()> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(&invite.card.signing_public_key)
        .map_err(|_| OnionChatError::InvalidInvite)?;
    let key: [u8; 32] = key.try_into().map_err(|_| OnionChatError::InvalidInvite)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| OnionChatError::InvalidInvite)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&invite.signature)
        .map_err(|_| OnionChatError::InvalidInvite)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| OnionChatError::InvalidInvite)?;
    let signature = Signature::from_bytes(&signature);
    let bytes = invite.card.canonical_bytes()?;
    verifying_key
        .verify(&bytes, &signature)
        .map_err(|_| OnionChatError::InvalidInvite)?;
    validate_peer_onion(&invite.card.onion)?;
    Ok(())
}

pub fn verify_group_invite(invite: &GroupInviteFile) -> Result<()> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(&invite.group.owner_signing_public_key)
        .map_err(|_| OnionChatError::InvalidGroupInvite)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| OnionChatError::InvalidGroupInvite)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| OnionChatError::InvalidGroupInvite)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&invite.signature)
        .map_err(|_| OnionChatError::InvalidGroupInvite)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| OnionChatError::InvalidGroupInvite)?;
    let signature = Signature::from_bytes(&signature);

    if invite.group.group_id.trim().is_empty() || invite.group.revision == 0 {
        return Err(OnionChatError::InvalidGroupInvite.into());
    }
    validate_peer_onion(&invite.group.owner).map_err(|_| OnionChatError::InvalidGroupInvite)?;
    if invite.group.members.is_empty() {
        return Err(OnionChatError::InvalidGroupInvite.into());
    }
    for member in &invite.group.members {
        validate_peer_onion(member).map_err(|_| OnionChatError::InvalidGroupInvite)?;
    }
    if !invite
        .group
        .members
        .iter()
        .any(|member| member == &invite.group.owner)
    {
        return Err(OnionChatError::InvalidGroupInvite.into());
    }
    verifying_key
        .verify(&invite.group.canonical_bytes()?, &signature)
        .map_err(|_| OnionChatError::InvalidGroupInvite)?;
    Ok(())
}

pub fn verify_message(envelope: &MessageEnvelope, signing_public_key: &str) -> Result<()> {
    if envelope.signature.is_empty() {
        return Err(OnionChatError::InvalidMessageSignature.into());
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(signing_public_key)
        .map_err(|_| OnionChatError::InvalidMessageSignature)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| OnionChatError::InvalidMessageSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|_| OnionChatError::InvalidMessageSignature)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature)
        .map_err(|_| OnionChatError::InvalidMessageSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| OnionChatError::InvalidMessageSignature)?;
    let signature = Signature::from_bytes(&signature);

    verifying_key
        .verify(&envelope.canonical_bytes()?, &signature)
        .map_err(|_| OnionChatError::InvalidMessageSignature)?;
    Ok(())
}

pub fn encrypt_message(
    plaintext: &str,
    sender_secret_key: &StaticSecret,
    recipient_public_key: &str,
) -> Result<(String, String)> {
    let recipient_key = decode_encryption_public_key(recipient_public_key, true)?;
    let shared_secret = sender_secret_key.diffie_hellman(&recipient_key);
    let key_bytes = derive_message_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|_| OnionChatError::MessageEncryptionFailed)?;

    Ok((
        base64::engine::general_purpose::STANDARD.encode(nonce),
        base64::engine::general_purpose::STANDARD.encode(ciphertext),
    ))
}

pub fn decrypt_message(
    nonce: &str,
    ciphertext: &str,
    recipient_secret_key: &StaticSecret,
    sender_public_key: &str,
) -> Result<String> {
    let sender_key = decode_encryption_public_key(sender_public_key, false)?;
    let shared_secret = recipient_secret_key.diffie_hellman(&sender_key);
    let key_bytes = derive_message_key(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let nonce = base64::engine::general_purpose::STANDARD
        .decode(nonce)
        .map_err(|_| OnionChatError::MessageDecryptionFailed)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| OnionChatError::MessageDecryptionFailed)?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|_| OnionChatError::MessageDecryptionFailed)?;

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| OnionChatError::MessageDecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| OnionChatError::MessageDecryptionFailed.into())
}

fn decode_encryption_public_key(public_key: &str, encrypting: bool) -> Result<EncryptionPublicKey> {
    let key = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .map_err(|_| {
            if encrypting {
                OnionChatError::MessageEncryptionFailed
            } else {
                OnionChatError::MessageDecryptionFailed
            }
        })?;
    let key: [u8; 32] = key.try_into().map_err(|_| {
        if encrypting {
            OnionChatError::MessageEncryptionFailed
        } else {
            OnionChatError::MessageDecryptionFailed
        }
    })?;
    Ok(EncryptionPublicKey::from(key))
}

fn derive_message_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"onionchat-message-v1");
    hasher.update(shared_secret);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        decode_frame, decrypt_message, encode_frame, encrypt_message, sanitize_terminal,
        verify_group_invite, verify_invite, verify_message, ContactCard, GroupInvite,
        GroupInviteFile, InviteFile, MessageEnvelope, MessagePayload, PROTOCOL_VERSION,
    };
    use crate::config::AppConfig;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;
    use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};

    #[test]
    fn message_round_trip() {
        let config = AppConfig::default();
        let message = MessageEnvelope {
            version: PROTOCOL_VERSION,
            from: "peer.onion".into(),
            timestamp_unix: 42,
            payload: MessagePayload::Direct {
                nonce: "nonce".into(),
                ciphertext: "ciphertext".into(),
            },
            signature: String::new(),
        };

        let frame = encode_frame(&message, &config).unwrap();
        let decoded = decode_frame(&frame[4..], &config).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn sanitizer_strips_escape_sequences() {
        let clean = sanitize_terminal("ok\x1b[31mtext");
        assert_eq!(clean, "ok[31mtext");
    }

    #[test]
    fn invite_signature_verifies() {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let card = ContactCard {
            version: PROTOCOL_VERSION,
            display_name: "alice".into(),
            onion: "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd2345".into(),
            signing_public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            encryption_public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            created_at_unix: 1,
        };
        let signature = signing_key.sign(&card.canonical_bytes().unwrap());
        let invite = InviteFile {
            card,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        verify_invite(&invite).unwrap();
    }

    #[test]
    fn message_signature_verifies() {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let mut message = MessageEnvelope {
            version: PROTOCOL_VERSION,
            from: "peer.onion".into(),
            timestamp_unix: 42,
            payload: MessagePayload::Direct {
                nonce: "nonce".into(),
                ciphertext: "ciphertext".into(),
            },
            signature: String::new(),
        };

        message.sign(&signing_key).unwrap();

        verify_message(
            &message,
            &base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
        )
        .unwrap();
    }

    #[test]
    fn group_invite_signature_verifies() {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let group = GroupInvite {
            version: PROTOCOL_VERSION,
            group_id: "deadbeefcafebabe".into(),
            group_name: "ops".into(),
            owner: "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd2345".into(),
            owner_signing_public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            members: vec![
                "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd2345".into(),
                "bcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd23456".into(),
            ],
            revision: 1,
            created_at_unix: 1,
        };
        let signature = signing_key.sign(&group.canonical_bytes().unwrap());
        let invite = GroupInviteFile {
            group,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        verify_group_invite(&invite).unwrap();
    }

    #[test]
    fn message_encryption_round_trip() {
        let mut sender_secret = [0u8; 32];
        let mut recipient_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut sender_secret);
        rand::rngs::OsRng.fill_bytes(&mut recipient_secret);
        let sender_secret = StaticSecret::from(sender_secret);
        let recipient_secret = StaticSecret::from(recipient_secret);
        let recipient_public = EncryptionPublicKey::from(&recipient_secret);
        let sender_public = EncryptionPublicKey::from(&sender_secret);

        let (nonce, ciphertext) = encrypt_message(
            "hello",
            &sender_secret,
            &base64::engine::general_purpose::STANDARD.encode(recipient_public.as_bytes()),
        )
        .unwrap();
        let plaintext = decrypt_message(
            &nonce,
            &ciphertext,
            &recipient_secret,
            &base64::engine::general_purpose::STANDARD.encode(sender_public.as_bytes()),
        )
        .unwrap();

        assert_eq!(plaintext, "hello");
    }
}
