use crate::config::AppConfig;
use crate::error::OnionChatError;
use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: u8,
    pub from: String,
    pub timestamp_unix: u64,
    pub payload: MessagePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessagePayload {
    Direct {
        body: String,
    },
    Group {
        group_id: String,
        group_name: String,
        body: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactCard {
    pub version: u8,
    pub display_name: String,
    pub onion: String,
    pub signing_public_key: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteFile {
    pub card: ContactCard,
    pub signature: String,
}

impl MessageEnvelope {
    pub fn direct(from: String, body: String) -> Self {
        Self::new(from, MessagePayload::Direct { body })
    }

    pub fn group(from: String, group_id: String, group_name: String, body: String) -> Self {
        Self::new(
            from,
            MessagePayload::Group {
                group_id,
                group_name,
                body,
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
        }
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

#[cfg(test)]
mod tests {
    use super::{
        decode_frame, encode_frame, sanitize_terminal, verify_invite, ContactCard, InviteFile,
        MessageEnvelope, MessagePayload, PROTOCOL_VERSION,
    };
    use crate::config::AppConfig;
    use base64::Engine;
    use ed25519_dalek::Signer;
    use rand::RngCore;

    #[test]
    fn message_round_trip() {
        let config = AppConfig::default();
        let message = MessageEnvelope {
            version: PROTOCOL_VERSION,
            from: "peer.onion".into(),
            timestamp_unix: 42,
            payload: MessagePayload::Direct {
                body: "hello".into(),
            },
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
            created_at_unix: 1,
        };
        let signature = signing_key.sign(&card.canonical_bytes().unwrap());
        let invite = InviteFile {
            card,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        verify_invite(&invite).unwrap();
    }
}
