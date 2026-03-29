use crate::config::AppConfig;
use crate::error::OnionChatError;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub version: u8,
    pub from: String,
    pub timestamp_unix: u64,
    pub body: String,
}

impl MessageEnvelope {
    pub fn new(from: String, body: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            from,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            body,
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

#[cfg(test)]
mod tests {
    use super::{decode_frame, encode_frame, sanitize_terminal, MessageEnvelope, PROTOCOL_VERSION};
    use crate::config::AppConfig;

    #[test]
    fn message_round_trip() {
        let config = AppConfig::default();
        let message = MessageEnvelope {
            version: PROTOCOL_VERSION,
            from: "peer.onion".into(),
            timestamp_unix: 42,
            body: "hello".into(),
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
}
