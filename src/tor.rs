use crate::config::AppConfig;
use crate::error::OnionChatError;
use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, info};

type HmacSha256 = Hmac<Sha256>;

const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

#[derive(Debug)]
pub struct TorController {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

#[derive(Debug, Clone)]
pub struct OnionIdentityMaterial {
    pub service_id: String,
    pub private_key: String,
}

#[derive(Debug, Clone)]
pub struct ActiveOnionService {
    pub service_id: String,
    pub onion_address: String,
}

impl TorController {
    pub async fn connect(config: &AppConfig) -> Result<Self> {
        let stream =
            TcpStream::connect((config.tor.control_host.as_str(), config.tor.control_port))
                .await
                .with_context(|| {
                    format!(
                        "failed to connect to Tor control port at {}:{}",
                        config.tor.control_host, config.tor.control_port
                    )
                })?;
        let (read_half, write_half) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        })
    }

    pub async fn authenticate(&mut self) -> Result<()> {
        let lines = self.command("PROTOCOLINFO 1").await?;
        let auth_line = lines
            .iter()
            .find(|line| line.starts_with("AUTH "))
            .ok_or_else(|| {
                OnionChatError::TorProtocol("missing AUTH line in PROTOCOLINFO".into())
            })?;
        let attributes = parse_kv_pairs(auth_line);
        let methods = attributes
            .get("METHODS")
            .cloned()
            .unwrap_or_default()
            .split(',')
            .map(str::to_string)
            .collect::<Vec<_>>();

        if methods.iter().any(|method| method == "SAFECOOKIE") {
            let cookie_file = attributes.get("COOKIEFILE").ok_or_else(|| {
                OnionChatError::TorAuth("SAFECOOKIE offered without COOKIEFILE".into())
            })?;
            self.authenticate_safecookie(cookie_file).await
        } else if methods.iter().any(|method| method == "NULL") {
            self.command("AUTHENTICATE").await?;
            Ok(())
        } else {
            Err(OnionChatError::TorAuth(format!(
                "unsupported Tor authentication methods: {}",
                methods.join(",")
            ))
            .into())
        }
    }

    pub async fn create_persistent_identity(
        &mut self,
        virtual_port: u16,
    ) -> Result<OnionIdentityMaterial> {
        let command = format!("ADD_ONION NEW:ED25519-V3 Port={},127.0.0.1:1", virtual_port);
        let lines = self.command(&command).await?;
        let values = flatten_reply(&lines);
        let service_id = values
            .get("ServiceID")
            .cloned()
            .ok_or_else(|| anyhow!("Tor did not return ServiceID"))?;
        let private_key = values
            .get("PrivateKey")
            .cloned()
            .ok_or_else(|| anyhow!("Tor did not return PrivateKey"))?;
        Ok(OnionIdentityMaterial {
            service_id,
            private_key,
        })
    }

    pub async fn publish_onion(
        &mut self,
        private_key: &str,
        virtual_port: u16,
        target_port: u16,
    ) -> Result<ActiveOnionService> {
        let command = format!(
            "ADD_ONION {} Port={},127.0.0.1:{}",
            private_key, virtual_port, target_port
        );
        let lines = self.command(&command).await?;
        let values = flatten_reply(&lines);
        let service_id = values
            .get("ServiceID")
            .cloned()
            .ok_or_else(|| anyhow!("Tor did not return ServiceID"))?;
        info!("published onion service {}", service_id);
        Ok(ActiveOnionService {
            onion_address: format!("{}.onion", service_id),
            service_id,
        })
    }

    pub async fn delete_onion(&mut self, service_id: &str) -> Result<()> {
        self.command(&format!("DEL_ONION {}", service_id)).await?;
        Ok(())
    }

    pub async fn connect_via_socks(
        config: &AppConfig,
        peer_onion: &str,
        port: u16,
    ) -> Result<TcpStream> {
        let stream = Socks5Stream::connect(
            (config.tor.socks_host.as_str(), config.tor.socks_port),
            (format!("{}.onion", peer_onion), port),
        )
        .await
        .with_context(|| {
            format!(
                "failed to connect to peer through Tor SOCKS proxy at {}:{}",
                config.tor.socks_host, config.tor.socks_port
            )
        })?;
        Ok(stream.into_inner())
    }

    async fn authenticate_safecookie(&mut self, cookie_path: &str) -> Result<()> {
        let cookie = fs::read(cookie_path)
            .with_context(|| format!("failed to read Tor cookie at {}", cookie_path))?;
        if cookie.len() != 32 {
            return Err(
                OnionChatError::TorAuth("Tor SAFECOOKIE cookie must be 32 bytes".into()).into(),
            );
        }

        let mut client_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut client_nonce);
        let challenge = format!("AUTHCHALLENGE SAFECOOKIE {}", hex::encode(client_nonce));
        let lines = self.command(&challenge).await?;
        let values = flatten_reply(&lines);
        let server_hash = hex::decode(
            values
                .get("SERVERHASH")
                .ok_or_else(|| anyhow!("Tor did not return SERVERHASH"))?,
        )
        .context("invalid SERVERHASH hex")?;
        let server_nonce = hex::decode(
            values
                .get("SERVERNONCE")
                .ok_or_else(|| anyhow!("Tor did not return SERVERNONCE"))?,
        )
        .context("invalid SERVERNONCE hex")?;

        let expected_server_hash =
            safecookie_hmac(SAFECOOKIE_SERVER_KEY, &cookie, &client_nonce, &server_nonce)?;
        if server_hash != expected_server_hash {
            return Err(OnionChatError::TorAuth(
                "SAFECOOKIE server hash verification failed".into(),
            )
            .into());
        }

        let client_hash =
            safecookie_hmac(SAFECOOKIE_CLIENT_KEY, &cookie, &client_nonce, &server_nonce)?;
        self.command(&format!("AUTHENTICATE {}", hex::encode(client_hash)))
            .await?;
        Ok(())
    }

    async fn command(&mut self, command: &str) -> Result<Vec<String>> {
        debug!(
            "torctl> {}",
            command.split_whitespace().next().unwrap_or(command)
        );
        self.writer
            .write_all(command.as_bytes())
            .await
            .context("failed to write Tor command")?;
        self.writer
            .write_all(b"\r\n")
            .await
            .context("failed to terminate Tor command")?;
        self.writer
            .flush()
            .await
            .context("failed to flush Tor command")?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        loop {
            let mut raw = String::new();
            let read = self
                .reader
                .read_line(&mut raw)
                .await
                .context("failed reading Tor reply")?;
            if read == 0 {
                return Err(anyhow!("Tor control port closed unexpectedly"));
            }

            let line = raw.trim_end_matches(['\r', '\n']).to_string();
            if line.len() < 4 {
                return Err(anyhow!("malformed Tor control reply: {}", line));
            }

            let status = &line[..3];
            let separator = line.as_bytes()[3] as char;
            let body = line[4..].to_string();

            if status != "250" {
                return Err(OnionChatError::TorProtocol(line).into());
            }

            match separator {
                '-' => lines.push(body),
                ' ' => {
                    if body != "OK" {
                        lines.push(body);
                    }
                    break;
                }
                '+' => {
                    let mut data = String::new();
                    loop {
                        let mut chunk = String::new();
                        self.reader
                            .read_line(&mut chunk)
                            .await
                            .context("failed reading Tor data block")?;
                        let chunk = chunk.trim_end_matches(['\r', '\n']);
                        if chunk == "." {
                            break;
                        }
                        data.push_str(chunk);
                    }
                    lines.push(format!("{}={}", body, data));
                }
                _ => return Err(anyhow!("unknown Tor reply separator: {}", separator)),
            }
        }
        Ok(lines)
    }
}

fn safecookie_hmac(
    key: &[u8],
    cookie: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).context("failed to initialize HMAC")?;
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn parse_kv_pairs(line: &str) -> HashMap<String, String> {
    split_quoted_fields(line)
        .into_iter()
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((key.to_string(), value.trim_matches('"').to_string()))
        })
        .collect()
}

fn flatten_reply(lines: &[String]) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in lines {
        for part in line.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                values.insert(key.to_string(), value.to_string());
            }
        }
    }
    values
}

fn split_quoted_fields(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ch if ch.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}
