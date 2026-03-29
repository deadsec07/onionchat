use crate::config::AppConfig;
use crate::identity::Identity;
use crate::storage::Storage;
use crate::tor::{ActiveOnionService, TorController};
use crate::transport::{
    read_frame, sanitize_terminal, validate_peer_onion, write_frame, MessageEnvelope,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerBook {
    pub peers: BTreeMap<String, PeerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub last_used_unix: u64,
}

pub async fn listen(storage: &Storage, config: &AppConfig, identity: &Identity) -> Result<()> {
    let shutdown = Arc::new(Notify::new());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind local listener")?;
    let local_port = listener.local_addr()?.port();

    let mut tor = TorController::connect(config).await?;
    tor.authenticate().await?;
    let onion = tor
        .publish_onion(
            &identity.private_key,
            config.app.onion_virtual_port,
            local_port,
        )
        .await?;

    println!("listening on {}", onion.onion_address);
    println!("press Ctrl+C to stop");

    let serve = run_listener(
        listener,
        storage.clone(),
        config.clone(),
        onion.clone(),
        shutdown.clone(),
    );
    tokio::select! {
        result = serve => result?,
        result = tokio::signal::ctrl_c() => {
            result.context("failed waiting for Ctrl+C")?;
        }
    }

    shutdown.notify_waiters();
    let _ = tor.delete_onion(&onion.service_id).await;
    Ok(())
}

pub async fn send_message(
    storage: &Storage,
    config: &AppConfig,
    identity: &Identity,
    peer_onion: &str,
    message: &str,
) -> Result<()> {
    let peer = validate_peer_onion(peer_onion)?;
    record_peer(storage, &peer)?;

    let mut stream =
        TorController::connect_via_socks(config, &peer, config.app.onion_virtual_port).await?;
    let envelope = MessageEnvelope::new(identity.onion_address(), message.to_string());
    write_frame(&mut stream, &envelope, config).await?;
    println!("sent to {}.onion", peer);
    Ok(())
}

pub async fn interactive_chat(
    storage: &Storage,
    config: &AppConfig,
    identity: &Identity,
    peer_onion: &str,
) -> Result<()> {
    let peer = validate_peer_onion(peer_onion)?;
    record_peer(storage, &peer)?;

    let shutdown = Arc::new(Notify::new());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind local chat listener")?;
    let local_port = listener.local_addr()?.port();

    let mut tor = TorController::connect(config).await?;
    tor.authenticate().await?;
    let onion = tor
        .publish_onion(
            &identity.private_key,
            config.app.onion_virtual_port,
            local_port,
        )
        .await?;

    println!("your onion: {}", onion.onion_address);
    println!("chat peer: {}.onion", peer);
    println!("type messages, or /quit to exit");

    let listener_task = tokio::spawn(run_listener(
        listener,
        storage.clone(),
        config.clone(),
        onion.clone(),
        shutdown.clone(),
    ));

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    loop {
        print!("> ");
        io::stdout().flush().ok();

        tokio::select! {
            signal_result = tokio::signal::ctrl_c() => {
                signal_result.context("failed waiting for Ctrl+C")?;
                break;
            }
            next_line = lines.next_line() => {
                let Some(line) = next_line.context("stdin failed")? else {
                    break;
                };

                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if line == "/quit" || line == "/exit" {
                    break;
                }

                if let Err(error) = send_message(storage, config, identity, &peer, line).await {
                    eprintln!("send failed: {error:#}");
                }
            }
        }
    }

    shutdown.notify_waiters();
    listener_task.abort();
    let _ = tor.delete_onion(&onion.service_id).await;
    Ok(())
}

async fn run_listener(
    listener: TcpListener,
    storage: Storage,
    config: AppConfig,
    onion: ActiveOnionService,
    shutdown: Arc<Notify>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accept = listener.accept() => {
                let (mut socket, _) = accept.context("accept failed")?;
                match read_frame(&mut socket, &config).await {
                    Ok(message) => {
                        let from = sanitize_terminal(&message.from);
                        let body = sanitize_terminal(&message.body);
                        println!("\n[{from}] {body}");
                        if let Ok(peer) = validate_peer_onion(&from) {
                            if let Err(error) = record_peer(&storage, &peer) {
                                warn!("failed to update peer book: {error:#}");
                            }
                        }
                    }
                    Err(error) => warn!("discarded malformed frame: {error:#}"),
                }
            }
        }
    }

    info!("listener stopped for {}", onion.onion_address);
    Ok(())
}

fn record_peer(storage: &Storage, peer_onion: &str) -> Result<()> {
    let mut peers = if storage.paths.peers_file.exists() {
        storage.read_json::<PeerBook>(&storage.paths.peers_file)?
    } else {
        PeerBook::default()
    };
    peers.peers.insert(
        peer_onion.to_string(),
        PeerRecord {
            last_used_unix: now_unix(),
        },
    );
    storage.write_json(&storage.paths.peers_file, &peers)?;
    Ok(())
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
