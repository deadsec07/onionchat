use crate::config::AppConfig;
use crate::error::OnionChatError;
use crate::identity::Identity;
use crate::storage::{now_unix, GroupRecord, PeerBook, Storage};
use crate::tor::{ActiveOnionService, TorController};
use crate::transport::{
    decrypt_message, encrypt_message, read_frame, sanitize_label, sanitize_terminal,
    validate_peer_onion, verify_group_invite, verify_invite, verify_message, write_frame,
    ContactCard, GroupInvite, GroupInviteFile, InviteFile, MessageEnvelope, MessagePayload,
};
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{info, warn};

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
    remember_peer(storage, &peer, None, None, None, "manual")?;

    let peers = storage.load_peer_book()?;
    let peer_record = peers
        .find(&peer)
        .ok_or_else(|| OnionChatError::MissingPeer(peer.clone()))?;
    let encryption_public_key = peer_record
        .encryption_public_key
        .as_deref()
        .ok_or_else(|| OnionChatError::MissingPeerEncryptionKey(peer.clone()))?;
    let (nonce, ciphertext) = encrypt_message(
        message,
        &identity.encryption_secret_key()?,
        encryption_public_key,
    )?;
    let mut envelope = MessageEnvelope::direct(identity.onion_address(), nonce, ciphertext);
    envelope.sign(&identity.signing_key()?)?;
    send_envelope(config, &peer, &envelope).await?;
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
    remember_peer(storage, &peer, None, None, None, "manual")?;

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

pub fn export_invite(
    storage: &Storage,
    identity: &Identity,
    display_name: Option<String>,
    output: Option<String>,
) -> Result<()> {
    let card = ContactCard {
        version: crate::transport::PROTOCOL_VERSION,
        display_name: sanitize_display_name(
            display_name.unwrap_or_else(|| "anonymous".to_string()),
        ),
        onion: identity.onion_address(),
        signing_public_key: identity.signing_public_key.clone(),
        encryption_public_key: identity.encryption_public_key.clone(),
        created_at_unix: now_unix(),
    };
    let signature = identity.sign_bytes(&card.canonical_bytes()?)?;
    let invite = InviteFile { card, signature };

    let path = output
        .map(Into::into)
        .unwrap_or_else(|| storage.paths.root.join("invite.json"));
    let raw = serde_json::to_vec_pretty(&invite).context("failed to serialize invite")?;
    storage.write_atomic(&path, &raw)?;
    println!("{}", path.display());
    Ok(())
}

pub fn import_invite(storage: &Storage, path: &str) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let invite: InviteFile = serde_json::from_str(&raw).context("failed to parse invite json")?;
    verify_invite(&invite)?;
    remember_peer(
        storage,
        &invite.card.onion,
        Some(invite.card.display_name.clone()),
        Some(invite.card.signing_public_key.clone()),
        Some(invite.card.encryption_public_key.clone()),
        "invite",
    )?;
    println!(
        "imported {} ({})",
        invite.card.display_name, invite.card.onion
    );
    Ok(())
}

pub fn add_peer(storage: &Storage, peer_onion: &str, name: Option<String>) -> Result<()> {
    let peer = validate_peer_onion(peer_onion)?;
    remember_peer(storage, &peer, name, None, None, "manual")?;
    println!("saved {}.onion", peer);
    Ok(())
}

pub fn list_peers(storage: &Storage) -> Result<()> {
    let peers = storage.load_peer_book()?;
    if peers.peers.is_empty() {
        println!("no peers saved");
        return Ok(());
    }

    for peer in peers.peers {
        let label = peer.display_name.unwrap_or_else(|| "-".to_string());
        println!("{}\t{}\t{}", peer.onion, label, peer.source);
    }
    Ok(())
}

pub fn create_group(
    storage: &Storage,
    identity: &Identity,
    name: String,
    members: Vec<String>,
) -> Result<()> {
    let peers = storage.load_peer_book()?;
    let normalized_members = members
        .into_iter()
        .map(|member| {
            let onion = validate_peer_onion(&member)?;
            if peers.find(&onion).is_none() {
                return Err(OnionChatError::MissingPeer(onion).into());
            }
            Ok(onion)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut groups = storage.load_group_book()?;
    let group = groups.create_group(
        sanitize_display_name(name),
        identity.service_id.clone(),
        identity.signing_public_key.clone(),
        normalized_members,
    )?;
    storage.save_group_book(&groups)?;
    println!("{}\t{}\t{}", group.id, group.name, group.members.join(","));
    Ok(())
}

pub fn list_groups(storage: &Storage) -> Result<()> {
    let groups = storage.load_group_book()?;
    if groups.groups.is_empty() {
        println!("no groups saved");
        return Ok(());
    }

    for group in groups.groups {
        println!(
            "{}\t{}\t{}\tr{}",
            group.id,
            group.name,
            group.members.len(),
            group.revision
        );
    }
    Ok(())
}

pub fn show_group(storage: &Storage, group_id: &str) -> Result<()> {
    let groups = storage.load_group_book()?;
    let group = groups
        .find(group_id)
        .ok_or_else(|| OnionChatError::MissingGroup(group_id.to_string()))?;
    println!("id: {}", group.id);
    println!("name: {}", group.name);
    if !group.owner.is_empty() {
        println!("owner: {}.onion", group.owner);
    }
    println!("revision: {}", group.revision);
    println!("members:");
    for member in &group.members {
        println!("- {}.onion", member);
    }
    Ok(())
}

pub fn export_group(
    storage: &Storage,
    identity: &Identity,
    group_id: &str,
    output: Option<String>,
) -> Result<()> {
    let mut groups = storage.load_group_book()?;
    let group = groups
        .find_mut(group_id)
        .ok_or_else(|| OnionChatError::MissingGroup(group_id.to_string()))?;

    if group.owner.is_empty() {
        group.owner = identity.service_id.clone();
        group.owner_signing_public_key = identity.signing_public_key.clone();
        if !group.members.iter().any(|member| member == &group.owner) {
            group.members.push(group.owner.clone());
            group.members.sort();
            group.members.dedup();
        }
        if group.revision == 0 {
            group.revision = 1;
        }
    }

    if group.owner != identity.service_id {
        return Err(OnionChatError::NotGroupOwner.into());
    }

    let group = group.clone();

    let invite_group = GroupInvite {
        version: crate::transport::PROTOCOL_VERSION,
        group_id: group.id.clone(),
        group_name: group.name.clone(),
        owner: group.owner.clone(),
        owner_signing_public_key: group.owner_signing_public_key.clone(),
        members: group.members.clone(),
        revision: group.revision,
        created_at_unix: group.created_at_unix,
    };
    let signature = identity.sign_bytes(&invite_group.canonical_bytes()?)?;
    let invite = GroupInviteFile {
        group: invite_group,
        signature,
    };
    storage.save_group_book(&groups)?;

    let file_name = format!("group-{}.json", group.id);
    let path = output
        .map(Into::into)
        .unwrap_or_else(|| storage.paths.root.join(file_name));
    let raw = serde_json::to_vec_pretty(&invite).context("failed to serialize group invite")?;
    storage.write_atomic(&path, &raw)?;
    println!("{}", path.display());
    Ok(())
}

pub fn import_group(storage: &Storage, path: &str) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {}", path))?;
    let invite: GroupInviteFile =
        serde_json::from_str(&raw).context("failed to parse group invite json")?;
    verify_group_invite(&invite)?;

    let peers = storage.load_peer_book()?;
    if let Some(owner_peer) = peers.find(&invite.group.owner) {
        if let Some(saved_key) = &owner_peer.signing_public_key {
            if saved_key != &invite.group.owner_signing_public_key {
                return Err(OnionChatError::GroupOwnerMismatch.into());
            }
        }
    }

    let mut members = invite.group.members.clone();
    members.sort();
    members.dedup();
    let record = GroupRecord {
        id: invite.group.group_id.clone(),
        name: sanitize_display_name(invite.group.group_name.clone()),
        members,
        owner: invite.group.owner.clone(),
        owner_signing_public_key: invite.group.owner_signing_public_key.clone(),
        revision: invite.group.revision,
        created_at_unix: invite.group.created_at_unix,
    };

    let mut groups = storage.load_group_book()?;
    if let Some(existing) = groups.find(&record.id) {
        if !existing.owner.is_empty() && existing.owner != record.owner {
            return Err(OnionChatError::GroupOwnerMismatch.into());
        }
        if !existing.owner_signing_public_key.is_empty()
            && existing.owner_signing_public_key != record.owner_signing_public_key
        {
            return Err(OnionChatError::GroupOwnerMismatch.into());
        }
        if record.revision <= existing.revision {
            return Err(OnionChatError::StaleGroupRevision.into());
        }
    }
    groups.upsert_group(record.clone());
    storage.save_group_book(&groups)?;
    println!(
        "imported group {} ({}) revision {}",
        record.name, record.id, record.revision
    );
    Ok(())
}

pub fn update_group_members(
    storage: &Storage,
    identity: &Identity,
    group_id: &str,
    members: Vec<String>,
) -> Result<()> {
    let peers = storage.load_peer_book()?;
    let normalized_members = members
        .into_iter()
        .map(|member| {
            let onion = validate_peer_onion(&member)?;
            if peers.find(&onion).is_none() {
                return Err(OnionChatError::MissingPeer(onion).into());
            }
            Ok(onion)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut groups = storage.load_group_book()?;
    let group = groups
        .find_mut(group_id)
        .ok_or_else(|| OnionChatError::MissingGroup(group_id.to_string()))?;

    if group.owner.is_empty() {
        group.owner = identity.service_id.clone();
        group.owner_signing_public_key = identity.signing_public_key.clone();
        if group.revision == 0 {
            group.revision = 1;
        }
    }
    if group.owner != identity.service_id {
        return Err(OnionChatError::NotGroupOwner.into());
    }

    let mut normalized = normalized_members;
    normalized.push(group.owner.clone());
    normalized.sort();
    normalized.dedup();
    group.members = normalized;
    group.revision += 1;
    let group = group.clone();
    storage.save_group_book(&groups)?;
    println!(
        "{}\t{}\t{}\tr{}",
        group.id,
        group.name,
        group.members.join(","),
        group.revision
    );
    Ok(())
}

pub async fn send_group_message(
    storage: &Storage,
    config: &AppConfig,
    identity: &Identity,
    group_id: &str,
    message: &str,
) -> Result<()> {
    let groups = storage.load_group_book()?;
    let group = groups
        .find(group_id)
        .cloned()
        .ok_or_else(|| OnionChatError::MissingGroup(group_id.to_string()))?;
    let peers = storage.load_peer_book()?;
    fan_out_group(config, &group, &peers, identity, message).await?;
    println!("sent to group {}", group.name);
    Ok(())
}

pub async fn interactive_group_chat(
    storage: &Storage,
    config: &AppConfig,
    identity: &Identity,
    group_id: &str,
) -> Result<()> {
    let groups = storage.load_group_book()?;
    let group = groups
        .find(group_id)
        .cloned()
        .ok_or_else(|| OnionChatError::MissingGroup(group_id.to_string()))?;

    let shutdown = Arc::new(Notify::new());
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind local group chat listener")?;
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
    println!("group: {} ({})", group.name, group.id);
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
        print!("group> ");
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

                if let Err(error) = send_group_message(storage, config, identity, group_id, line).await {
                    eprintln!("group send failed: {error:#}");
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
                        if let Ok(peer) = validate_peer_onion(&message.from) {
                            if let Err(error) = remember_peer(&storage, &peer, None, None, None, "inbound") {
                                warn!("failed to update peer book: {error:#}");
                            }
                        }
                        print_incoming(&storage, &message)?;
                    }
                    Err(error) => warn!("discarded malformed frame: {error:#}"),
                }
            }
        }
    }

    info!("listener stopped for {}", onion.onion_address);
    Ok(())
}

fn print_incoming(storage: &Storage, message: &MessageEnvelope) -> Result<()> {
    let peers = storage.load_peer_book()?;
    let groups = storage.load_group_book()?;
    let identity = Identity::load(storage)?;
    let from_onion =
        validate_peer_onion(&message.from).unwrap_or_else(|_| sanitize_terminal(&message.from));
    let peer = peers
        .find(&from_onion)
        .ok_or_else(|| OnionChatError::MissingPeer(from_onion.clone()))?;
    let signing_public_key = peer
        .signing_public_key
        .as_deref()
        .ok_or_else(|| OnionChatError::MissingPeer(from_onion.clone()))?;
    verify_message(message, signing_public_key)?;
    let from_label = peer
        .display_name
        .clone()
        .unwrap_or_else(|| from_onion.clone());
    let encryption_public_key = peer
        .encryption_public_key
        .as_deref()
        .ok_or_else(|| OnionChatError::MissingPeerEncryptionKey(from_onion.clone()))?;
    let identity_secret = identity.encryption_secret_key()?;

    match &message.payload {
        MessagePayload::Direct { nonce, ciphertext } => {
            let body = decrypt_message(nonce, ciphertext, &identity_secret, encryption_public_key)?;
            println!("\n[{from_label}] {}", sanitize_terminal(&body));
        }
        MessagePayload::Group {
            group_id,
            group_name,
            nonce,
            ciphertext,
        } => {
            let group = groups
                .find(group_id)
                .ok_or_else(|| OnionChatError::MissingGroup(group_id.clone()))?;
            if !group.members.iter().any(|member| member == &from_onion) {
                return Err(OnionChatError::UnauthorizedGroupSender(group_id.clone()).into());
            }
            let body = decrypt_message(nonce, ciphertext, &identity_secret, encryption_public_key)?;
            println!(
                "\n[group:{}] [{}] {}",
                sanitize_terminal(group_name),
                from_label,
                sanitize_terminal(&body)
            );
        }
    }
    Ok(())
}

fn sanitize_display_name(name: String) -> String {
    let cleaned = sanitize_label(&name);
    if cleaned.is_empty() {
        "anonymous".to_string()
    } else {
        cleaned
    }
}

fn remember_peer(
    storage: &Storage,
    peer_onion: &str,
    name: Option<String>,
    signing_public_key: Option<String>,
    encryption_public_key: Option<String>,
    source: &str,
) -> Result<()> {
    let mut peers = storage.load_peer_book()?;
    peers.upsert(
        peer_onion,
        name.map(sanitize_display_name),
        signing_public_key,
        encryption_public_key,
        source,
    )?;
    peers.touch(peer_onion);
    storage.save_peer_book(&peers)?;
    Ok(())
}

async fn send_envelope(config: &AppConfig, peer: &str, envelope: &MessageEnvelope) -> Result<()> {
    let mut stream =
        TorController::connect_via_socks(config, peer, config.app.onion_virtual_port).await?;
    write_frame(&mut stream, envelope, config).await?;
    Ok(())
}

async fn fan_out_group(
    config: &AppConfig,
    group: &GroupRecord,
    peers: &PeerBook,
    identity: &Identity,
    message: &str,
) -> Result<()> {
    let mut failures = Vec::new();
    for member in &group.members {
        if member == &identity.service_id {
            continue;
        }
        let Some(peer) = peers.find(member) else {
            failures.push(format!("{}.onion: missing peer", member));
            continue;
        };
        let Some(encryption_public_key) = peer.encryption_public_key.as_deref() else {
            failures.push(format!("{}.onion: missing peer encryption key", member));
            continue;
        };
        let Ok((nonce, ciphertext)) = encrypt_message(
            message,
            &identity.encryption_secret_key()?,
            encryption_public_key,
        ) else {
            failures.push(format!("{}.onion: message encryption failed", member));
            continue;
        };
        let mut envelope = MessageEnvelope::group(
            identity.onion_address(),
            group.id.clone(),
            group.name.clone(),
            nonce,
            ciphertext,
        );
        envelope.sign(&identity.signing_key()?)?;
        if let Err(error) = send_envelope(config, member, &envelope).await {
            failures.push(format!("{}.onion: {error}", member));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(failures.join("\n")))
    }
}
