mod chat;
mod cli;
mod config;
mod error;
mod identity;
mod storage;
mod tor;
mod transport;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, GroupCommands, IdentityCommands, InviteCommands, PeerCommands};
use config::AppConfig;
use identity::Identity;
use storage::Storage;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = Storage::discover()?;
    let config = AppConfig::load_or_create(&storage)?;

    init_logging(&config);

    match cli.command {
        Commands::Init => {
            let identity = Identity::create(&storage, &config).await?;
            println!("{}", identity.summary(&storage));
        }
        Commands::Identity { command } => match command {
            IdentityCommands::Show => {
                let identity = Identity::load(&storage)?;
                println!("{}", identity.summary(&storage));
            }
        },
        Commands::Invite { command } => {
            let identity = Identity::load(&storage)?;
            match command {
                InviteCommands::Export { name, output } => {
                    chat::export_invite(&storage, &identity, name, output)?;
                }
                InviteCommands::Import { path } => {
                    chat::import_invite(&storage, &path)?;
                }
            }
        }
        Commands::Peers { command } => match command {
            PeerCommands::Add { peer_onion, name } => {
                chat::add_peer(&storage, &peer_onion, name)?;
            }
            PeerCommands::List => {
                chat::list_peers(&storage)?;
            }
        },
        Commands::Groups { command } => {
            let identity = Identity::load(&storage)?;
            match command {
                GroupCommands::Create { name, members } => {
                    chat::create_group(&storage, &identity, name, members)?;
                }
                GroupCommands::List => {
                    chat::list_groups(&storage)?;
                }
                GroupCommands::Show { group_id } => {
                    chat::show_group(&storage, &group_id)?;
                }
                GroupCommands::Export { group_id, output } => {
                    chat::export_group(&storage, &identity, &group_id, output)?;
                }
                GroupCommands::Import { path } => {
                    chat::import_group(&storage, &path)?;
                }
                GroupCommands::Update { group_id, members } => {
                    chat::update_group_members(&storage, &identity, &group_id, members)?;
                }
                GroupCommands::Send { group_id, message } => {
                    chat::send_group_message(&storage, &config, &identity, &group_id, &message)
                        .await?;
                }
                GroupCommands::Chat { group_id } => {
                    chat::interactive_group_chat(&storage, &config, &identity, &group_id).await?;
                }
            }
        }
        Commands::Listen => {
            let identity = Identity::load(&storage)?;
            chat::listen(&storage, &config, &identity).await?;
        }
        Commands::Send {
            peer_onion,
            message,
        } => {
            let identity = Identity::load(&storage)?;
            chat::send_message(&storage, &config, &identity, &peer_onion, &message).await?;
        }
        Commands::Chat { peer_onion } => {
            let identity = Identity::load(&storage)?;
            chat::interactive_chat(&storage, &config, &identity, &peer_onion).await?;
        }
    }

    Ok(())
}

fn init_logging(config: &AppConfig) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("onionchat={}", config.app.log_level)))
        .unwrap_or_else(|_| EnvFilter::new("onionchat=info"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
