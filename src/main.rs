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
use cli::{Cli, Commands, IdentityCommands};
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
