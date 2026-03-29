use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "onionchat",
    version,
    about = "Minimal CLI chat over Tor onion services"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init,
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    Listen,
    Send {
        peer_onion: String,
        message: String,
    },
    Chat {
        peer_onion: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommands {
    Show,
}
