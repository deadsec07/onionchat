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
    Invite {
        #[command(subcommand)]
        command: InviteCommands,
    },
    Peers {
        #[command(subcommand)]
        command: PeerCommands,
    },
    Groups {
        #[command(subcommand)]
        command: GroupCommands,
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

#[derive(Subcommand, Debug)]
pub enum InviteCommands {
    Export {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Import {
        path: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeerCommands {
    Add {
        peer_onion: String,
        #[arg(long)]
        name: Option<String>,
    },
    List,
}

#[derive(Subcommand, Debug)]
pub enum GroupCommands {
    Create {
        name: String,
        members: Vec<String>,
    },
    List,
    Show {
        group_id: String,
    },
    Export {
        group_id: String,
        #[arg(long)]
        output: Option<String>,
    },
    Import {
        path: String,
    },
    Update {
        group_id: String,
        members: Vec<String>,
    },
    Send {
        group_id: String,
        message: String,
    },
    Chat {
        group_id: String,
    },
}
