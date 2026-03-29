use thiserror::Error;

#[derive(Debug, Error)]
pub enum OnionChatError {
    #[error("tor control authentication failed: {0}")]
    TorAuth(String),
    #[error("tor control protocol error: {0}")]
    TorProtocol(String),
    #[error("invalid onion address")]
    InvalidOnionAddress,
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),
    #[error("missing identity; run `onionchat init` first")]
    MissingIdentity,
}
