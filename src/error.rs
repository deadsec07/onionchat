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
    #[error("invalid invite file")]
    InvalidInvite,
    #[error("invalid group invite file")]
    InvalidGroupInvite,
    #[error("invalid message signature")]
    InvalidMessageSignature,
    #[error("message encryption failed")]
    MessageEncryptionFailed,
    #[error("message decryption failed")]
    MessageDecryptionFailed,
    #[error("missing peer: {0}")]
    MissingPeer(String),
    #[error("missing peer encryption key: {0}")]
    MissingPeerEncryptionKey(String),
    #[error("missing group: {0}")]
    MissingGroup(String),
    #[error("group requires at least one peer")]
    EmptyGroup,
    #[error("sender is not a member of group: {0}")]
    UnauthorizedGroupSender(String),
    #[error("group owner mismatch")]
    GroupOwnerMismatch,
    #[error("group invite revision is not newer")]
    StaleGroupRevision,
    #[error("only the group owner can export or update this group")]
    NotGroupOwner,
}
