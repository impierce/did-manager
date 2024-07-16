use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsumerError {
    #[error("{0}")]
    Generic(String),
    #[error("Identity error: `{0}`")]
    IdentityDidError(#[from] identity_iota::did::Error),
    #[error("Identity error: `{0}`")]
    IdentityResolverError(#[from] identity_iota::resolver::Error),
    #[error("Client error: `{0}`")]
    ClientError(#[from] iota_sdk::client::error::Error),
}

#[derive(Error, Debug)]
pub enum ProducerError {
    #[error("Identity error: `{0}`")]
    KeyStorageError(#[from] identity_iota::core::SingleStructError<identity_iota::storage::KeyStorageErrorKind>),
    #[error("Identity error: `{0}`")]
    IdentityDidError(#[from] identity_iota::did::Error),
    #[error("Identity error: `{0}`")]
    IdentityResolverError(#[from] identity_iota::resolver::Error),
    #[error("No `{0}` `KeyId` available")]
    MissingKeyIdError(String),
    #[error("Generic producer error: `{0}`")]
    Generic(String),
}
