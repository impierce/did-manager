use iota_sdk::types::block::address::Bech32Address;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsumerError {
    #[error("{0}")]
    Generic(String),
    #[error("Identity error: `{0}`")]
    IdentityDidError(#[from] identity_iota::did::Error),
    #[error("Identity error: `{0}`")]
    IdentityResolverError(#[from] identity_iota::resolver::Error),
    #[error("SDK error: `{0}`")]
    SdkError(#[from] iota_sdk::client::error::Error),
}

#[derive(Error, Debug)]
pub enum ProducerError {
    #[error("Generic producer error: `{0}`")]
    Generic(String),
    #[error("IOTA SDK - Client error: `{0}`")]
    ClientError(#[from] iota_sdk::client::Error),
    #[error("Wallet error: `{0}`")]
    WalletError(#[from] WalletError),
    #[error("Identity error: `{0}`")]
    IdentityIotaError(#[from] identity_iota::iota::Error),
    #[error("Identity error: `{0}`")]
    IdentityIotaBlockError(#[from] identity_iota::iota::block::Error),
    #[error("Identity error: `{0}`")]
    IdentityCoreError(#[from] identity_iota::core::Error),
    #[error("Stronghold error: `{0}`")]
    StrongholdError(#[from] iota_stronghold::ClientError),
}

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Wallet error: `{0}`")]
    Generic(String),
    #[error("Insufficient funds for storage deposit. Please send {required_amount:?} tokens to `{funding_address:?}`")]
    InsufficientFunds {
        required_amount: u64,
        funding_address: Bech32Address,
    },
    #[error("IOTA SDK - Wallet error: `{0}`")]
    WalletError(#[from] iota_sdk::wallet::Error),
    #[error("IOTA SDK - Client error: `{0}`")]
    ClientError(#[from] iota_sdk::client::Error),
}
