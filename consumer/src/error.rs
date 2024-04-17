use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsumerError {
    #[error("{0}")]
    Generic(String),
    #[error("Identity error: `{0}`")]
    IdentityDidError(#[from] identity_iota::did::Error),
    #[error("Identity error: `{0}`")]
    IdentityResolverError(#[from] identity_iota::resolver::Error),
}
