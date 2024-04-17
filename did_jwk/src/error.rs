use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsumerError {
    #[error("{0}")]
    Generic(String),
}

#[derive(Error, Debug)]
pub enum ProducerError {}
