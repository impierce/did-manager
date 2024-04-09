use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProducerError {
    #[error("Generic producer error: `{0}`")]
    Generic(String),
}
