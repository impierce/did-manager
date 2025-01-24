pub mod cache;
pub mod did_document;
pub mod secret_manager;
pub mod signature;

pub use crate::did_document::MethodSpecificParameters;
pub use crate::secret_manager::{generate, SecretManager};
pub use did_web;
pub use identity_iota::document::CoreDocument;
