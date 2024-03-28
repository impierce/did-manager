use identity_iota::document::CoreDocument;
use serde::{Deserialize, Serialize};
use shared::JwkStorageWrapper;

use crate::SecretManager;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Method {
    #[serde(rename = "did:jwk")]
    Jwk,
    #[serde(rename = "did:key")]
    Key,
    #[serde(rename = "did:web")]
    Web,
}

impl SecretManager {
    pub async fn produce_document(&self, method: Method) -> Result<CoreDocument, std::io::Error> {
        let storage = JwkStorageWrapper::Stronghold(self.stronghold_storage.clone());

        let host: Option<url::Host> = Some(url::Host::parse("localhost").unwrap()); // TODO
        let port: Option<u16> = None; // TODO

        let core_document: Option<CoreDocument> = match method {
            Method::Jwk => {
                let core_document = did_jwk::producer::produce_did_jwk(storage, self.key_id.as_str())
                    .await
                    .unwrap();
                Some(core_document)
            }
            Method::Key => {
                let core_document = did_key::producer::produce_did_key(storage, &self.key_id).await.unwrap();
                Some(core_document)
            }
            Method::Web => {
                let core_document =
                    did_web::producer::produce_did_web(storage, &self.key_id, host.expect("host not specified"), port)
                        .await
                        .unwrap();
                Some(core_document)
            }
        };

        match core_document {
            Some(core_document) => Ok(core_document),
            None => Err(std::io::Error::other("No core_document produced")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::{json, ToJson};
    use log::info;
    use shared::test_utils::random_stronghold_path;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[tokio::test]
    async fn create_document_from_generated_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let secret_manager = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document(Method::Web).await;

        info!("document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[tokio::test]
    async fn recreate_expected_document_from_existing_stronghold() {
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document(Method::Web).await;

        assert_eq!(
            document
                .unwrap()
                .verification_method()
                .first()
                .unwrap()
                .data()
                .public_key_jwk()
                .unwrap()
                .to_json_value()
                .unwrap(),
            json!({
                "kty": "OKP",
                "alg": "EdDSA",
                "kid": "aHq-0PIf6_ljLhyx4W86Gviqb-671OAI67E6vXpZc7Q",
                "crv": "Ed25519",
                "x": "P2BkYS6z4UHmsxn6FX1oHsyx7eiUSFEMJ1D_RC8M0-w"
            })
        )
    }
}
