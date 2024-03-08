use identity_iota::{core::ToJson, document::CoreDocument};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared::JwkStorageWrapper;

use crate::SecretManager;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Method {
    Jwk,
    Key,
    Web,
}

impl SecretManager {
    pub async fn produce_document_json(&self, method: Method) -> Result<Value, std::io::Error> {
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
                let core_document = did_key::producer::produce_did_from_key(storage, &self.key_id)
                    .await
                    .unwrap();
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
            Some(core_document) => Ok(core_document.to_json_value().unwrap()),
            None => Err(std::io::Error::other("No core_document produced")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::{json, ToJson};
    use shared::test_utils::random_stronghold_path;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[tokio::test]
    #[ignore]
    async fn create_document_from_generated_stronghold() {
        let secret_manager = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document_json(Method::Web).await;

        println!("document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[tokio::test]
    async fn recreate_expected_document_from_existing_stronghold() {
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document_json(Method::Web).await;

        assert_eq!(
            document
                .unwrap()
                .get("verificationMethod")
                .unwrap()
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .get("publicKeyJwk")
                .unwrap(),
            &json!({
                "kty": "OKP",
                "alg": "EdDSA",
                "kid": "aHq-0PIf6_ljLhyx4W86Gviqb-671OAI67E6vXpZc7Q",
                "crv": "Ed25519",
                "x": "P2BkYS6z4UHmsxn6FX1oHsyx7eiUSFEMJ1D_RC8M0-w"
            })
        )
    }
}
