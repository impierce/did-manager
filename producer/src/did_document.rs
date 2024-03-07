use identity_iota::{core::ToJson, document::CoreDocument, storage::KeyId};
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
        // TODO: remove this hard-coded value and replace it with: get_key_id(method_digest)
        // let key_id = KeyId::new("9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS");
        // self.stronghold_storage.
        // let public_key = self.stronghold_storage.get_public_key(&key_id).await.unwrap();
        // let signature = self.stronghold_storage.sign(&key_id, data, &public_key).await.unwrap();
        // Ok(signature)
        let storage = JwkStorageWrapper::Stronghold(self.stronghold_storage.clone());

        // TODO: remove this hard-coded value and replace it with: get_key_id(method_digest)
        let key_id = KeyId::new("9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS");

        let host: Option<url::Host> = Some(url::Host::parse("localhost").unwrap()); // TODO
        let port: Option<u16> = None; // TODO

        let core_document: Option<CoreDocument> = match method {
            Method::Jwk => {
                let core_document = did_jwk::producer::produce_did_jwk(storage, key_id.as_str())
                    .await
                    .unwrap();
                Some(core_document)
            }
            Method::Key => {
                let core_document = did_key::producer::produce_did_from_key(storage, &key_id).await.unwrap();
                Some(core_document)
            }
            Method::Web => {
                let core_document =
                    did_web::producer::produce_did_web(storage, &key_id, host.expect("host not specified"), port)
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

    #[tokio::test]
    #[ignore]
    async fn create_document_from_generated_stronghold() {
        let secret_manager = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            "secure_password".to_string(),
        )
        .unwrap();

        // TODO: , Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document_json(Method::Web).await;

        println!("document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[tokio::test]
    async fn recreate_expected_document_from_existing_stronghold() {
        let secret_manager =
            SecretManager::load("tests/res/test.stronghold".to_string(), "secure_password".to_string()).unwrap();

        // TODO: , Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager.produce_document_json(Method::Web).await;

        assert_eq!(
            document
                .unwrap()
                // .verification_method()
                // .first()
                // .unwrap()
                // .to_json_value()
                // .unwrap()
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
