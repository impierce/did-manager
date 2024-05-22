use identity_iota::document::CoreDocument;
use identity_iota::iota::IotaDID;
use identity_iota::verification::jws::JwsAlgorithm;
use serde::{Deserialize, Serialize};
use shared::error::ProducerError;
use shared::JwkStorageWrapper;

use crate::SecretManager;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DidMethod {
    #[serde(rename = "did:jwk")]
    Jwk,
    #[serde(rename = "did:key")]
    Key,
    #[serde(rename = "did:web")]
    Web,
    #[serde(rename = "did:iota:rms")]
    ShimmerTestnet,
    #[serde(rename = "did:iota:smr")]
    Shimmer,
    #[serde(rename = "did:iota")]
    IotaMainnet,
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::json!(self).as_str().ok_or(std::fmt::Error)?)
    }
}

impl SecretManager {
    pub async fn produce_document(
        &self,
        did_method: DidMethod,
        jws_algorithm: JwsAlgorithm,
    ) -> Result<CoreDocument, ProducerError> {
        let (storage, key_id) = match jws_algorithm {
            JwsAlgorithm::ES256 => (
                JwkStorageWrapper::StrongholdExt(self.stronghold_ext_storage.clone()),
                self.es256_key_id.as_ref().unwrap().as_str(),
            ),
            JwsAlgorithm::EdDSA => (
                JwkStorageWrapper::Stronghold(self.stronghold_storage.clone()),
                self.ed25519_key_id.as_ref().unwrap().as_str(),
            ),
            _ => return Err(ProducerError::Generic("Unsupported JWS algorithm".to_string())),
        };

        let host: url::Host = url::Host::parse("localhost").unwrap(); // TODO
        let port: Option<u16> = None; // TODO: default?

        let core_document: Option<CoreDocument> = match did_method {
            DidMethod::Jwk => {
                let core_document = did_jwk::producer::produce_did_jwk(storage, key_id).await.unwrap();
                Some(core_document)
            }
            DidMethod::Key => {
                let core_document = did_key::producer::produce_did_key(storage, key_id).await.unwrap();
                Some(core_document)
            }
            DidMethod::Web => {
                let core_document = did_web::producer::produce_did_web(storage, key_id, host, port)
                    .await
                    .unwrap();
                Some(core_document)
            }
            DidMethod::ShimmerTestnet => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Testnet,
                    IotaDID::parse(self.did.clone().expect("externally managed `DID` not specified"))?,
                    self.fragment
                        .clone()
                        .expect("externally managed `fragment` not specified")
                        .to_string(),
                )
                .await
                .unwrap();
                Some(core_document)
            }
            DidMethod::Shimmer => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Shimmer,
                    IotaDID::parse(self.did.clone().expect("externally managed `DID` not specified"))?,
                    self.fragment
                        .clone()
                        .expect("externally managed `fragment` not specified")
                        .to_string(),
                )
                .await
                .unwrap();
                Some(core_document)
            }
            DidMethod::IotaMainnet => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Mainnet,
                    IotaDID::parse(self.did.clone().expect("externally managed `DID` not specified"))?,
                    self.fragment
                        .clone()
                        .expect("externally managed `fragment` not specified")
                        .to_string(),
                )
                .await
                .unwrap();
                Some(core_document)
            }
        };

        match core_document {
            Some(core_document) => Ok(core_document),
            None => Err(ProducerError::Generic("Failed to produce document".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::{json, ToJson};
    use log::info;
    use shared::test_utils::random_stronghold_path;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn create_document_from_generated_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let secret_manager = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager
            .produce_document(DidMethod::Web, JwsAlgorithm::EdDSA)
            .await;

        info!("Document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[test(tokio::test)]
    async fn recreate_expected_document_from_existing_stronghold() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID.to_owned()),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager
            .produce_document(DidMethod::Web, JwsAlgorithm::EdDSA)
            .await;

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
