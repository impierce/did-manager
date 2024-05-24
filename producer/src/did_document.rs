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
            JwsAlgorithm::EdDSA => (
                JwkStorageWrapper::Stronghold(self.stronghold_storage.clone()),
                self.ed25519_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("ed25519".to_string()))?
                    .as_str(),
            ),
            JwsAlgorithm::ES256 => (
                JwkStorageWrapper::StrongholdExt(self.stronghold_ext_storage.clone()),
                self.es256_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("es256".to_string()))?
                    .as_str(),
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

    const SNAPSHOT_PATH: &str = "tests/res/multi.stronghold";
    const PASSWORD: &str = "sup3rSecr3t";
    const KEY_ID_ED25519: &str = "key-0";
    const KEY_ID_ES256: &str = "key-1";

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
    async fn recreate_expected_document_from_existing_ed25519_key() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID_ED25519.to_owned()),
            Some(KEY_ID_ES256.to_owned()),
            None,
            None,
        )
        .await
        .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, JwsAlgorithm::EdDSA)
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
                "kid": "f02ShYrak2enzU2hKa9BKy-v7HGK3sUp3XlE4bojcX0",
                "crv": "Ed25519",
                "x": "7aKj0vjMYobg_4Mh5MatFHeDFEiiYtH_-ghj91X_SLQ"
            })
        )
    }

    #[test(tokio::test)]
    async fn recreate_expected_document_from_existing_es256_key() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID_ED25519.to_owned()),
            Some(KEY_ID_ES256.to_owned()),
            None,
            None,
        )
        .await
        .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, JwsAlgorithm::ES256)
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
                "kty": "EC",
                "alg": "ES256",
                "kid": "0aHqNxJebHBv1ae8HJMABzCCN0fmaRbaoqgfLnLCFBE",
                "crv": "P-256",
                "x": "qVu_ZGlQoS4sLOJgmhW67IsxDQqm94KWOUI4-QAk1q0",
                "y": "wY2tkzhYaZw5llZf-QNDx03OQVM1J6_h9-ml7kTUiUw"
            })
        )
    }
}
