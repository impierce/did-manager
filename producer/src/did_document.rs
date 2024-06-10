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
        alg: JwsAlgorithm,
    ) -> Result<CoreDocument, ProducerError> {
        let (storage, key_id) = match alg {
            JwsAlgorithm::EdDSA => (
                JwkStorageWrapper::Stronghold(self.stronghold_storage.clone()),
                self.ed25519_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("No Ed25519 key present".to_string()))?
                    .as_str(),
            ),
            JwsAlgorithm::ES256 => (
                JwkStorageWrapper::StrongholdExt(self.stronghold_ext_storage.clone()),
                self.es256_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("No ES256 key present".to_string()))?
                    .as_str(),
            ),
            JwsAlgorithm::ES256K => (
                JwkStorageWrapper::StrongholdExt(self.stronghold_ext_storage.clone()),
                self.es256k_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("No ES256K key present".to_string()))?
                    .as_str(),
            ),
            _ => return Err(ProducerError::Generic("Unsupported JWS algorithm".to_string())),
        };

        let host: url::Host = url::Host::parse("localhost").unwrap(); // TODO
        let port: Option<u16> = None; // TODO: default?

        let core_document: Option<CoreDocument> = match did_method {
            DidMethod::Jwk => {
                let core_document = did_jwk::producer::produce_did_jwk(storage, key_id, alg).await.unwrap();
                Some(core_document)
            }
            DidMethod::Key => {
                let core_document = did_key::producer::produce_did_key(storage, key_id, alg).await.unwrap();
                Some(core_document)
            }
            DidMethod::Web => {
                let core_document = did_web::producer::produce_did_web(storage, key_id, host, port, alg)
                    .await
                    .unwrap();
                Some(core_document)
            }
            DidMethod::ShimmerTestnet => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Testnet,
                    JwsAlgorithm::EdDSA,
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
                    JwsAlgorithm::EdDSA,
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
                    JwsAlgorithm::EdDSA,
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
    use shared::test_utils::random_stronghold_path;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/full.stronghold";
    const PASSWORD: &str = "sup3rSecr3t";
    const KEY_ID_ED25519: &str = "ed25519-0";
    const KEY_ID_ES256: &str = "es256-0";
    const KEY_ID_ES256K: &str = "es256k-0";

    #[test(tokio::test)]
    async fn create_document_from_generated_stronghold() {
        let secret_manager = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            PASSWORD.to_owned(),
        )
        .await
        .unwrap();

        // TODO: Some(url::Host::parse("localhost").unwrap()), Some(8080)
        let document = secret_manager
            .produce_document(DidMethod::Jwk, JwsAlgorithm::EdDSA)
            .await;

        // info!("Document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[test(tokio::test)]
    async fn recreate_expected_document_from_existing_ed25519_key() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID_ED25519.to_owned()),
            Some(KEY_ID_ES256.to_owned()),
            Some(KEY_ID_ES256K.to_owned()),
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
                "kid": "D7k3xG5YQz62N4jUG8oUSYSITEQY-K9odBz3ecLFHIA",
                "crv": "Ed25519",
                "x": "fKTUgRvus4YXb_xQMJhQeQmkfufMS_R5B8qzVZh9k4E"
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
            Some(KEY_ID_ES256K.to_owned()),
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
                "kid": "rpX0Q107fZGt5BgEUQ9EcJ_NAdLHG3BNntiGF0nE21E",
                "crv": "P-256",
                "x": "h5NpEotjRlXMlcrgqZq0HAoeULbKzXuOVXyKs6dz4dA",
                "y": "GkwYGlSF5-uRJZ5pjJJXl3kKjfeZZLls_PC4mhDavYk"
            })
        )
    }

    #[test(tokio::test)]
    async fn recreate_expected_document_from_existing_es256k_key() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID_ED25519.to_owned()),
            Some(KEY_ID_ES256.to_owned()),
            Some(KEY_ID_ES256K.to_owned()),
            None,
            None,
        )
        .await
        .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, JwsAlgorithm::ES256K)
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
                "alg": "ES256K",
                "kid": "dcCeYlgGTGFHtlBHqurEsz-IARMY8o0lnA93B-VZJKA",
                "crv": "secp256k1",
                "x": "5iS4FSWKI-0t4-Q46IcGNm4u4zIGLQ26dg29O8dexsw",
                "y": "5zXAx1QXCsP8cnn4THW2wSbkp8OqbyAvcDO22Y3tRsY"
            })
        )
    }
}
