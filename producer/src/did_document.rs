use identity_iota::did::CoreDID;
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

/// Some DID methods require additional parameters for producing a document.
pub enum MethodSpecificParameters {
    Web { origin: url::Origin },
}

impl SecretManager {
    pub async fn produce_document(
        &mut self,
        did_method: DidMethod,
        method_specific_parameters: Option<MethodSpecificParameters>,
        alg: JwsAlgorithm,
    ) -> Result<CoreDocument, ProducerError> {
        let (storage, key_id) = match alg {
            JwsAlgorithm::EdDSA => (
                JwkStorageWrapper::StrongholdExt(self.stronghold_ext_storage.clone()),
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

        // Try to retrieve from cache first
        let core_document: Option<CoreDocument> = match &mut self.cache {
            Some(cache) => match &self.did {
                Some(did) => {
                    let did = CoreDID::parse(did)?;
                    cache.retrieve(&did)
                }
                None => None,
            },
            None => None,
        };

        // Return the document if it was found in the cache
        if let Some(core_document) = core_document {
            return Ok(core_document);
        }

        // If cache miss, produce the document
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
                let origin = match method_specific_parameters {
                    Some(MethodSpecificParameters::Web { origin }) => origin,
                    None => {
                        return Err(ProducerError::Generic(
                            "Missing method-specific parameters for `did:web`".to_string(),
                        ))
                    }
                };
                let core_document = did_web::producer::produce_did_web(storage, key_id, origin, alg)
                    .await
                    .unwrap();
                Some(core_document)
            }
            DidMethod::ShimmerTestnet => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Testnet,
                    alg,
                    IotaDID::parse(self.did.as_ref().expect("externally managed `DID` not specified"))?,
                    self.fragment
                        .clone()
                        .expect("externally managed `fragment` not specified")
                        .to_string(),
                )
                .await
                .unwrap();
                if let Some(cache) = &mut self.cache {
                    cache.insert(core_document.clone());
                }
                Some(core_document)
            }
            DidMethod::Shimmer => {
                let core_document = did_iota::produce::produce_did_iota(
                    &storage,
                    key_id,
                    did_iota::produce::IotaMethod::Shimmer,
                    alg,
                    IotaDID::parse(self.did.as_ref().expect("externally managed `DID` not specified"))?,
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
                    alg,
                    IotaDID::parse(self.did.as_ref().expect("externally managed `DID` not specified"))?,
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

    use crate::cache::InMemoryCache;

    use identity_iota::core::{json, ToJson};
    use log::info;
    use shared::test_utils::random_stronghold_path;
    use std::time::Instant;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "../shared/tests/res/all_slots.stronghold";
    const PASSWORD: &str = "sup3rSecr3t";

    #[test(tokio::test)]
    async fn create_document_from_generated_stronghold() {
        let mut secret_manager = SecretManager::builder()
            .snapshot_path(random_stronghold_path().to_str().unwrap())
            .password(PASSWORD)
            .build()
            .await
            .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, None, JwsAlgorithm::EdDSA)
            .await;

        assert!(document.is_ok())
    }

    #[test(tokio::test)]
    async fn recreate_expected_document_from_existing_ed25519_key() {
        let mut secret_manager = SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password(PASSWORD)
            .build()
            .await
            .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, None, JwsAlgorithm::EdDSA)
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
        let mut secret_manager = SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password(PASSWORD)
            .build()
            .await
            .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, None, JwsAlgorithm::ES256)
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
        let mut secret_manager = SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password(PASSWORD)
            .build()
            .await
            .unwrap();

        let document = secret_manager
            .produce_document(DidMethod::Jwk, None, JwsAlgorithm::ES256K)
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

    #[ignore = "This test needs to be updated to use `Devnet`"]
    #[test(tokio::test)]
    async fn cached_did_document_is_returned() {
        let mut secret_manager = SecretManager::builder()
            .snapshot_path("../shared/tests/res/selv.stronghold")
            .password("VNvRtH4tKyWwvJDpL6Vuc2aoLiKAecGQ")
            .with_ed25519_key("UVDxWhG2rB39FkaR7I27mHeUNrGtUgcr")
            .with_did("did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90")
            .with_fragment("bQKQRzaop7CgEvqVq8UlgLGsdF-R-hnLFkKFZqW2VN0")
            .with_cache(InMemoryCache::builder().build())
            .build()
            .await
            .unwrap();

        // We measure the time it takes to produce the document intially
        let instant_before_with_empty_cache = Instant::now();

        let document = secret_manager
            .produce_document(DidMethod::ShimmerTestnet, None, JwsAlgorithm::EdDSA)
            .await;

        assert!(document.is_ok());

        let total_millis_uncached = instant_before_with_empty_cache.elapsed().as_millis();

        // We measure the time again (with cached document)
        let instant_before_with_filled_cached = Instant::now();

        let document = secret_manager
            .produce_document(DidMethod::ShimmerTestnet, None, JwsAlgorithm::EdDSA)
            .await;

        assert!(document.is_ok());

        let total_millis_cached = instant_before_with_filled_cached.elapsed().as_millis();

        info!(
            "Time to produce document: empty cache: {}ms, filled cache: {}ms",
            total_millis_uncached, total_millis_cached
        );

        assert!(total_millis_uncached > total_millis_cached);
    }
}
