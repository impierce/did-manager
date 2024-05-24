pub mod error;
pub mod test_utils;

use error::ProducerError;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_stronghold::StrongholdStorage;
use identity_stronghold_ext::StrongholdExtStorage;
use serde_json::json;
use std::collections::BTreeMap;

pub enum JwkStorageWrapper {
    Stronghold(StrongholdStorage),
    StrongholdExt(StrongholdExtStorage),
    PKCS11,
}

impl JwkStorageWrapper {
    // This function returns the `JWK` as a `serde_json::Value` object because `StrongholdStorage` and
    // `StrongholdExtStorage` don't return the same exact `Jwk` type.
    pub async fn get_public_key(&self, key_id: &str, alg: JwsAlgorithm) -> Result<serde_json::Value, ProducerError> {
        Ok(match self {
            JwkStorageWrapper::Stronghold(ref stronghold_storage) => match alg {
                JwsAlgorithm::EdDSA => json!(stronghold_storage
                    .get_public_key_with_type(
                        &identity_iota::storage::KeyId::new(key_id),
                        identity_stronghold::StrongholdKeyType::Ed25519
                    )
                    .await
                    .unwrap()),
                // TODO: throw ProducerError
                _ => unimplemented!(
                    "KeyType `{alg}` not supported! JwkStorageWrapper `Stronghold` only supports `EdDSA`"
                ),
            },
            JwkStorageWrapper::StrongholdExt(ref stronghold_ext_storage) => {
                // let alg = JwsAlgorithm::from_str(alg)
                //     .map_err(|_| ProducerError::Generic("Unsupported algorithm".to_string()))?;
                match alg {
                    JwsAlgorithm::ES256 => json!(stronghold_ext_storage
                        .get_es256_public_key(&identity_storage::KeyId::new(key_id))
                        .await
                        .unwrap()),
                    JwsAlgorithm::EdDSA => json!(stronghold_ext_storage
                        .get_ed25519_public_key(&identity_storage::KeyId::new(key_id))
                        .await
                        .unwrap()),
                    // TODO: throw ProducerError
                    _ => unimplemented!(
                        "KeyType `{alg}` not supported! JwkStorageWrapper `Stronghold` only supports [`ES256`, `EdDSA`]"
                    ),
                }
            }
            JwkStorageWrapper::PKCS11 => todo!(),
        })
    }

    pub fn get_properties(&self) -> BTreeMap<String, serde_json::Value> {
        let mut properties = BTreeMap::new();
        properties.insert(
            "@context".to_string(),
            match self {
                JwkStorageWrapper::Stronghold(_) => json!([
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ]),
                JwkStorageWrapper::StrongholdExt(_) => json!([
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1"
                ]),
                JwkStorageWrapper::PKCS11 => unimplemented!("PKCS11"),
            },
        );
        properties
    }
}
