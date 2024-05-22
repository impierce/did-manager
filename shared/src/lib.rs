pub mod error;
pub mod test_utils;

use error::ProducerError;
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
    // FIX THIS: errors and comment
    // Use `public_key_jwk` as a `serde_json::Value` here because `StrongholdStorage` and `StrongholdExtStorage` utilize
    // conflicting `KeyId` types.
    pub async fn get_public_key_jwk(&self, key_id: &str) -> Result<serde_json::Value, ProducerError> {
        Ok(match self {
            JwkStorageWrapper::Stronghold(ref stronghold_storage) => {
                json!(stronghold_storage
                    .get_public_key(&identity_iota::storage::KeyId::new(key_id))
                    .await
                    .unwrap())
            }
            JwkStorageWrapper::StrongholdExt(ref stronghold_ext_storage) => json!(stronghold_ext_storage
                .get_public_key(&identity_storage::KeyId::new(key_id))
                .await
                .unwrap()),
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
