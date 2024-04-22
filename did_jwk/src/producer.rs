use identity_iota::core::Object;
use identity_iota::verification::VerificationMethod;
use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument, storage::KeyId};
use identity_stronghold::StrongholdStorage;
use log::info;
use serde_json::json;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;
use std::io::ErrorKind;

// See specification: "Since did:jwk only contains a single key, the DID URL fragment identifier is always a fixed #0 value."
const FRAGMENT: &str = "0";

pub async fn produce_did_jwk(storage: JwkStorageWrapper, key_id: &str) -> Result<CoreDocument, Error> {
    // let stronghold_secret_manager = StrongholdSecretManager::builder()
    //     .password(Password::from("secure_password".to_owned()))
    //     .build(random_stronghold_path())
    //     .unwrap();

    // identity.rs
    // let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

    // IOTA SDK
    // let secret_manager: SecretManager = SecretManager::Stronghold(stronghold_secret_manager);

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => {
            stronghold_storage.get_public_key(&KeyId::new(key_id)).await.unwrap()
        }
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.to_json_value().unwrap()).unwrap();

    info!("Producing did:jwk for key_id=[{:?}] ...", key_id);

    if let Some(did_str) = did_jwk_extern::DIDJWK.generate(&Source::Key(&jwk)) {
        info!("DID: {:?}", did_str);

        let controller = CoreDID::parse(did_str).unwrap();

        let verification_method =
            VerificationMethod::new_from_jwk(controller.clone(), public_key_jwk.clone(), Some(FRAGMENT)).unwrap();

        let mut properties = Object::new();
        properties.insert(
            "@context".to_string(),
            json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1" // TODO: make dynamic
            ]),
        );

        let document = CoreDocument::builder(properties)
            .id(controller)
            .verification_method(verification_method)
            .build()
            .unwrap();

        info!("DID Document: {}", document.to_json_pretty().unwrap());

        return Ok(document);
    };

    Err(Error::new(ErrorKind::Other, "Done without result"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use shared::test_utils::new_stronghold;
    use test_log::test;

    #[test(tokio::test)]
    async fn produces_did_jwk() {
        let (stronghold_storage, key_id) = new_stronghold().await;

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_storage));
        let document = produce_did_jwk(storage, key_id.as_str()).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
              ],
              "id": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ",
              "verificationMethod": [
                {
                  "id": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ#0",
                  "type": "JsonWebKey",
                  "controller": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ",
                  "publicKeyJwk": {
                    "kty": "OKP",
                    "alg": "EdDSA",
                    "kid": "SFICW73HCwJoBTCiACF1E3Wmrh5LE0xj_G1JVSeXS-M",
                    "crv": "Ed25519",
                    "x": "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88"
                  }
                }
              ]
            })
        );
    }
}
