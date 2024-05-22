use identity_iota::core::FromJson;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::VerificationMethod;
use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument};
use log::info;
use serde_json::json;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;
use std::io::ErrorKind;

// See specification: "Since did:jwk only contains a single key, the DID URL fragment identifier is always a fixed #0 value."
const FRAGMENT: &str = "0";

pub async fn produce_did_jwk(storage: JwkStorageWrapper, key_id: &str) -> Result<CoreDocument, Error> {
    // FIX THIS: fix error
    let public_key_jwk = storage.get_public_key_jwk(key_id).await.unwrap();

    info!("Producing did:jwk for key_id=[{:?}] ...", key_id);

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.clone()).unwrap();

    if let Some(did_str) = did_jwk_extern::DIDJWK.generate(&Source::Key(&jwk)) {
        info!("DID: {:?}", did_str);

        let controller = CoreDID::parse(did_str).unwrap();

        let verification_method = VerificationMethod::new_from_jwk(
            controller.clone(),
            Jwk::from_json_value(public_key_jwk).unwrap(),
            Some(FRAGMENT),
        )
        .unwrap();

        let properties = storage.get_properties();

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
    use shared::test_utils::new_stronghold_storage;
    use test_log::test;

    #[test(tokio::test)]
    async fn produces_did_jwk_eddsa() {
        let (stronghold_storage, key_id, _) = new_stronghold_storage().await;

        let storage = JwkStorageWrapper::Stronghold(stronghold_storage);
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

    // TODO: implement `StrongholdExt::insert`
    // #[test(tokio::test)]
    // async fn produces_did_jwk_es256() {
    // let (stronghold_ext_storage, _, key_id) = new_stronghold_ext_storage().await;

    //     let storage = JwkStorageWrapper::StrongholdExt(stronghold_ext_storage);
    //     let document = produce_did_jwk(storage, key_id.as_str()).await.unwrap();

    //     assert_eq!(
    //         document.to_json_value().unwrap(),
    //         json!({
    //           "@context": [
    //             "https://www.w3.org/ns/did/v1",
    //             "https://w3id.org/security/suites/jws-2020/v1"
    //           ],
    //           "id": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ",
    //           "verificationMethod": [
    //             {
    //               "id": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ#0",
    //               "type": "JsonWebKey",
    //               "controller": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ",
    //               "publicKeyJwk": {
    //                 "kty": "OKP",
    //                 "alg": "ECDSA",
    //                 "kid": "_",
    //                 "crv": "P-256",
    //                 "x": "_",
    //                 "y": "_"
    //               }
    //             }
    //           ]
    //         })
    //     );
    // }
}
