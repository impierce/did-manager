use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument, storage::KeyId};
use log::info;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;
use std::io::ErrorKind;

pub async fn produce_did_jwk(storage: JwkStorageWrapper, key_id: &str) -> std::result::Result<CoreDocument, Error> {
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

        let document = CoreDocument::builder(Default::default())
            .id(controller)
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

    #[tokio::test]
    async fn produces_did_jwk() {
        let (stronghold_storage, key_id) = new_stronghold_storage().await;

        let storage = JwkStorageWrapper::Stronghold(stronghold_storage);
        let result = produce_did_jwk(storage, key_id.as_str()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().id().to_string(), "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ")
    }
}
