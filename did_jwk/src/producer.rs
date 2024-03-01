use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument, storage::KeyId};
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

    println!(
        "Producing DID for key_id=[{:?}] from storage=[{:?}] ...",
        key_id, "TODO_get_name"
    );

    if let Some(did_str) = did_jwk_extern::DIDJWK.generate(&Source::Key(&jwk)) {
        println!("DID: {:?}", did_str);

        let controller = CoreDID::parse(did_str).unwrap();

        let document = CoreDocument::builder(Default::default())
            .id(controller)
            .build()
            .unwrap();

        return Ok(document);
    };

    Err(Error::new(ErrorKind::Other, "Done without result"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::storage::JwkStorage;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use shared::test_utils::{get_test_jwk, random_stronghold_path};

    #[tokio::test]
    async fn produces_did_jwk() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        // Create stronghold
        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();
        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

        let jwk = get_test_jwk();

        // Insert into stronghold
        let key_id = stronghold_storage.insert(jwk).await.unwrap();

        // println!("key_id: {:?}", key_id);

        // let storage = Storage::new(stronghold_storage.clone(), stronghold_storage.clone());
        let storage = JwkStorageWrapper::Stronghold(stronghold_storage);
        let result = produce_did_jwk(storage, key_id.as_str()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().id().to_string(), "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ")
    }
}
