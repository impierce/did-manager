use identity_iota::{
    core::ToJson,
    did::{CoreDID, DID},
    document::CoreDocument,
    storage::KeyId,
    verification::VerificationMethod,
};
use log::info;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;

pub async fn produce_did_key(storage: JwkStorageWrapper, key_id: &KeyId) -> std::result::Result<CoreDocument, Error> {
    // TODO: Check if key exists in key_id_storage, if not return error
    // let exists = storage.key_storage().exists(key_id).await.unwrap();

    // if !exists {
    //     return Err(Error::other(format!("Key with id=[{}] does not exist", key_id)));
    // }

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage.get_public_key(key_id).await.unwrap(),
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    info!("Producing did:key for key_id=[{:?}] ...", key_id.as_str(),);

    let did_str = did_method_key::DIDKey
        .generate(&Source::Key(
            &serde_json::from_str(&public_key_jwk.to_json().unwrap()).unwrap(),
        ))
        .unwrap();
    let did = CoreDID::parse(did_str).unwrap();
    info!("DID: {}", did);

    let verification_method =
        VerificationMethod::new_from_jwk(did.clone(), public_key_jwk.clone(), Some(did.method_id())).unwrap();

    let document = CoreDocument::builder(Default::default())
        .id(did)
        .verification_method(verification_method)
        .build()
        .unwrap();
    info!("DID Document: {}", document.to_json_pretty().unwrap());

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::ToJson;
    use identity_iota::storage::JwkStorage;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use shared::test_utils::{get_test_jwk, random_stronghold_path};

    #[tokio::test]
    async fn produces_did_key() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        info!("====== Preparing Stronghold");

        // Create stronghold
        let stronghold = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();

        let stronghold_storage = StrongholdStorage::new(stronghold);

        let jwk = get_test_jwk();

        // Insert into stronghold
        let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();
        info!("====== Done");

        let expected_did = did_method_key::DIDKey
            .generate(&Source::Key(&serde_json::from_str(&jwk.to_json().unwrap()).unwrap()))
            .unwrap();
        info!("Expected DID: {}", expected_did);

        let document = produce_did_key(JwkStorageWrapper::Stronghold(stronghold_storage), &key_id)
            .await
            .unwrap();

        assert_eq!(
            document.id().to_string(),
            "did:key:z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6"
        );

        assert_eq!(
            document.verification_method().first().unwrap().id().to_string(),
            "did:key:z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6#z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6"
        );
    }
}
