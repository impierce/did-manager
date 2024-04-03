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
    use shared::test_utils::{new_stronghold_storage, test_jwk};

    #[tokio::test]
    async fn produces_did_key() {
        let (stronghold_storage, key_id) = new_stronghold_storage().await;

        let expected_did = did_method_key::DIDKey
            .generate(&Source::Key(
                &serde_json::from_str(&test_jwk().to_json().unwrap()).unwrap(),
            ))
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
