use identity_iota::{
    core::{FromJson, Object, ToJson},
    did::{CoreDID, DID},
    document::CoreDocument,
    storage::KeyId,
    verification::VerificationMethod,
};
use log::info;
use serde_json::json;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;

pub async fn produce_did_key(storage: JwkStorageWrapper, key_id: &KeyId) -> Result<CoreDocument, Error> {
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

    let verification_method = VerificationMethod::from_json_value(json!({
        "id": format!("{}#{}", did, did.method_id()),
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyMultibase": did.method_id()
    }))
    .unwrap();

    let mut properties = Object::new();
    properties.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1" // TODO: make dynamic
        ]),
    );

    let document = CoreDocument::builder(properties)
        .id(did)
        .verification_method(verification_method)
        .build()
        .unwrap();

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::test_utils::new_stronghold_storage;
    use test_log::test;

    #[test(tokio::test)]
    async fn produces_did_key() {
        let (stronghold_storage, key_id) = new_stronghold_storage().await;

        let storage = JwkStorageWrapper::Stronghold(stronghold_storage);
        let document = produce_did_key(storage, &key_id).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
              ],
              "id": "did:key:z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6",
              "verificationMethod": [
                {
                  "id": "did:key:z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6#z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6",
                  "type": "Ed25519VerificationKey2020",
                  "controller": "did:key:z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6",
                  "publicKeyMultibase": "z6Mkv5KkqNHuR6bPVT8fud3m9JaHBSEjEmiLp7HuGAwtbkk6"
                }
              ]
            })
        );
    }
}
