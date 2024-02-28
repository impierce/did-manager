use common::JwkStorageWrapper;
use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument, storage::KeyId};
use ssi_dids::{DIDMethod, Source};
use std::io::{Error, ErrorKind};

pub async fn produce_did_web(storage: JwkStorageWrapper, key_id: &KeyId) -> std::result::Result<CoreDocument, Error> {
    // let exists = storage.key_storage().exists(key_id).await.unwrap();

    // if !exists {
    //     return Err(Error::other(format!("Key with id=[{}] does not exist", key_id)));
    // }

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage.get_public_key(key_id).await.unwrap(),
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.to_json_value().unwrap()).unwrap();

    println!(
        "Producing DID for key_id=[{:?}] from storage=[{:?}] ...",
        key_id.as_str(),
        "TODO_get_name"
    );

    let did_str = did_web_extern::DIDWeb.generate(&Source::Key(&jwk));
    println!("DIDWeb.generate(): {:?}", did_str);

    if let Some(did_str) = did_web_extern::DIDWeb.generate(&Source::Key(&jwk)) {
        println!("DID: {:?}", did_str);

        let controller = CoreDID::parse(did_str).unwrap();

        let document = CoreDocument::builder(Default::default())
            .id(controller)
            .build()
            .unwrap();

        return Ok(document);
    };

    return Err(Error::new(ErrorKind::Other, "Done without result"));
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::test_utils::{get_test_jwk, random_stronghold_path};
    use identity_iota::core::ToJson;
    use identity_iota::storage::JwkStorage;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Issue: https://github.com/iotaledger/identity.rs/issues/1299
    #[tokio::test]
    async fn produces_did_web() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        println!("====== Preparing Stronghold");

        // Create stronghold
        let stronghold = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();

        let stronghold_storage = StrongholdStorage::new(stronghold);

        // Generate key
        let jwk = get_test_jwk();
        // println!("JWK: {}", jwk.params().to_json().unwrap());
        // Insert into stronghold
        let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();
        println!("====== Done");

        let document = produce_did_web(JwkStorageWrapper::Stronghold(stronghold_storage), &key_id)
            .await
            .unwrap();

        // Start mock server and assert
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document.to_json().unwrap()))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server.address().port());
        // let document = resolve_did(&did).await.unwrap();

        // assert_eq!(document.id().as_str(), did);
    }
}
