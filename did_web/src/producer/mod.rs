use identity_iota::{
    document::CoreDocument,
    storage::{JwkStorage, KeyId, KeyIdStorage, Storage},
};
use std::io::Error;

pub async fn produce_did_from_key<K, I>(
    storage: Storage<K, I>,
    password: &str,
    key_id: &KeyId,
) -> std::result::Result<CoreDocument, Error>
where
    K: JwkStorage,
    I: KeyIdStorage,
{
    println!(
        "Producing DID for key_id=[{:?}] from storage=[{:?}] ...",
        key_id.as_str(),
        "TODO_get_name"
    );

    let exists = storage.key_storage().exists(key_id).await.unwrap();

    if !exists {
        return Err(Error::other(format!("Key with id=[{}] does not exist", key_id)));
    }

    Ok(todo!())
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::{FromJson, ToJson};
    use identity_iota::storage::{JwkMemStore, KeyIdMemstore};
    use identity_iota::verification::jwk::{Jwk, JwkParamsOkp};
    use identity_iota::verification::jws::JwsAlgorithm;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Issue: https://github.com/iotaledger/identity.rs/issues/1299
    #[tokio::test]
    async fn produces_did_web() {
        type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;
        let storage: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());

        let mut jwk = Jwk::from_params(
            JwkParamsOkp::from_json(
                r#"{
                    "crv": "Ed25519",
                    "x": "uhxVazAiEvAsPkVzfe3xeTpmNFBP4rEw5DBHu3lvYCg",
                    "d":"AGj4AHCRm6ApGng2-9F7HMCtlO19x4DhrAg5_71t2CQ"
                }"#,
            )
            .unwrap(),
        );
        jwk.set_alg(JwsAlgorithm::EdDSA.name());

        let key_id = storage.key_storage().insert(jwk).await.unwrap();

        let document = produce_did_from_key(storage, "foo", &key_id).await.unwrap();

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
