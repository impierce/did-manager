use identity_iota::{
    core::ToJson,
    did::{CoreDID, DID},
    document::CoreDocument,
    storage::{JwkDocumentExt, JwkStorage, KeyId, KeyIdStorage, KeyType, Storage},
    verification::{jws::JwsAlgorithm, MethodScope, VerificationMethod},
};
use ssi_dids::{DIDMethod, Source};
use std::io::Error;

pub async fn produce_did_from_key<K, I>(
    storage: Storage<K, I>,
    password: &str,
    key_id: &KeyId,
) -> std::result::Result<CoreDocument, std::io::Error>
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

    // // TODO (remove): this simulates we got the public key from the storage
    // let mut jwk = Jwk::from_params(
    //     JwkParamsOkp::from_json(
    //         r#"{
    //             "crv": "Ed25519",
    //             "x": "uhxVazAiEvAsPkVzfe3xeTpmNFBP4rEw5DBHu3lvYCg"
    //         }"#,
    //     )
    //     .unwrap(),
    // );
    // jwk.set_alg(JwsAlgorithm::EdDSA.name());
    // println!("JWK: {}", jwk.to_public().to_json().unwrap());

    // // Create did:key from JWK
    // let did_str = did_method_key::DIDKey
    //     .generate(&Source::Key(&serde_json::from_str(&jwk.to_json().unwrap()).unwrap()))
    //     .unwrap();

    // Use temporary DID string to satisfy the document builder
    let temp_did_str = "did:foo:bar";

    let temp_controller = CoreDID::parse(&temp_did_str).unwrap();

    let mut temp_document = CoreDocument::builder(Default::default())
        .id(temp_controller.clone())
        .build()
        .unwrap();

    // temp_document.insert_method(method, scope)

    // Insert new verification method
    temp_document
        .generate_method(
            &storage,
            KeyType::from_static_str("Ed25519"),
            JwsAlgorithm::EdDSA,
            Some(temp_controller.method_id()),
            MethodScope::VerificationMethod,
        )
        .await
        .unwrap();

    let temp_verification_method = temp_document.verification_method().first().unwrap().to_owned();
    let public_key_jwk = temp_verification_method.data().public_key_jwk().unwrap();
    println!(
        "(generated) public_key_jwk: {}",
        public_key_jwk.to_json_pretty().unwrap()
    );

    let did_str = did_method_key::DIDKey
        .generate(&Source::Key(
            &serde_json::from_str(&public_key_jwk.to_json().unwrap()).unwrap(),
        ))
        .unwrap();
    let did = CoreDID::parse(&did_str).unwrap();
    println!("DID: {}", did);

    // first_verification_method
    //     .set_id(DIDUrl::parse(format!("{}#{}", did, did.method_id())).unwrap())
    //     .unwrap();

    let verification_method =
        VerificationMethod::new_from_jwk(did.clone(), public_key_jwk.clone(), Some(did.method_id())).unwrap();
    // println!("VerificationMethod: {}", verification_method.to_json_pretty().unwrap());

    let document = CoreDocument::builder(Default::default())
        .id(did)
        .verification_method(verification_method)
        .build()
        .unwrap();
    println!("DID Document: {}", document.to_json_pretty().unwrap());

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto::signatures::ed25519::SecretKey;
    use did_key_extern::{Config, DIDCore};
    use identity_iota::core::{FromJson, ToJson};
    use identity_iota::storage::{JwkMemStore, KeyIdMemstore};
    use identity_iota::verification::jwk::{EdCurve, Jwk, JwkParamsOkp};
    use identity_iota::verification::jws::JwsAlgorithm;
    use identity_iota::verification::jwu;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use rand::distributions::DistString;

    #[tokio::test]
    async fn test_mem_storage() {
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

        assert_eq!(
            document.id().to_string(),
            "did:key:z6MkrykwDxGsAQve3QHsjdYbc9ammYHUDpGZVJAp77n8F8ud"
        );
    }

    #[tokio::test]
    async fn test_stronghold_storage() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        println!("====== Preparing Stronghold");

        // Create stronghold
        let stronghold = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();

        let stronghold_storage = StrongholdStorage::new(stronghold);

        // Generate key
        let private_key = SecretKey::generate().unwrap();
        let public_key = private_key.public_key();

        // Convert to JWK
        let x = jwu::encode_b64(public_key.as_ref());
        let d = jwu::encode_b64(private_key.to_bytes().as_ref());
        let mut params = JwkParamsOkp::new();
        params.x = x;
        params.d = Some(d);
        params.crv = EdCurve::Ed25519.name().to_owned();
        let mut jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::EdDSA.name());

        // TODO: temporarily overwrite with known static values for better assertions
        // since we can pre-calculate the expected did:key
        jwk = Jwk::from_params(
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

        println!("JWK: {}", jwk.params().to_json().unwrap());
        // Insert into stronghold
        let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();

        let storage = Storage::new(stronghold_storage.clone(), stronghold_storage);
        println!("====== Done");

        let expected_did = did_method_key::DIDKey
            .generate(&Source::Key(&serde_json::from_str(&jwk.to_json().unwrap()).unwrap()))
            .unwrap();
        println!("Expected DID: {}", expected_did);

        let document = produce_did_from_key(storage, "secure_password", &key_id).await.unwrap();

        // println!(
        //     "{}",
        //     did_key::resolve(&expected_did)
        //         .unwrap()
        //         .get_did_document(Config::default())
        //         .to_json_pretty()
        //         .unwrap()
        // );

        assert_eq!(
            document.id().to_string(),
            "did:key:z6MkrykwDxGsAQve3QHsjdYbc9ammYHUDpGZVJAp77n8F8ud"
        );

        assert_eq!(
            document.verification_method().first().unwrap().id().to_string(),
            "did:key:z6MkrykwDxGsAQve3QHsjdYbc9ammYHUDpGZVJAp77n8F8ud#z6MkrykwDxGsAQve3QHsjdYbc9ammYHUDpGZVJAp77n8F8ud"
        );
    }

    pub fn random_stronghold_path() -> std::path::PathBuf {
        let mut file = std::env::temp_dir();
        file.push("test_strongholds");
        file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
        file.set_extension("stronghold");
        println!("Stronghold path: {:?}", file);
        file.to_owned()
    }
}
