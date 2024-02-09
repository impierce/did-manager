use identity_iota::{
    core::{FromJson, ToJson},
    credential::Jws,
    did::{CoreDID, DID},
    document::{self, CoreDocument},
    storage::{JwkDocumentExt, JwkStorage, KeyIdStorage, KeyType, Storage},
    verification::{
        jwk::{Jwk, JwkParamsOkp},
        jws::JwsAlgorithm,
        MethodScope,
    },
};
use iota_sdk::utils::serde;
use ssi_dids::{DIDMethod, Source};

pub async fn produce_did_from_key<K, I>(
    storage: Storage<K, I>,
    password: &str,
    key_id: &str,
) -> std::result::Result<CoreDocument, std::io::Error>
where
    K: JwkStorage,
    I: KeyIdStorage,
{
    println!(
        "Producing DID for key_id=[{:?}] from storage=[{:?}] ...",
        key_id, "TODO_get_name"
    );

    // TODO: read public key of JWK from storage
    // ...

    // TODO (remove): this simulates we got the public key from the storage
    let mut jwk = Jwk::from_params(
        JwkParamsOkp::from_json(
            r#"{
                "crv": "Ed25519",
                "x": "uhxVazAiEvAsPkVzfe3xeTpmNFBP4rEw5DBHu3lvYCg"
            }"#,
        )
        .unwrap(),
    );
    jwk.set_alg(JwsAlgorithm::EdDSA.name());
    println!("JWK: {}", jwk.to_public().to_json().unwrap());

    // Create did:key from JWK
    let did_str = did_method_key::DIDKey
        .generate(&Source::Key(&serde_json::from_str(&jwk.to_json().unwrap()).unwrap()))
        .unwrap();

    // println!("DID: {}", did_str);

    let controller = CoreDID::parse(&did_str).unwrap();

    let mut document = CoreDocument::builder(Default::default())
        .id(controller.clone())
        .build()
        .unwrap();

    // println!("{}", document.to_json_pretty().unwrap());

    // Insert new verification method
    document
        .generate_method(
            &storage,
            KeyType::from_static_str("Ed25519"),
            JwsAlgorithm::EdDSA,
            Some(controller.method_id()),
            MethodScope::VerificationMethod,
        )
        .await
        .unwrap();

    println!("DID Document: {}", document.to_json_pretty().unwrap());
    Ok(document)
}

#[cfg(test)]
pub mod tests {
    use crypto::signatures::ed25519::SecretKey;
    use identity_iota::core::{FromJson, ToJson};
    use identity_iota::storage::{JwkMemStore, KeyIdMemstore};
    use identity_iota::verification::jwk::{EdCurve, Jwk, JwkParamsOkp};
    use identity_iota::verification::jws::JwsAlgorithm;
    use identity_iota::verification::jwu;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use rand::distributions::DistString;

    use super::*;

    #[tokio::test]
    async fn test_mem_storage() {
        type MemStorage = Storage<JwkMemStore, KeyIdMemstore>;
        let storage: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
        let document = produce_did_from_key(storage, "foo", "bar").await.unwrap();

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
        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();
        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

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

        // TODO: temporarily overwrite with known static values
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
        let key_id = stronghold_storage.insert(jwk).await.unwrap();

        let storage = Storage::new(stronghold_storage.clone(), stronghold_storage);
        println!("====== Done");

        let document = produce_did_from_key(storage, "secure_password", key_id.as_str())
            .await
            .unwrap();

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
