use identity_iota::{
    document::CoreDocument,
    storage::{JwkStorage, KeyId},
    verification::{
        jwk::{EdCurve, Jwk, JwkParamsOkp},
        jws::JwsAlgorithm,
        jwu,
    },
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::{
    client::{secret::stronghold::StrongholdSecretManager, Password},
    crypto::signatures::ed25519::SecretKey,
};
use iota_stronghold::SnapshotPath;
use rand::distributions::DistString;
use shared::JwkStorageWrapper;

pub enum Method {
    Jwk,
    Key,
    Web,
}

pub async fn produce(
    method: Method,
    stronghold_path: Option<String>,
    password: Option<String>,
    host: Option<url::Host>,
    port: Option<u16>,
) -> std::result::Result<CoreDocument, std::io::Error> {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    let (stronghold_storage, key_id) = if let Some(stronghold) = stronghold_path {
        // Read from existing stronghold
        let snapshot_path = SnapshotPath::from_path(stronghold);

        println!("Stronghold path: {:?}", snapshot_path.as_path());

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from(
                password.expect("stronghold password not provided").to_owned(),
            ))
            .build(snapshot_path.as_path())
            .unwrap();

        let key_id = KeyId::new("9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS");
        (StrongholdStorage::new(stronghold_secret_manager), key_id)
    } else {
        // Create random stronghold in temp folder
        let mut file = std::env::temp_dir();
        file.push("test_strongholds");
        file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
        file.set_extension("stronghold");
        println!("Stronghold path: {:?}", file);
        let path_buf = file.to_owned();

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(path_buf)
            .unwrap();
        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

        // Generate new key
        let private_key = SecretKey::generate().unwrap();
        let public_key = private_key.public_key();

        let x = jwu::encode_b64(public_key.as_ref());
        let d = jwu::encode_b64(private_key.to_bytes().as_ref());
        let mut params = JwkParamsOkp::new();
        params.x = x;
        params.d = Some(d);
        params.crv = EdCurve::Ed25519.name().to_owned();
        let mut jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::EdDSA.name());

        // Insert key into stronghold
        let key_id = stronghold_storage.insert(jwk).await.unwrap();
        (stronghold_storage, key_id)
    };

    let storage = JwkStorageWrapper::Stronghold(stronghold_storage);

    let core_document: Option<CoreDocument> = match method {
        Method::Jwk => {
            let core_document = did_jwk::producer::produce_did_jwk(storage, key_id.as_str())
                .await
                .unwrap();
            Some(core_document)
        }
        Method::Key => {
            let core_document = did_key::producer::produce_did_from_key(storage, &key_id).await.unwrap();
            Some(core_document)
        }
        Method::Web => {
            let core_document =
                did_web::producer::produce_did_web(storage, &key_id, host.expect("host not specified"), port)
                    .await
                    .unwrap();
            Some(core_document)
        }
    };

    match core_document {
        Some(core_document) => Ok(core_document),
        None => Err(std::io::Error::other("No core_document produced")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::core::{json, ToJson};

    #[tokio::test]
    async fn produce_with_generated_stronghold() {
        let document = produce(
            Method::Web,
            None,
            None,
            Some(url::Host::parse("localhost").unwrap()),
            Some(8080),
        )
        .await;

        println!("document: {}", document.as_ref().unwrap().to_json_pretty().unwrap());
        assert!(document.is_ok())
    }

    #[tokio::test]
    async fn produce_from_existing_stronghold() {
        let document = produce(
            Method::Web,
            Some("tests/res/test.stronghold".to_string()),
            Some("secure_password".to_string()),
            Some(url::Host::parse("localhost").unwrap()),
            Some(8080),
        )
        .await;

        assert_eq!(
            document
                .unwrap()
                .verification_method()
                .first()
                .unwrap()
                .to_json_value()
                .unwrap()
                .get("publicKeyJwk")
                .unwrap(),
            &json!({
                "kty": "OKP",
                "alg": "EdDSA",
                "kid": "aHq-0PIf6_ljLhyx4W86Gviqb-671OAI67E6vXpZc7Q",
                "crv": "Ed25519",
                "x": "P2BkYS6z4UHmsxn6FX1oHsyx7eiUSFEMJ1D_RC8M0-w"
            })
        )
    }
}
