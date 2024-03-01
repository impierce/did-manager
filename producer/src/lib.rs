use identity_iota::{
    document::CoreDocument,
    storage::JwkStorage,
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
use rand::distributions::DistString;
use shared::JwkStorageWrapper;

pub enum Method {
    Jwk,
    Key,
    Web,
}

pub async fn produce(
    method: Method,
    _stronghold_path: Option<String>,
    _password: Option<String>,
) -> std::result::Result<CoreDocument, std::io::Error> {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    // Read provided stronghold
    // TODO

    // random stronghold in temp folder
    let mut file = std::env::temp_dir();
    file.push("test_strongholds");
    file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
    file.set_extension("stronghold");
    println!("Stronghold path: {:?}", file);
    let path_buf = file.to_owned();

    // create stronghold
    let stronghold_secret_manager = StrongholdSecretManager::builder()
        .password(Password::from("secure_password".to_owned()))
        .build(path_buf)
        .unwrap();
    let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

    // Generate key
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

    // Insert into stronghold
    let key_id = stronghold_storage.insert(jwk).await.unwrap();
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
            let core_document = did_web::producer::produce_did_web(
                storage,
                &key_id,
                url::Url::parse("http://localhost").unwrap().host().unwrap().to_owned(),
                Some(1234),
            )
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

    #[tokio::test]
    async fn produce_all() {
        let document = produce(Method::Web, None, None).await;
        assert!(document.is_ok())
    }
}
