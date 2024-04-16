use crypto::signatures::ed25519::SecretKey;
use identity_iota::{
    core::{FromJson, ToJson},
    storage::JwkStorage,
    verification::{
        jwk::{EdCurve, Jwk, JwkParamsOkp},
        jws::JwsAlgorithm,
        jwu,
    },
};
use identity_stronghold::StrongholdStorage as ExternStrongholdStorage;
use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
use test_log::test;

const SNAPSHOT_PATH: &str = "tests/res/alice.stronghold";
const PASSWORD: &str = "secure_password";

#[ignore = "manual test"]
#[test(tokio::test)]
pub async fn create_new_stronghold() {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    let stronghold = StrongholdSecretManager::builder()
        .password(Password::from(PASSWORD.to_owned()))
        .build(SNAPSHOT_PATH)
        .unwrap();

    let stronghold_storage = ExternStrongholdStorage::new(stronghold);

    let mut jwk: Jwk = Jwk::from_json(
        r#"
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "eeNdk3EwKUyX2oAvZEiVnbveDcWbOLW-Eg34UsQQw5Q",
          "d": "aeFUNdwDjDZPOEgH6JLxSq1Syzcmo4cwZwCQsc9kZ98"
        }
      "#,
    )
    .unwrap();

    jwk.set_alg(JwsAlgorithm::EdDSA.name());

    println!("{}", jwk.to_json_pretty().unwrap());

    let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();

    println!("Key ID: {:?}", key_id);
}

// Create new key and produce JWK
#[ignore = "manual test"]
#[test(tokio::test)]
async fn generate_new_jwk() {
    let secret_key = SecretKey::generate().unwrap();

    let x = jwu::encode_b64(secret_key.public_key().as_ref());
    let d = jwu::encode_b64(secret_key.to_bytes().as_ref());
    let mut params = JwkParamsOkp::new();
    params.x = x;
    params.d = Some(d);
    params.crv = EdCurve::Ed25519.name().to_owned();
    let jwk = Jwk::from_params(params);

    println!("{}", jwk.to_json_pretty().unwrap());
}
