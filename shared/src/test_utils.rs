use identity_iota::core::ToJson;
use identity_iota::storage::{JwkStorage, KeyId};
use identity_iota::verification::{
    jwk::{EdCurve, Jwk, JwkParamsOkp},
    jws::JwsAlgorithm,
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::{generate_mnemonic, Password};
use log::debug;
use rand::distributions::DistString;

pub fn test_jwk() -> Jwk {
    let mut params = JwkParamsOkp::new();
    params.x = "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88".to_string();
    params.d = Some("iWUyZs5SWPiivpwTcWeG9C_Y5ZzWE3iB_s8STnE07RY".to_string());
    params.crv = EdCurve::Ed25519.name().to_owned();
    let mut jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());

    debug!("JWK: {}", jwk.params().to_json().unwrap());

    jwk
}

pub fn random_stronghold_path() -> std::path::PathBuf {
    let mut file = std::env::temp_dir();
    file.push("test_strongholds");
    file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
    file.set_extension("stronghold");
    debug!("Stronghold path: {:?}", file);
    file.to_owned()
}

/// Creates a new temporary Stronghold and inserts a Mnemonic and a JWK
pub async fn new_stronghold() -> (StrongholdSecretManager, KeyId) {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    let path = random_stronghold_path();

    let stronghold_secret_manager = StrongholdSecretManager::builder()
        .password(Password::from("secure_password".to_owned()))
        .build(path.clone())
        .unwrap();

    stronghold_secret_manager
        .store_mnemonic(generate_mnemonic().unwrap())
        .await
        .ok();

    let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

    let jwk = test_jwk();

    let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();

    // Load the Stronghold again since `StrongholdStroage` doesn't allow releasing the `StrongholdSecretManager`
    let stronghold_secret_manager = StrongholdSecretManager::builder()
        .password(Password::from("secure_password".to_owned()))
        .build(path)
        .unwrap();

    (stronghold_secret_manager, key_id)
}
