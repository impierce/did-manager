use identity_iota::core::ToJson;
use identity_iota::storage::{JwkStorage, KeyId};
use identity_iota::verification::jwk::{EcCurve, JwkOperation, JwkParamsEc, JwkType};
use identity_iota::verification::{
    jwk::{EdCurve, Jwk, JwkParamsOkp},
    jws::JwsAlgorithm,
};
use identity_stronghold::StrongholdStorage;
use identity_stronghold_ext::StrongholdExtStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;
use iota_stronghold::{KeyProvider, SnapshotPath, Stronghold};
use log::debug;
use rand::distributions::DistString;

pub fn test_jwk() -> Jwk {
    let mut params = JwkParamsOkp::new();
    params.x = "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88".to_string();
    params.d = Some("iWUyZs5SWPiivpwTcWeG9C_Y5ZzWE3iB_s8STnE07RY".to_string());
    EdCurve::Ed25519.name().clone_into(&mut params.crv);
    let mut jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());

    debug!("JWK: {}", jwk.params().to_json().unwrap());

    jwk
}

pub fn test_jwk_es256() -> Jwk {
    let mut jwk = Jwk::new(JwkType::Ec);

    let mut params = JwkParamsEc::new();
    params.x = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74".to_string();
    params.y = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI".to_string();
    params.d = Some("0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk".to_string());
    EcCurve::P256.name().clone_into(&mut params.crv);
    jwk.set_alg(JwsAlgorithm::ES256.name());
    jwk.set_key_ops(vec![JwkOperation::Verify]);
    let _ = jwk.set_params(params);

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

pub async fn new_stronghold_storage() -> (StrongholdStorage, KeyId, Option<KeyId>) {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    let stronghold = StrongholdSecretManager::builder()
        .password(Password::from("secure_password".to_owned()))
        .build(random_stronghold_path())
        .unwrap();

    let stronghold_storage = StrongholdStorage::new(stronghold);

    let jwk = test_jwk();

    let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();

    // TODO: Error: { kind: UnsupportedKeyType, source: None, message: Some("Jwk `kty` EC not supported") }
    // let key_id_es256 = stronghold_storage.insert(test_jwk_es256()).await.unwrap();

    (stronghold_storage, key_id.clone(), None)
}

// TODO: can be removed once `new_stronghold_storage()` can insert a given JWK
pub async fn existing_stronghold_storage(path: &str, password: &str) -> StrongholdExtStorage {
    iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

    let stronghold = Stronghold::default();
    stronghold
        .load_snapshot(
            &KeyProvider::with_passphrase_hashed_blake2b(password.as_bytes().to_vec()).unwrap(),
            &SnapshotPath::from_path(path),
        )
        .unwrap();

    StrongholdExtStorage::new(stronghold)
}
