use identity_iota::{
    core::ToJson,
    verification::{
        jwk::{EdCurve, Jwk, JwkParamsOkp},
        jws::JwsAlgorithm,
    },
};
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
