use identity_iota::{
    core::ToJson,
    verification::{
        jwk::{EdCurve, Jwk, JwkParamsOkp},
        jws::JwsAlgorithm,
    },
};
use log::info;
use rand::distributions::DistString;

pub fn get_test_jwk() -> Jwk {
    /*
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
    */
    let mut params = JwkParamsOkp::new();
    params.x = "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88".to_string();
    params.d = Some("iWUyZs5SWPiivpwTcWeG9C_Y5ZzWE3iB_s8STnE07RY".to_string());
    params.crv = EdCurve::Ed25519.name().to_owned();
    let mut jwk = Jwk::from_params(params);
    jwk.set_alg(JwsAlgorithm::EdDSA.name());

    info!("JWK: {}", jwk.params().to_json().unwrap());

    jwk
}

pub fn random_stronghold_path() -> std::path::PathBuf {
    let mut file = std::env::temp_dir();
    file.push("test_strongholds");
    file.push(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32));
    file.set_extension("stronghold");
    info!("Stronghold path: {:?}", file);
    file.to_owned()
}
