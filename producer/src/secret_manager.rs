use identity_stronghold::StrongholdStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;
use iota_stronghold::SnapshotPath;
use log::info;
use std::io::{Error, ErrorKind};

/// Generates or loads a Stronghold
#[derive(Clone)]
pub struct SecretManager {
    pub(crate) stronghold_storage: StrongholdStorage,
}

impl SecretManager {
    /// Generates a new Stronghold
    pub fn generate(snapshot_path: String, password: String) -> Result<Self, std::io::Error> {
        if std::path::Path::new(&snapshot_path).try_exists()? == true {
            return Err(Error::new(ErrorKind::Other, "Stronghold already exist"));
        };

        let snapshot_path = SnapshotPath::from_path(snapshot_path);

        info!("Generating new Stronghold at {:?} ...", snapshot_path.as_path());

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from(password))
            .build(snapshot_path.as_path())
            .unwrap();

        // TODO: generate a new key
        // let private_key = SecretKey::generate().unwrap();
        // let public_key = private_key.public_key();

        // let x = jwu::encode_b64(public_key.as_ref());
        // let d = jwu::encode_b64(private_key.to_bytes().as_ref());
        // let mut params = JwkParamsOkp::new();
        // params.x = x;
        // params.d = Some(d);
        // params.crv = EdCurve::Ed25519.name().to_owned();
        // let mut jwk = Jwk::from_params(params);
        // jwk.set_alg(JwsAlgorithm::EdDSA.name());

        // // Insert key into stronghold
        // let key_id = stronghold_storage.insert(jwk).await.unwrap();

        Ok(SecretManager {
            stronghold_storage: StrongholdStorage::new(stronghold_secret_manager),
        })
    }

    /// Loads an existing Stronghold as specified in the environment variables
    pub fn load(snapshot_path: String, password: String) -> Result<Self, std::io::Error> {
        if std::path::Path::new(&snapshot_path).try_exists()? == false {
            return Err(Error::new(ErrorKind::Other, "Stronghold does not exist"));
        };

        let snapshot_path = SnapshotPath::from_path(snapshot_path);

        info!("Loading existing Stronghold from {:?} ...", snapshot_path.as_path());

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from(password))
            .build(snapshot_path.as_path())
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(SecretManager {
            stronghold_storage: StrongholdStorage::new(stronghold_secret_manager),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::test_utils::random_stronghold_path;

    #[tokio::test]
    async fn successfully_loads_an_existing_stronghold() {
        let res = SecretManager::load("tests/res/test.stronghold".to_string(), "secure_password".to_string());
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn fails_to_load_an_existing_stronghold_when_password_is_incorrect() {
        let res = SecretManager::load("tests/res/test.stronghold".to_string(), "wrong_password".to_string());
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fails_to_load_when_stronghold_file_does_not_exist() {
        let res = SecretManager::load("non/existing/stronghold".to_string(), "".to_string());
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fails_to_generate_a_new_stronghold_when_file_already_exists() {
        let res = SecretManager::generate("tests/res/test.stronghold".to_string(), "secure_password".to_string());
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn successfully_generates_a_new_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let res = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            "new_password".to_string(),
        );
        assert!(res.is_ok());
    }
}
