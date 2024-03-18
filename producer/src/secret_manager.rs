use identity_iota::{
    storage::{JwkStorage, KeyId, KeyType},
    verification::jws::JwsAlgorithm,
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::Password;
use iota_stronghold::SnapshotPath;
use log::info;
use std::io::{Error, ErrorKind};

/// Generates or loads a Stronghold and uses the specified `KeyId` for all cryptographic operations
#[derive(Clone)]
pub struct SecretManager {
    pub(crate) stronghold_storage: StrongholdStorage,
    pub(crate) key_id: KeyId,
}

impl SecretManager {
    /// Generates a new Stronghold and a new Ed25519 key (only if not exists)
    pub async fn generate(snapshot_path: String, password: String) -> Result<Self, std::io::Error> {
        if std::path::Path::new(&snapshot_path).try_exists()? {
            return Err(Error::new(ErrorKind::Other, "Stronghold already exists"));
        };

        let snapshot_path = SnapshotPath::from_path(snapshot_path);

        info!("Generating new Stronghold at {:?} ...", snapshot_path.as_path());

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(Password::from(password))
            .build(snapshot_path.as_path())
            .unwrap();

        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

        // Generate new Ed25519 key
        let jwk_gen_output = stronghold_storage
            .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
            .await
            .unwrap();

        info!("Generated new Ed25519 key with {:?}", &jwk_gen_output.key_id);

        Ok(SecretManager {
            stronghold_storage,
            key_id: jwk_gen_output.key_id,
        })
    }

    /// Loads an existing Stronghold and verifies the specified key exists
    pub async fn load(snapshot_path: String, password: String, key_id: String) -> Result<Self, std::io::Error> {
        if !(std::path::Path::new(&snapshot_path).try_exists()?) {
            return Err(Error::new(ErrorKind::Other, "Stronghold does not exist"));
        };

        let snapshot_path = SnapshotPath::from_path(snapshot_path);
        let password = Password::from(password);
        let key_id = KeyId::new(key_id);

        info!("Loading existing Stronghold from {:?} ...", snapshot_path.as_path());

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(password)
            .build(snapshot_path.as_path())
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

        if stronghold_storage.exists(&key_id).await.unwrap() {
            info!("Successfully verified key exists with {:?}", key_id);
        } else {
            return Err(Error::new(
                ErrorKind::Other,
                "Specified key does not exist in stronghold",
            ));
        }

        Ok(SecretManager {
            stronghold_storage,
            key_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::test_utils::random_stronghold_path;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[tokio::test]
    async fn successfully_loads_an_existing_stronghold() {
        let res = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned()).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn fails_to_load_an_existing_stronghold_when_password_is_incorrect() {
        let res = SecretManager::load(SNAPSHOT_PATH.to_owned(), "wrong_password".to_owned(), KEY_ID.to_owned()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fails_to_load_an_existing_stronghold_when_key_does_not_exist() {
        let res = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            "non_existing_key_id".to_owned(),
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fails_to_load_when_stronghold_file_does_not_exist() {
        let res = SecretManager::load("non/existing/path".to_string(), PASSWORD.to_owned(), KEY_ID.to_owned()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn fails_to_generate_a_new_stronghold_when_file_already_exists() {
        let res = SecretManager::generate(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned()).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn successfully_generates_a_new_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let res = SecretManager::generate(
            random_stronghold_path().to_str().unwrap().to_string(),
            PASSWORD.to_owned(),
        )
        .await;
        assert!(res.is_ok());
    }
}
