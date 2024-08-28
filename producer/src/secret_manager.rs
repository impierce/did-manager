use identity_iota::{
    core::SingleStructError,
    storage::{JwkStorage, KeyId, KeyType},
    verification::jws::JwsAlgorithm,
};
use identity_storage::KeyStorageErrorKind::KeyNotFound;
use identity_stronghold::StrongholdStorage;
use identity_stronghold_ext::StrongholdExtStorage;
use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
use iota_stronghold::SnapshotPath;
use log::{debug, info, warn};
use shared::error::ProducerError;

use crate::cache::InMemoryCache;

const DEFAULT_KEY_ID_ED25519: &str = "ed25519-0";
const DEFAULT_KEY_ID_ES256: &str = "es256-0";
const DEFAULT_KEY_ID_ES256K: &str = "es256k-0";

/// Generates or loads a Stronghold and uses the specified `KeyId` for all cryptographic operations
#[derive(Debug)]
pub struct SecretManager {
    pub stronghold_storage: StrongholdStorage,
    pub stronghold_ext_storage: StrongholdExtStorage,
    pub ed25519_key_id: Option<KeyId>,
    pub es256_key_id: Option<KeyId>,
    pub es256k_key_id: Option<KeyId>,
    pub did: Option<String>,      // TODO(selv): externally managed DID (see did_iota/README.md)
    pub fragment: Option<String>, // TODO(selv): externally managed fragment (see did_iota/README.md)
    pub cache: Option<InMemoryCache>,
}

/// Currently, there's two implementations of `StrongholdStorage`:
/// - "default": unaltered implementation from `identity.rs`
/// - "extended": custom procedures that allow additional key types (such as `ES256` and `ES256K`)
#[derive(Clone, Debug, Default, PartialEq)]
pub enum StrongholdStorageType {
    Default,
    #[default]
    Extended,
}

#[derive(Default)]
pub struct SecretManagerBuilder {
    snapshot_path: Option<String>,
    password: Option<String>,
    storage_type: StrongholdStorageType,
    ed25519_key_id: Option<KeyId>,
    es256_key_id: Option<KeyId>,
    es256k_key_id: Option<KeyId>,
    did: Option<String>,
    fragment: Option<String>,
    cache: Option<InMemoryCache>,
}

impl SecretManager {
    pub fn builder() -> SecretManagerBuilder {
        SecretManagerBuilder::default()
    }
}

impl SecretManagerBuilder {
    pub fn snapshot_path(mut self, snapshot_path: &str) -> Self {
        self.snapshot_path = Some(snapshot_path.to_owned());
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_owned());
        self
    }

    pub fn with_ed25519_key(mut self, key_id: &str) -> Self {
        self.storage_type = StrongholdStorageType::Default;
        self.ed25519_key_id = Some(KeyId::new(key_id));
        self
    }

    pub fn with_es256_key(mut self, key_id: &str) -> Self {
        self.storage_type = StrongholdStorageType::Extended;
        self.es256_key_id = Some(KeyId::new(key_id));
        self
    }

    pub fn with_did(mut self, did: &str) -> Self {
        self.did = Some(did.to_owned());
        self
    }

    pub fn with_fragment(mut self, fragment: &str) -> Self {
        self.fragment = Some(fragment.to_owned());
        self
    }

    pub fn with_cache(mut self, cache: InMemoryCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub async fn build(mut self) -> Result<SecretManager, ProducerError> {
        let snapshot_path = match self.snapshot_path {
            Some(ref snapshot_path) => snapshot_path,
            None => {
                // Fail if no snapshot path is provided
                return Err(ProducerError::SecretManagerBuilder(
                    "No snapshot path provided".to_string(),
                ));
            }
        };

        // Check if Stronghold snapshot exists at provided path
        let exists = std::path::Path::new(snapshot_path)
            .try_exists()
            .map_err(|e| ProducerError::SecretManagerBuilder(e.to_string()))?;

        match exists {
            true => info!("Loading existing Stronghold from {snapshot_path:?} ..."),
            false => info!("Generating new Stronghold at {snapshot_path:?} ..."),
        }

        let snapshot_path = SnapshotPath::from_path(snapshot_path);

        let password = match self.password {
            Some(password) => Password::from(password),
            None => {
                // Fail if no password is provided
                return Err(ProducerError::SecretManagerBuilder("No password provided".to_string()));
            }
        };

        #[cfg(test)]
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(password.clone())
            .build(snapshot_path.as_path())
            .map_err(|e| ProducerError::SecretManagerBuilder(e.to_string()))?;

        let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

        // We have to do this twice, since `StrongholdAdapter` does not implement the `Copy` trait
        let stronghold_secret_manager = StrongholdSecretManager::builder()
            .password(password)
            .build(snapshot_path.as_path())
            .map_err(|e| ProducerError::SecretManagerBuilder(e.to_string()))?;

        let stronghold_ext_storage = StrongholdExtStorage::new(stronghold_secret_manager);

        // If no key IDs have been provided, use the default ones.
        // This prevents a crash when user just wants a "default" Stronghold and restarts the app without specifying any key IDs.
        if self.ed25519_key_id.is_none() && self.es256_key_id.is_none() && self.es256k_key_id.is_none() {
            self.ed25519_key_id = Some(KeyId::new(DEFAULT_KEY_ID_ED25519));
            self.es256_key_id = Some(KeyId::new(DEFAULT_KEY_ID_ES256));
            self.es256k_key_id = Some(KeyId::new(DEFAULT_KEY_ID_ES256K));
        };

        // If Stronghold doesn't exist yet, generate new keys
        if !exists {
            info!("Generating new keys ...");

            match self.storage_type {
                StrongholdStorageType::Default => {
                    let jwk_gen_output = stronghold_storage
                        .generate(KeyType::new("Ed25519"), JwsAlgorithm::EdDSA)
                        .await?;
                    info!(
                        "Generated new {} key with key ID `{}`",
                        "Ed25519",
                        &jwk_gen_output.key_id.as_str()
                    );
                    warn!(
                        "A new key was generated with id `{}`. It is required for all future operations. Provide it using `with_ed25519_key()`. If you do not intend this behavior, remove the generated Stronghold file and use the default key IDs.",
                        &jwk_gen_output.key_id.as_str()
                    );
                    self.ed25519_key_id = Some(jwk_gen_output.key_id);
                }
                StrongholdStorageType::Extended => {
                    let ed25519_key_id =
                        generate(&stronghold_ext_storage, KeyType::new("Ed25519"), JwsAlgorithm::EdDSA).await?;
                    self.ed25519_key_id = Some(ed25519_key_id);
                    let es256_key_id =
                        generate(&stronghold_ext_storage, KeyType::new("ES256"), JwsAlgorithm::ES256).await?;
                    self.es256_key_id = Some(es256_key_id);
                    let es256k_key_id =
                        generate(&stronghold_ext_storage, KeyType::new("ES256K"), JwsAlgorithm::ES256K).await?;
                    self.es256k_key_id = Some(es256k_key_id);
                }
            }
        }

        // Check if specified keys exists
        match self.storage_type {
            StrongholdStorageType::Default => {
                if self.es256_key_id.is_some() || self.es256k_key_id.is_some() {
                    warn!("Key IDs for ECDSA keys are ignored for Stronghold Storage of type `Default`");
                }
                let ed25519_key_id = self
                    .ed25519_key_id
                    .as_ref()
                    .ok_or(SingleStructError::new(KeyNotFound))?;
                if stronghold_storage
                    .exists(ed25519_key_id)
                    .await
                    .map_err(ProducerError::KeyStorageError)?
                {
                    debug!("Key exists: `{}`", ed25519_key_id);
                } else {
                    return Err(ProducerError::KeyStorageError(SingleStructError::new(KeyNotFound)));
                }
            }
            StrongholdStorageType::Extended => {
                if let Some(ed25519_key_id) = &self.ed25519_key_id {
                    check_key_existence(&stronghold_ext_storage, ed25519_key_id).await?;
                }

                if let Some(es256_key_id) = &self.es256_key_id {
                    check_key_existence(&stronghold_ext_storage, es256_key_id).await?;
                }

                if let Some(es256k_key_id) = &self.es256k_key_id {
                    check_key_existence(&stronghold_ext_storage, es256k_key_id).await?;
                }
            }
        }

        Ok(SecretManager {
            stronghold_storage,
            stronghold_ext_storage,
            ed25519_key_id: self.ed25519_key_id,
            es256_key_id: self.es256_key_id,
            es256k_key_id: self.es256k_key_id,
            did: self.did,
            fragment: self.fragment,
            cache: self.cache,
        })
    }
}

// Helper function
async fn check_key_existence(
    stronghold_ext_storage: &StrongholdExtStorage,
    key_id: &KeyId,
) -> Result<(), ProducerError> {
    if stronghold_ext_storage
        .exists(key_id)
        .await
        .map_err(ProducerError::KeyStorageError)?
    {
        debug!("Key exists: `{}`", key_id);
        Ok(())
    } else {
        warn!("Key does not exist: `{}`", key_id);
        Err(ProducerError::KeyStorageError(SingleStructError::new(KeyNotFound)))
    }
}

async fn generate(
    stronghold_ext_storage: &StrongholdExtStorage,
    key_type: KeyType,
    alg: JwsAlgorithm,
) -> Result<KeyId, ProducerError> {
    let jwk_gen_output = stronghold_ext_storage
        .generate(key_type.clone(), alg)
        .await
        .map_err(ProducerError::KeyStorageError)?;
    info!(
        "Generated new {:?} key with key ID {:?}",
        &key_type.as_str(),
        &jwk_gen_output.key_id.as_str()
    );
    Ok(jwk_gen_output.key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::test_utils::random_stronghold_path;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const ED25519_KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn successfully_loads_an_existing_stronghold() {
        assert!(SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password(PASSWORD)
            .with_ed25519_key(ED25519_KEY_ID)
            .build()
            .await
            .is_ok());
    }

    #[test(tokio::test)]
    async fn successfully_loads_an_existing_stronghold_with_es256_key() {
        assert!(SecretManager::builder()
            .snapshot_path("../shared/tests/res/all_slots.stronghold")
            .password("sup3rSecr3t")
            .with_es256_key("es256-0")
            .build()
            .await
            .is_ok());
    }

    #[test(tokio::test)]
    async fn fails_to_load_an_existing_stronghold_when_password_is_incorrect() {
        assert!(SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password("wrong_password")
            .with_ed25519_key(ED25519_KEY_ID)
            .build()
            .await
            .is_err());
    }

    #[test(tokio::test)]
    async fn fails_to_load_an_existing_stronghold_when_key_does_not_exist() {
        assert!(SecretManager::builder()
            .snapshot_path(SNAPSHOT_PATH)
            .password(PASSWORD)
            .with_ed25519_key("non_existing_key_id")
            .build()
            .await
            .is_err());
    }

    #[test(tokio::test)]
    async fn loads_an_existing_stronghold_ext() {
        let path = random_stronghold_path().to_str().unwrap().to_string();

        // Create a new stronghold file
        assert!(SecretManager::builder()
            .snapshot_path(&path)
            .password(PASSWORD)
            .build()
            .await
            .is_ok());

        // Make the same call again
        assert!(SecretManager::builder()
            .snapshot_path(&path)
            .password(PASSWORD)
            .build()
            .await
            .is_ok());

        // Make the same call again, but with a manually specifying the correct key ID
        assert!(SecretManager::builder()
            .snapshot_path(&path)
            .password(PASSWORD)
            .with_ed25519_key("ed25519-0")
            .build()
            .await
            .is_ok());
    }

    #[test(tokio::test)]
    async fn providing_an_existing_key_id_fails_on_second_run() {
        let path = random_stronghold_path().to_str().unwrap().to_string();

        // Successfully creates the Stronghold, but with a generated key ID (not the passed one)
        assert!(SecretManager::builder()
            .snapshot_path(&path)
            .password(PASSWORD)
            .with_ed25519_key("my-key-id")
            .build()
            .await
            .is_ok());

        // When the same key ID is provided (for example on reboot), it should fail
        assert!(SecretManager::builder()
            .snapshot_path(&path)
            .password(PASSWORD)
            .with_ed25519_key("my-key-id")
            .build()
            .await
            .is_err());
    }

    #[ignore = "run manually to generate persisted stronghold"]
    #[test(tokio::test)]
    async fn successfully_generates_a_new_ext_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        SecretManager::builder()
            .snapshot_path("tests/res/all_slots.stronghold")
            .password("sup3rSecr3t")
            .build()
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn builder_requires_snapshot_path_and_password() {
        assert_eq!(
            SecretManager::builder().build().await.unwrap_err().to_string(),
            "Could not create `SecretManager`: `No snapshot path provided`".to_string()
        );

        assert_eq!(
            SecretManager::builder()
                .snapshot_path(random_stronghold_path().to_str().unwrap())
                .build()
                .await
                .unwrap_err()
                .to_string(),
            "Could not create `SecretManager`: `No password provided`".to_string()
        );
    }
}
