use identity_storage::{KeyStorageError, KeyStorageErrorKind, KeyStorageResult};
use iota_sdk::client::secret::SecretManager;
use iota_stronghold::{Client, ClientError, Stronghold};
use tokio::sync::MutexGuard;

// static IDENTITY_VAULT_PATH: &str = "iota_identity_vault";
pub(crate) static IDENTITY_CLIENT_PATH: &[u8] = b"iota_identity_client";

pub fn get_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
    let client = stronghold.get_client(IDENTITY_CLIENT_PATH);
    match client {
        Ok(client) => Ok(client),
        Err(ClientError::ClientDataNotPresent) => load_or_create_client(stronghold),
        Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
    }
}

fn load_or_create_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
    match stronghold.load_client(IDENTITY_CLIENT_PATH) {
        Ok(client) => Ok(client),
        Err(ClientError::ClientDataNotPresent) => stronghold
            .create_client(IDENTITY_CLIENT_PATH)
            .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
        Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
    }
}

pub async fn persist_changes(
    secret_manager: &SecretManager,
    stronghold: MutexGuard<'_, Stronghold>,
) -> KeyStorageResult<()> {
    stronghold.write_client(IDENTITY_CLIENT_PATH).map_err(|err| {
        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("stronghold write client error")
            .with_source(err)
    })?;
    // Must be dropped since `write_stronghold_snapshot` needs to acquire the stronghold lock.
    drop(stronghold);

    match secret_manager {
        iota_sdk::client::secret::SecretManager::Stronghold(stronghold_manager) => {
            stronghold_manager
                .write_stronghold_snapshot(None)
                .await
                .map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message("writing to stronghold snapshot failed")
                        .with_source(err)
                })?;
        }
        _ => {
            return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                .with_custom_message("secret manager is not of type stronghold"))
        }
    };
    Ok(())
}
