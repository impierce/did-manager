pub mod error;
pub mod test_utils;

use identity_stronghold::StrongholdStorage;
// use iota_sdk::client::secret::stronghold::StrongholdSecretManager;

/// TODO: Change name to `SecretManagerWrapper`?
pub enum JwkStorageWrapper {
    Stronghold(StrongholdStorage),
    PKCS11,
}
