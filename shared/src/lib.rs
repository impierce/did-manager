pub mod test_utils;

use identity_stronghold::StrongholdStorage;

pub enum JwkStorageWrapper {
    Stronghold(StrongholdStorage),
    PKCS11,
}
