pub mod error;
pub mod test_utils;

use identity_stronghold::StrongholdStorage;
use identity_stronghold_ext::StrongholdExtStorage;

pub enum JwkStorageWrapper {
    Stronghold(StrongholdStorage),
    StrongholdExt(StrongholdExtStorage),
    PKCS11,
}
