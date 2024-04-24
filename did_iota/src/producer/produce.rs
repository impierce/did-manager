use identity_iota::{
    core::ToJson,
    document::CoreDocument,
    iota::{IotaDID, NetworkName},
    storage::KeyId,
};
use log::info;
use shared::{error::ProducerError, JwkStorageWrapper};

use crate::producer::resolve::resolve;

pub enum IotaMethod {
    Testnet,
    Shimmer,
    Mainnet,
}

/// Note: Producing a DID document on an IOTA network involves publishing it to the network.
pub async fn produce_did_iota(
    storage: &JwkStorageWrapper,
    key_id: &KeyId,
    iota_method: IotaMethod,
    managed_did: IotaDID,     // TODO(selv): see README.md
    managed_fragment: String, // TODO(selv): see README.md
) -> Result<CoreDocument, ProducerError> {
    let stronghold_storage = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage,
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    // Sanity check: Does the key exist in storage?
    let public_key_jwk = stronghold_storage.get_public_key(key_id).await.unwrap();

    let _ = match iota_method {
        IotaMethod::Testnet => {
            info!(
                "Producing did:iota:rms (Testnet) for key_id=[{:?}] ...",
                key_id.as_str()
            );
            NetworkName::try_from("rms").unwrap()
        }
        IotaMethod::Shimmer => {
            info!(
                "Producing did:iota:smr (Shimmer) for key_id=[{:?}] ...",
                key_id.as_str()
            );
            NetworkName::try_from("smr").unwrap()
        }
        IotaMethod::Mainnet => {
            info!("Producing did:iota (Mainnet) for key_id=[{:?}] ...", key_id.as_str());
            NetworkName::try_from("iota").unwrap()
        }
    };

    // Sanity check: Can the document be resolved from the ledger?
    let published_document = resolve(managed_did).await.unwrap();

    // Sanity check: Is the method in the document?
    let verification_method = published_document.resolve_method(&managed_fragment, None).unwrap();

    // Sanity check: Do the public keys match?
    assert_eq!(
        public_key_jwk,
        verification_method.data().public_key_jwk().unwrap().clone()
    );

    info!("DID Document: {}", published_document.to_json_pretty().unwrap());

    Ok(published_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";
    const IOTA_DID: &str = "";
    const FRAGMENT: &str = "";

    #[test(tokio::test)]
    async fn produce_did_iota_testnet() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        let document = produce_did_iota(
            &storage,
            &KeyId::new(KEY_ID),
            IotaMethod::Testnet,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(
            document.id(),
            "did:iota:rms:0x29418b0a0120d10e20d0dacc78896c200ecd1cc1e3b153be482f150859a96739"
        );

        // Expect public key of first verification method
        assert_eq!(
            document
                .verification_method()
                .first()
                .unwrap()
                .data()
                .public_key_jwk()
                .unwrap()
                .try_okp_params()
                .unwrap()
                .x,
            "P2BkYS6z4UHmsxn6FX1oHsyx7eiUSFEMJ1D_RC8M0-w".to_string()
        );
    }

    #[ignore]
    #[test(tokio::test)]
    async fn produce_did_iota_shimmer() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        let document = produce_did_iota(
            &storage,
            &KeyId::new(KEY_ID),
            IotaMethod::Shimmer,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(document.id(), "did:iota:smr:0x0000");
    }

    #[ignore]
    #[test(tokio::test)]
    async fn produce_did_iota_mainnet() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        let document = produce_did_iota(
            &storage,
            &KeyId::new(KEY_ID),
            IotaMethod::Mainnet,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(document.id(), "did:iota:0x0000");
    }
}
