use identity_iota::{
    core::ToJson,
    document::CoreDocument,
    iota::{IotaDID, IotaDocument, NetworkName},
    storage::KeyId,
    verification::{MethodScope, VerificationMethod},
};
use iota_sdk::{
    client::{api::GetAddressesOptions, constants::SHIMMER_TESTNET_BECH32_HRP},
    types::block::address::Bech32Address,
};
use log::info;
use shared::JwkStorageWrapper;
use std::io::Error;

use crate::iota::publish::publish_iota_document;

pub enum IotaMethod {
    Testnet,
    Shimmer,
    Mainnet,
}

/// Note: Producing a DID document on an IOTA network involves publishing it to the network.
pub async fn produce_did_iota(
    storage: JwkStorageWrapper,
    key_id: &KeyId,
    iota_method: IotaMethod,
) -> std::result::Result<CoreDocument, Error> {
    // TODO: check if key exists for given key_id?

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(ref stronghold_storage) => {
            stronghold_storage.get_public_key(key_id).await.unwrap()
        }
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    let network = match iota_method {
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

    let mut iota_document = IotaDocument::new(&network);

    // Placeholder until document is published to network
    let controller = IotaDID::placeholder(&network);

    let verification_method =
        VerificationMethod::new_from_jwk(controller, public_key_jwk.clone(), Some("key-0")).unwrap();

    iota_document
        .insert_method(verification_method, MethodScope::VerificationMethod)
        .ok();

    let governor = create_new_governor_and_state_controller(&storage).await;

    let published_document = publish_iota_document(iota_document, governor).await.unwrap();

    info!("DID Document: {}", published_document.to_json_pretty().unwrap());

    Ok(published_document)
}

/// First address: funding address, second address: governor address
async fn create_new_governor_and_state_controller(storage: &JwkStorageWrapper) -> Bech32Address {
    info!("Creating new Governor and State Controller ...");
    let stronghold_storage = match storage {
        JwkStorageWrapper::Stronghold(s) => s,
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    let addresses = stronghold_storage
        .as_secret_manager()
        .generate_ed25519_addresses(
            GetAddressesOptions::default()
                .with_range(0..2)
                .with_bech32_hrp(SHIMMER_TESTNET_BECH32_HRP),
        )
        .await
        .unwrap();

    // info!("Addresses: {:#?}", addresses);
    // TODO: funding address == governor address --> should be a different index or even different key
    let governor = addresses[0];
    info!("Governor address: {}", governor);
    governor
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::SecretManager;

    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    // const KEY_ID: &str = "7GvXZGN3YoDmZRLXLJDVNFR6yJzB8nKz";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    // const SNAPSHOT_PATH: &str = "tests/res/alice.stronghold"; // Alice
    // const KEY_ID: &str = "HG75tNwdZuIeQZT2a5Syfg1pZhkiv0k2"; // Alice

    #[test(tokio::test)]
    async fn produce_did_iota_testnet() {
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let storage = JwkStorageWrapper::Stronghold(secret_manager.stronghold_storage);

        let document = produce_did_iota(storage, &KeyId::new(KEY_ID), IotaMethod::Testnet)
            .await
            .unwrap();

        assert_eq!(
            document.id(),
            "did:iota:rms:0x4a55dd9720372deb80bebd2e87e9a1e7273a178ba76b14eefa5b072f4f3c1c5f"
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
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let storage = JwkStorageWrapper::Stronghold(secret_manager.stronghold_storage);

        let document = produce_did_iota(storage, &KeyId::new(KEY_ID), IotaMethod::Shimmer)
            .await
            .unwrap();

        assert_eq!(document.id(), "did:iota:smr:0x0000");
    }

    #[ignore]
    #[test(tokio::test)]
    async fn produce_did_iota_mainnet() {
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let storage = JwkStorageWrapper::Stronghold(secret_manager.stronghold_storage);

        let document = produce_did_iota(storage, &KeyId::new(KEY_ID), IotaMethod::Mainnet)
            .await
            .unwrap();

        assert_eq!(document.id(), "did:iota:0x0000");
    }
}
