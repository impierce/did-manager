use std::sync::Arc;
use token_wallet::{iota::IotaWallet, TokenWallet};
use tokio::sync::RwLock;

use identity_iota::{
    core::ToJson,
    document::CoreDocument,
    iota::{IotaDID, IotaDocument, NetworkName},
    storage::KeyId,
    verification::{MethodScope, VerificationMethod},
};
use identity_stronghold::StrongholdStorage;
use iota_sdk::{
    client::{
        api::GetAddressesOptions,
        constants::{SHIMMER_COIN_TYPE, SHIMMER_TESTNET_BECH32_HRP},
        secret::{stronghold::StrongholdSecretManager, SecretManager},
        Password,
    },
    types::block::address::Bech32Address,
    wallet::ClientOptions,
    Wallet,
};
use log::info;
use shared::{error::ProducerError, test_utils::random_stronghold_path, JwkStorageWrapper};

use crate::producer::publish::publish_iota_document;

pub enum IotaMethod {
    Testnet,
    Shimmer,
    Mainnet,
}

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

/// Note: Producing a DID document on an IOTA network involves publishing it to the network.
pub async fn produce_did_iota(
    storage: &JwkStorageWrapper,
    key_id: &KeyId,
    iota_method: IotaMethod,
) -> Result<CoreDocument, ProducerError> {
    // TODO: check if key exists for given key_id?

    let stronghold_storage = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage,
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

    // let secret_manager = SecretManager::Stronghold(stronghold_secret_manager);

    // let stronghold_storage = StrongholdStorage::new(stronghold_secret_manager);

    // Create new Stronghold instance
    // let secret_manager = SecretManager::Stronghold(
    //     StrongholdSecretManager::builder()
    //         .password(Password::from("password"))
    //         .build(random_stronghold_path())?,
    // );

    // let x = secret_manager.clone();

    let wallet = IotaWallet::new().await;

    // let client_options = ClientOptions::new().with_node(TESTNET_URL).unwrap();
    // let coin_type = SHIMMER_COIN_TYPE; // TODO: hardcoded for now
    // let wallet = Wallet::builder()
    //     .with_secret_manager_arc(Some(Arc::new(RwLock::new(secret_manager))))
    //     .with_client_options(client_options)
    //     .with_coin_type(coin_type)
    //     .finish()
    //     .await
    //     .unwrap();

    // let ssm: StrongholdSecretManager = match wallet.get_secret_manager().as_ref() {
    //     SecretManager::Stronghold(ssm) => ssm.clone(),
    //     _ => panic!("Expected StrongholdSecretManager"),
    // };

    let public_key_jwk = stronghold_storage.get_public_key(key_id).await.unwrap();

    let verification_method =
        VerificationMethod::new_from_jwk(controller, public_key_jwk.clone(), Some("key-0")).unwrap();

    iota_document
        .insert_method(verification_method, MethodScope::VerificationMethod)
        .ok();

    let governor_address = wallet.get_governor_address().await;

    let published_document = publish_iota_document(iota_document, governor_address, wallet).await?;

    info!("DID Document: {}", published_document.to_json_pretty().unwrap());

    Ok(published_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn produce_did_iota_testnet() {
        // let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
        //     .await
        //     .unwrap();
        // let storage = JwkStorageWrapper::Stronghold(secret_manager.stronghold_storage);

        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));
        // let storage = JwkStorageWrapper::Stronghold(stronghold_adapter);

        let document = produce_did_iota(&storage, &KeyId::new(KEY_ID), IotaMethod::Testnet)
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

        let document = produce_did_iota(&storage, &KeyId::new(KEY_ID), IotaMethod::Shimmer)
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

        let document = produce_did_iota(&storage, &KeyId::new(KEY_ID), IotaMethod::Mainnet)
            .await
            .unwrap();

        assert_eq!(document.id(), "did:iota:0x0000");
    }
}
