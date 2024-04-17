use identity_iota::iota::{Error, IotaClientExt, IotaDID, IotaIdentityClientExt};
use iota_sdk::{
    client::{secret::SecretManager as ExternSecretManager, Client},
    types::block::address::Address,
};

/// Destroying an IOTA document involves returning the storage deposit to the original funding address.
pub async fn destroy_iota_document(
    did: IotaDID,
    return_address: Address,
    secret_manager: ExternSecretManager,
) -> anyhow::Result<()> {
    let client: Client = Client::builder()
        .with_primary_node("https://api.testnet.shimmer.network", None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    client.delete_did_output(&secret_manager, return_address, &did).await?;

    let error: Error = client.resolve_did(&did).await.unwrap_err();

    assert!(matches!(
        error,
        identity_iota::iota::Error::DIDResolutionError(iota_sdk::client::Error::Node(
            iota_sdk::client::node_api::error::Error::NotFound(..)
        ))
    ));

    // let document: IotaDocument = client.resolve_did(&did).await?;

    // Check if the DID is already deactivated.
    // let deactivated: IotaDocument = client.resolve_did(&did).await?;
    // println!("Deactivated DID document: {deactivated:#}");
    // assert_eq!(deactivated.metadata.deactivated, None);

    // Deactivate the DID by publishing an empty document.
    // This process can be reversed since the Alias Output is not destroyed.
    // Deactivation may only be performed by the state controller of the Alias Output.
    // let deactivated_output: AliasOutput = client.deactivate_did_output(&did).await?;

    // let _ = client.publish_did_output(&secret_manager, deactivated_output).await?;

    // let deactivated: IotaDocument = client.resolve_did(&did).await?;
    // println!("Deactivated DID document: {deactivated:#}");
    // assert_eq!(deactivated.metadata.deactivated, Some(true));

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    use iota_sdk::client::{secret::stronghold::StrongholdSecretManager, Password};
    use test_log::test;

    #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn destroy_did_iota_testnet() {
        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";
        let secret_manager: ExternSecretManager = ExternSecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        destroy_iota_document(
            IotaDID::from_str("did:iota:rms:0x4a55dd9720372deb80bebd2e87e9a1e7273a178ba76b14eefa5b072f4f3c1c5f")
                .unwrap(),
            Address::try_from_bech32("rms1qrdgpq8a4xjetgf79gnx7g5n0rfeykm30rek9fpjef6dnx3md929ksv04a0").unwrap(),
            secret_manager,
        )
        .await
        .unwrap();
    }
}
