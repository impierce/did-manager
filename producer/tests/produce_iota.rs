use std::error::Error;

use anyhow::Context;
use did_iota::producer::produce::{produce_did_iota, IotaMethod};
use iota_sdk::{
    client::{
        generate_mnemonic, node_api::indexer::query_parameters::QueryParameter,
        secret::stronghold::StrongholdSecretManager, Client, Password,
    },
    types::block::address::Bech32Address,
};
use log::info;
use shared::{
    error::WalletError,
    test_utils::{new_stronghold_storage, random_stronghold_path},
    JwkStorageWrapper,
};
use test_log::test;

#[test(tokio::test)]
pub async fn produce_and_publish_and_destroy_a_new_iota_testnet_did() {
    let (storage, key_id) = new_stronghold_storage().await;

    let result = produce_did_iota(
        JwkStorageWrapper::Stronghold(storage.clone()),
        &key_id,
        IotaMethod::Testnet,
    )
    .await;
    assert!(result.is_err());

    // Extract required amount for storage deposit and funding address from error
    let error = result.unwrap_err();
    let source = error.source().unwrap();
    let wallet_error = source.downcast_ref::<WalletError>().unwrap();
    info!("{}", wallet_error);

    let (required_amount, funding_address) = match wallet_error {
        WalletError::InsufficientFunds {
            required_amount,
            funding_address,
        } => (required_amount, funding_address),
        _ => panic!("Unexpected error: {:?}", wallet_error),
    };

    let api_endpoint: &str = "https://api.testnet.shimmer.network";
    let faucet_endpoint: &str = "https://faucet.testnet.shimmer.network/api/enqueue";

    // TODO: request faucet, wait a few seconds
    let client: Client = Client::builder()
        .with_primary_node(api_endpoint, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    request_faucet_funds(&client, funding_address, faucet_endpoint)
        .await
        .unwrap();

    // Try to produce the DID again
    let result = produce_did_iota(JwkStorageWrapper::Stronghold(storage), &key_id, IotaMethod::Testnet).await;
    let x = result.inspect_err(|e| info!("{}", e)).unwrap();
    // assert!(result.is_ok());
}

/// Helper functions

/// Requests funds from the faucet for the given `address`.
async fn request_faucet_funds(client: &Client, address: &Bech32Address, faucet_endpoint: &str) -> anyhow::Result<()> {
    iota_sdk::client::request_funds_from_faucet(faucet_endpoint, &address).await?;

    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let balance = get_address_balance(client, &address)
                .await
                .context("failed to get address balance")?;
            if balance > 0 {
                info!("Funds received.");
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("maximum timeout exceeded")??;

    Ok(())
}

/// Returns the balance of the given Bech32-encoded `address`.
async fn get_address_balance(client: &Client, address: &Bech32Address) -> anyhow::Result<u64> {
    let output_ids = client
        .basic_output_ids(vec![
            QueryParameter::Address(address.to_owned()),
            QueryParameter::HasExpiration(false),
            QueryParameter::HasTimelock(false),
            QueryParameter::HasStorageDepositReturn(false),
        ])
        .await?;

    let outputs = client.get_outputs(&output_ids).await?;

    let mut total_amount = 0;
    for output_response in outputs {
        total_amount += output_response.output().amount();
    }

    Ok(total_amount)
}
