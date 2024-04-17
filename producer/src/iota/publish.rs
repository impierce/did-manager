use consumer::resolver::Resolver;
use identity_iota::core::ToJson;
use identity_iota::did::DID;
use identity_iota::document::CoreDocument;
use identity_iota::iota::{IotaClientExt, IotaDID, IotaDocument, IotaIdentityClientExt};
use iota_sdk::client::api::GetAddressesOptions;
use iota_sdk::client::{
    node_api::indexer::query_parameters::QueryParameter, secret::SecretManager as ExternSecretManager, Client,
};
use iota_sdk::types::block::address::Bech32Address;
use iota_sdk::types::block::output::{AliasId, MinimumStorageDepositBasicOutput};
use log::{debug, info, warn};
use token_wallet::get_address_balance;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

/// Publishes a given `IotaDocument` to the Tangle network.
/// It resolves the DID first to check if it's already published.
pub async fn publish_iota_document(
    document: IotaDocument,
    governor_address: Bech32Address,
    secret_manager: &ExternSecretManager,
) -> anyhow::Result<CoreDocument> {
    let client = match document.id().network_str() {
        "rms" => Client::builder().with_primary_node(TESTNET_URL, None)?.finish().await?,
        "smr" => Client::builder().with_primary_node(SHIMMER_URL, None)?.finish().await?,
        "iota" => Client::builder().with_primary_node(MAINNET_URL, None)?.finish().await?,
        _ => anyhow::bail!("Unsupported network"),
    };

    // Query the network for the given Governor address
    let alias_output_ids = client
        .alias_output_ids(vec![QueryParameter::Governor(governor_address)])
        .await?
        .items;
    debug!("Output IDs: {:?}", alias_output_ids);

    let document = match alias_output_ids.len() {
        0 => {
            info!("No AliasOutput found for the given Governor address.");

            // Check available funds for storage deposit
            let balance = get_address_balance(&governor_address).await?;

            // calculate_storage_deposit(&client).await?;
            // TODO: temporary hardcoded: check if balance is enough for storage deposit
            if balance < 89300 {
                let funding_address = secret_manager
                    .generate_ed25519_addresses(
                        GetAddressesOptions::default()
                            .with_range(0..1)
                            .with_bech32_hrp(client.get_bech32_hrp().await?),
                    )
                    .await
                    .unwrap()
                    .first()
                    .unwrap()
                    .to_owned();
                anyhow::bail!(
                    "Insufficient balance for storage deposit: {}. Please send some funds to `{}`",
                    balance,
                    funding_address
                );
            }

            // Create new Alias
            let alias_output = client
                .new_did_output(governor_address.into_inner(), document.clone(), None)
                .await?;

            info!(
                "Publishing new AliasOutput to the Tangle (network: `{}`) ...",
                client.network_name().await?
            );

            // TODO: check for balance?
            // After successful publish, return left over funds

            // TODO: handle different types of errors:
            // - no funding at all: "publish failed: no input with matching ed25519 address provided"
            // - too little funding: "publish failed: insufficient amount: found 42601, required 89300"
            let document: IotaDocument = client.publish_did_output(secret_manager, alias_output).await?;

            info!("Successfully published AliasOutput.");
            document.core_document().to_owned()
        }
        1 => {
            info!("Found one AliasOutput for the given State Controller address.");
            // Convert first OutputId to AliasId
            // TODO: How to handle multiple OutputIds?
            let alias_id: AliasId = alias_output_ids.first().unwrap().into();
            // info!("Alias ID: {:?}", alias_id);

            // Convert to DID
            let iota_did = IotaDID::from_alias_id(&alias_id.to_string(), &client.network_name().await?);
            info!("DID: `{}`", iota_did.as_str());

            // Resolve what's already published
            debug!("Creating new resolver ...");
            let resolver = Resolver::new().await;

            debug!("Resolving document ...");
            // let published_address = "did:iota:rms:0x4a55dd9720372deb80bebd2e87e9a1e7273a178ba76b14eefa5b072f4f3c1c5f";
            let resolved_document = resolver
                .resolve(iota_did.as_str())
                .await
                .expect("TODO: handle resolver error");
            info!("Successfully resolved document!");

            // TODO: Hardening (does this check have to be implemented in the first version?)
            // TODO: compare that the given document and the resolved document are the same (except for the id?)
            // TODO: - use .resolve_method()?
            info!("Given document: {}", document.core_document().to_json_pretty()?);
            info!("Resolved document: {}", resolved_document.to_json_pretty()?);
            resolved_document
        }
        _ => {
            warn!("Found multiple AliasOutputs for the given State Controller address.");
            // TODO: hardening: iterate all AliasOutputs, resolve the DID and compare the verificationMethod with the given document
            unimplemented!("TODO: handle multiple AliasOutputs")
        }
    };

    Ok(document)
}

/// TODO: calculate storage deposit for alias output
async fn calculate_storage_deposit(client: &Client) -> anyhow::Result<u64> {
    let rent_structure = client.get_rent_structure().await?;
    let token_supply = client.get_token_supply().await?;

    let storage_deposit_amount = MinimumStorageDepositBasicOutput::new(rent_structure, token_supply)
        .with_storage_deposit_return()?
        .with_expiration()?
        .finish()?;

    info!("Storage deposit amount: {:?}", storage_deposit_amount);
    Ok(storage_deposit_amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{did_document::DidMethod, SecretManager};

    use identity_iota::iota::NetworkName;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn successfully_publishes_a_did_document() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();

        let core_document = SecretManager::produce_document(&secret_manager, DidMethod::IotaTestnet)
            .await
            .unwrap();

        let iota_document = IotaDocument::new(&NetworkName::try_from("rms").unwrap());
        let governor_address =
            Bech32Address::try_from_str("rms1qzs0e5qrmljhmgcas9z3xs0v9ejjvfpcwhztfjcdq5slmfr48amwk7vl0xr").unwrap();

        publish_iota_document(
            iota_document,
            governor_address,
            secret_manager.stronghold_storage.as_secret_manager(),
        )
        .await
        .unwrap();
    }
}
