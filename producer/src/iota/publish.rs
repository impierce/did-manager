use consumer::resolver::Resolver;
use identity_iota::did::DID;
use identity_iota::document::CoreDocument;
use identity_iota::iota::{IotaDID, IotaDocument, IotaIdentityClientExt, NetworkName};
use iota_sdk::client::node_api::indexer::query_parameters::QueryParameter;
use iota_sdk::client::Client;
use iota_sdk::client::{
    secret::{stronghold::StrongholdSecretManager, SecretManager as ExternSecretManager},
    Password,
};
use iota_sdk::types::block::output::AliasId;
use log::{debug, info, warn};
use token_wallet::get_first_address;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

pub async fn publish_iota_document(document: IotaDocument) -> anyhow::Result<CoreDocument> {
    info!("{}", document.id());

    let client = match document.id().network_str() {
        "rms" => Client::builder().with_primary_node(TESTNET_URL, None)?.finish().await?,
        "smr" => Client::builder().with_primary_node(SHIMMER_URL, None)?.finish().await?,
        "iota" => Client::builder().with_primary_node(MAINNET_URL, None)?.finish().await?,
        _ => anyhow::bail!("Unsupported network"),
    };

    info!("Getting address from Stronghold ...");

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    let secret_manager: ExternSecretManager = ExternSecretManager::Stronghold(
        StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())?,
    );

    // State Controller & Governor
    let wallet_address = get_first_address(&secret_manager, document.id().network_str()).await?;

    // Query the network for the given State Controller address
    let output_ids = client
        .alias_output_ids(vec![QueryParameter::StateController(wallet_address)])
        .await?
        .items;
    debug!("Output IDs: {:?}", output_ids);

    // Convert first OutputId to AliasId
    // TODO: How to handle multiple OutputIds?
    let alias_id: AliasId = output_ids.iter().next().unwrap().into();
    debug!("Alias ID: {:?}", alias_id);

    // Convert to DID
    let iota_did = IotaDID::from_alias_id(&alias_id.to_string(), &NetworkName::try_from("rms").unwrap());
    info!("DID: {:?}", iota_did.as_str());

    // Resolve what's already published
    debug!("Creating resolver ...");
    let resolver = Resolver::new().await;

    debug!("Resolving document ...");
    // let published_address = "did:iota:rms:0x4a55dd9720372deb80bebd2e87e9a1e7273a178ba76b14eefa5b072f4f3c1c5f";
    let result = resolver.resolve(iota_did.as_str()).await;
    if result.is_ok() {
        info!("Successfully resolved!");
        return Ok(result.unwrap());
    } else {
        warn!("Failed to resolve: {:?}", result);

        // Publish the document
        let alias_output = client
            .new_did_output(wallet_address.into_inner(), document.clone(), None)
            .await?;

        info!(
            "Publishing new AliasOutput to the Tangle (network: `{}`) ...",
            client.network_name().await?
        );

        // ==== Uncomment this to actually publish ====
        // let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await?;

        info!("Successfully published AliasOutput.");
    }

    Ok(document.core_document().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{did_document::Method, SecretManager};

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

        let core_document = SecretManager::produce_document(&secret_manager, Method::IotaTestnet)
            .await
            .unwrap();

        let iota_document = IotaDocument::new(&NetworkName::try_from("rms").unwrap());

        publish_iota_document(iota_document).await.unwrap();
    }
}
