use iota_sdk::client::error::Error;
use iota_sdk::client::Client;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

/// Builds clients for all IOTA networks.
pub async fn iota_clients() -> Result<Vec<(&'static str, Client)>, Error> {
    let mainnet_client: Client = Client::builder().with_primary_node(MAINNET_URL, None)?.finish().await?;
    let shimmer_client: Client = Client::builder().with_primary_node(SHIMMER_URL, None)?.finish().await?;
    let testnet_client: Client = Client::builder().with_primary_node(TESTNET_URL, None)?.finish().await?;

    Ok(vec![
        ("iota", mainnet_client),
        ("smr", shimmer_client),
        ("rms", testnet_client),
    ])
}
