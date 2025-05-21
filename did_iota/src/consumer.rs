use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::IotaClientBuilder;

/// Builds clients for all IOTA networks.
pub async fn iota_clients() -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let iota_testnet = IotaClientBuilder::default().build_testnet().await?;
    let iota_devnet = IotaClientBuilder::default().build_devnet().await?;
    let iota_mainnet = IotaClientBuilder::default().build_mainnet().await?;

    Ok(vec![
        ("iota_testnet", IdentityClientReadOnly::new(iota_testnet).await?),
        ("iota_devnet", IdentityClientReadOnly::new(iota_devnet).await?),
        ("iota_mainnet", IdentityClientReadOnly::new(iota_mainnet).await?),
    ])
}
