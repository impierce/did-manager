use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::IotaClientBuilder;

/// Builds clients for all IOTA networks.
pub async fn iota_clients(
    tls_config: Option<rustls::ClientConfig>,
) -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let mut iota_testnet_client_builder = IotaClientBuilder::default();

    if let Some(tls_config) = &tls_config {
        iota_testnet_client_builder = iota_testnet_client_builder.tls_config(tls_config.clone());
    }

    let iota_testnet = iota_testnet_client_builder.build_testnet().await?;

    let mut iota_devnet_client_builder = IotaClientBuilder::default();

    if let Some(tls_config) = &tls_config {
        iota_devnet_client_builder = iota_devnet_client_builder.tls_config(tls_config.clone());
    }

    let iota_devnet = iota_devnet_client_builder.build_devnet().await?;

    let mut iota_mainnet_client_builder = IotaClientBuilder::default();

    if let Some(tls_config) = tls_config {
        iota_mainnet_client_builder = iota_mainnet_client_builder.tls_config(tls_config);
    }

    let iota_mainnet = iota_mainnet_client_builder.build_mainnet().await?;

    Ok(vec![
        ("testnet", IdentityClientReadOnly::new(iota_testnet).await?),
        ("devnet", IdentityClientReadOnly::new(iota_devnet).await?),
        ("iota", IdentityClientReadOnly::new(iota_mainnet).await?),
    ])
}
