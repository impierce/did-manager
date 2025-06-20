use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::IotaClientBuilder;

/// Builds clients for all IOTA networks.
pub async fn iota_clients(
    tls_config: Option<rustls::ClientConfig>,
) -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let tls_config = tls_config.unwrap();
    let iota_testnet = IotaClientBuilder::default()
        .tls_config(tls_config.clone())
        .build_testnet()
        .await?;
    let iota_devnet = IotaClientBuilder::default()
        .tls_config(tls_config.clone())
        .build_devnet()
        .await?;
    let iota_mainnet = IotaClientBuilder::default()
        .tls_config(tls_config)
        .build_mainnet()
        .await?;

    Ok(vec![
        ("iota_testnet", IdentityClientReadOnly::new(iota_testnet).await?),
        ("iota_devnet", IdentityClientReadOnly::new(iota_devnet).await?),
        ("iota_mainnet", IdentityClientReadOnly::new(iota_mainnet).await?),
    ])
}
