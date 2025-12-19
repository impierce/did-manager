use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::IotaClientBuilder;

// Helper to create a builder with optional TLS config AND/OR node url
fn client_builder_with_tls_or_url(
    tls_config: Option<&rustls::ClientConfig>,
    node_url: Option<&str>,
) -> IotaClientBuilder {
    let mut builder = IotaClientBuilder::default();
    if let Some(url) = node_url {
        builder = builder.ws_url(url);
    }
    if let Some(cfg) = tls_config {
        builder = builder.tls_config(cfg.clone());
    }
    builder
}

/// Builds clients for all IOTA networks with optional node URL and/or TLS config.
pub async fn iota_clients(
    node_url: Option<&str>,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let iota_testnet = client_builder_with_tls_or_url(tls_config.as_ref(), node_url)
        .build_testnet()
        .await?;
    let iota_devnet = client_builder_with_tls_or_url(tls_config.as_ref(), node_url)
        .build_devnet()
        .await?;
    let iota_mainnet = client_builder_with_tls_or_url(tls_config.as_ref(), node_url)
        .build_mainnet()
        .await?;

    Ok(vec![
        ("testnet", IdentityClientReadOnly::new(iota_testnet).await?),
        ("devnet", IdentityClientReadOnly::new(iota_devnet).await?),
        ("iota", IdentityClientReadOnly::new(iota_mainnet).await?),
    ])
}
