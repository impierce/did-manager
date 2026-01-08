use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::{IotaClient, IotaClientBuilder};

/// Builds clients for all IOTA networks.
///
/// Parameters:
/// - TLS configuration (optional)
/// - Node URLs (optional)
/// - Basic Authentication (optional)
///
/// This function only returns an error if it fails to build. The provided values are not validated.
pub async fn iota_clients(
    tls_config: Option<rustls::ClientConfig>,
    node_urls: Option<NodeUrls>,
    basic_auth: Option<(&str, &str)>,
) -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let iota_mainnet: IotaClient;
    let iota_testnet: IotaClient;
    let iota_devnet: IotaClient;
    if let Some(urls) = &node_urls {
        iota_mainnet = match &urls.mainnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_mainnet().await?,
        };
        iota_testnet = match &urls.testnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_testnet().await?,
        };
        iota_devnet = match &urls.devnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_devnet().await?,
        };
    } else {
        iota_mainnet = client_builder(tls_config.as_ref(), basic_auth).build_mainnet().await?;
        iota_testnet = client_builder(tls_config.as_ref(), basic_auth).build_testnet().await?;
        iota_devnet = client_builder(tls_config.as_ref(), basic_auth).build_devnet().await?;
    }

    Ok(vec![
        ("iota", IdentityClientReadOnly::new(iota_mainnet).await?),
        ("testnet", IdentityClientReadOnly::new(iota_testnet).await?),
        ("devnet", IdentityClientReadOnly::new(iota_devnet).await?),
    ])
}

fn client_builder(tls_config: Option<&rustls::ClientConfig>, basic_auth: Option<(&str, &str)>) -> IotaClientBuilder {
    let mut builder = IotaClientBuilder::default();
    if let Some(cfg) = tls_config {
        builder = builder.tls_config(cfg.clone());
    }
    if let Some((username, password)) = basic_auth {
        builder = builder.basic_auth(username, password);
    }
    builder
}

#[derive(Debug, Clone)]
pub struct NodeUrls {
    pub mainnet: Option<String>,
    pub testnet: Option<String>,
    pub devnet: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_iota_clients_custom_node_config() {
        let node_urls = NodeUrls {
            mainnet: Some("https://rpc.mainnet.iota.monochain.p2p.org/".to_string()),
            testnet: None,
            devnet: None,
        };

        let basic_auth = Some(("username", "password"));

        let _ = iota_clients(None, Some(node_urls), basic_auth).await.unwrap();
    }
}
