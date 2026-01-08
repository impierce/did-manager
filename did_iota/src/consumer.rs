use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use identity_iota::iota::rebased::Error;
use iota_sdk::{IotaClient, IotaClientBuilder};

/// Builds clients for all IOTA networks with optional node URL, TLS confiuration and basic authentication (username, password).
/// Only returns an error if it fails to build, incorrect tls_config or node_urls aren't caught but simply defaults.
pub async fn iota_clients(
    tls_config: Option<rustls::ClientConfig>,
    node_urls: Option<NodeUrls>,
    basic_auth: Option<(&str, &str)>,
) -> Result<Vec<(&'static str, IdentityClientReadOnly)>, Error> {
    let iota_mainnet: IotaClient;
    let iota_devnet: IotaClient;
    let iota_testnet: IotaClient;
    if let Some(urls) = &node_urls {
        iota_mainnet = match &urls.mainnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_mainnet().await?,
        };
        iota_devnet = match &urls.devnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_devnet().await?,
        };
        iota_testnet = match &urls.testnet {
            Some(url) => client_builder(tls_config.as_ref(), basic_auth).build(url).await?,
            None => client_builder(tls_config.as_ref(), basic_auth).build_testnet().await?,
        };
    } else {
        iota_mainnet = client_builder(tls_config.as_ref(), basic_auth).build_mainnet().await?;
        iota_devnet = client_builder(tls_config.as_ref(), basic_auth).build_devnet().await?;
        iota_testnet = client_builder(tls_config.as_ref(), basic_auth).build_testnet().await?;
    }

    Ok(vec![
        ("iota", IdentityClientReadOnly::new(iota_mainnet).await?),
        ("devnet", IdentityClientReadOnly::new(iota_devnet).await?),
        ("testnet", IdentityClientReadOnly::new(iota_testnet).await?),
    ])
}

// Helpers

// Helper to create a builder with optional TLS config and basic_auth configuration
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

/// This struct is to strictly define what is passed as an argument to fn iota_clients()
/// If None is passed the IOTA default node for that net will be used.
#[derive(Debug, Clone)]
pub struct NodeUrls {
    pub mainnet: Option<String>,
    pub devnet: Option<String>,
    pub testnet: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This is a very basic test which simply checks wether the function completes without error.
    /// All resulting structs are private in the identity.rs crates, therefore no assertions can be made.
    /// See the second test for a more in-depth test.
    #[tokio::test]
    async fn test_iota_clients_node_urls() {
        let node_urls = NodeUrls {
            mainnet: Some("https://rpc.mainnet.iota.monochain.p2p.org/".to_string()),
            devnet: Some("https://indexer.devnet.iota.cafe".to_string()),
            testnet: Some("https://rpc.ankr.com/iota_testnet".to_string()),
        };

        iota_clients(None, Some(node_urls), None).await.unwrap();
    }

    /// This tests the underlying logic in our iota_clients() fn in a way that we can also make assertions.
    #[tokio::test]
    async fn test_iota_client_builder_node_urls() {
        let mainnet = IotaClientBuilder::default()
            .build("https://rpc.mainnet.iota.monochain.p2p.org/")
            .await
            .unwrap();
        let devnet = IotaClientBuilder::default()
            .build("https://indexer.devnet.iota.cafe")
            .await
            .unwrap();
        let testnet = IotaClientBuilder::default()
            .build("https://rpc.ankr.com/iota_testnet")
            .await
            .unwrap();

        let main_http_str = format!("{:?}", mainnet.http());
        let dev_http_str = format!("{:?}", devnet.http());
        let test_http_str = format!("{:?}", testnet.http());

        assert!(main_http_str.contains("https://rpc.mainnet.iota.monochain.p2p.org/"));
        assert!(dev_http_str.contains("https://indexer.devnet.iota.cafe"));
        assert!(test_http_str.contains("https://rpc.ankr.com/iota_testnet"));
    }
}
