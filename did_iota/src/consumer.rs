use identity_iota::iota::rebased::client::IdentityClientReadOnly;
use iota_sdk::IotaClientBuilder;

/// Builds client for the specified IOTA network with optional TLS configuration, node URLs, and basic authentication.
///
/// Parameters:
/// - TLS configuration (optional)
/// - Node URL (optional)
/// - Basic Authentication (optional)
///
/// This function returns an `IdentityClientReadOnly` instance if the client is successfully built, or `None` if there was an error during initialization.
pub async fn get_iota_client(
    network: &str,
    tls_config: Option<rustls::ClientConfig>,
    node_url: Option<String>,
    basic_auth: Option<(&str, &str)>,
) -> Option<IdentityClientReadOnly> {
    let mut builder = IotaClientBuilder::default();

    if let Some(cfg) = tls_config {
        builder = builder.tls_config(cfg);
    }
    if let Some((username, password)) = basic_auth {
        builder = builder.basic_auth(username, password);
    }

    let iota_client = if let Some(node_url) = &node_url {
        builder.build(node_url).await.ok()?
    } else {
        match network {
            "iota" => builder.build_mainnet().await.ok()?,
            "testnet" => builder.build_testnet().await.ok()?,
            "devnet" => builder.build_devnet().await.ok()?,
            _ => return None,
        }
    };

    IdentityClientReadOnly::new(iota_client).await.ok()
}

#[derive(Debug, Default)]
pub struct IotaClients {
    pub mainnet: bool,
    pub testnet: bool,
    pub devnet: bool,
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
        let basic_auth = Some(("username", "password"));

        let _ = get_iota_client(
            "iota",
            None,
            Some("https://rpc.mainnet.iota.monochain.p2p.org/".to_string()),
            basic_auth,
        )
        .await
        .unwrap();
    }
}
