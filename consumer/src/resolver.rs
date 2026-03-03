use did_iota::consumer::{get_iota_client, IotaClients, NodeUrls};
use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::{CoreDID, DID as _};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver as IdentityResolver;
use shared::error::ConsumerError;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
struct ResolverConfig {
    tls_config: Option<rustls::ClientConfig>,
    node_urls: Option<NodeUrls>,
    basic_auth: Option<(String, String)>,
}

#[derive(Debug)]
pub struct Resolver {
    // We store the config so that we can initialize the resolver lazily
    config: ResolverConfig,

    iota_clients: RwLock<IotaClients>,
    // We use an RwLock to allow concurrent reads, but exclusive access for initialization
    resolver: RwLock<Option<Arc<IdentityResolver>>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            config: ResolverConfig {
                tls_config: None,
                node_urls: None,
                basic_auth: None,
            },
            resolver: RwLock::new(None),
            iota_clients: RwLock::new(IotaClients::default()),
        }
    }

    pub fn new_with_options(
        tls_config: Option<rustls::ClientConfig>,
        node_urls: Option<NodeUrls>,
        basic_auth: Option<(&str, &str)>,
    ) -> Self {
        Self {
            config: ResolverConfig {
                tls_config,
                node_urls,
                // Convert &str to String because we need to own the data for future initialization
                basic_auth: basic_auth.map(|(u, p)| (u.to_string(), p.to_string())),
            },
            resolver: RwLock::new(None),
            iota_clients: RwLock::new(IotaClients::default()),
        }
    }

    /// This function returns the `Resolver` instance if it exists, or initializes it if it doesn't. It also ensures
    /// that the appropriate IOTA handler is attached based on the authority. The 'basic' handlers (jwk, key, web) are
    /// always attached in the base `Resolver`, but the IOTA handlers are only attached when needed. This way we avoid
    /// the initialization of the IOTA client and handler for non-IOTA DIDs, and we only initialize the specific IOTA
    /// client when we encounter a DID that requires it.
    async fn get_or_init_resolver(&self, authority: &str) -> Result<Arc<IdentityResolver>, ConsumerError> {
        // Ensure the basic resolver exists first
        let basic_resolver_opt = self.resolver.read().await.clone();

        let mut resolver_arc = if let Some(resolver) = basic_resolver_opt {
            resolver
        } else {
            let mut guard = self.resolver.write().await;
            if let Some(resolver) = guard.as_ref() {
                resolver.clone()
            } else {
                // Initialize the basic resolver with non-IOTA handlers (jwk, key, web).
                let mut resolver = IdentityResolver::new();
                Self::add_basic_handlers(&mut resolver);
                let arc = Arc::new(resolver);
                *guard = Some(arc.clone());
                arc
            }
        };

        // Determine if this is an IOTA request
        if !authority.starts_with("iota:") {
            return Ok(resolver_arc);
        }

        // Determine the network parameters based on the authority prefix.
        let (network_name, get_node_url): (&str, fn(&NodeUrls) -> Option<String>) =
            if authority.starts_with("iota:testnet:") {
                ("testnet", |urls| urls.testnet.clone())
            } else if authority.starts_with("iota:devnet:") {
                ("devnet", |urls| urls.devnet.clone())
            } else {
                ("iota", |urls| urls.mainnet.clone())
            };

        // Acquire write lock immediately to check and initialize
        let mut clients_guard = self.iota_clients.write().await;

        let needs_initialization = match network_name {
            "testnet" => !clients_guard.testnet,
            "devnet" => !clients_guard.devnet,
            _ => !clients_guard.mainnet,
        };

        if needs_initialization {
            let node_url = self.config.node_urls.as_ref().and_then(get_node_url);

            let iota_client = get_iota_client(
                network_name,
                self.config.tls_config.clone(),
                node_url,
                self.config.basic_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
            )
            .await
            .ok_or_else(|| ConsumerError::Generic(format!("Failed to initialize IOTA client: {}", network_name)))?;

            // Reconstruct resolver with new client
            let mut resolver_guard = self.resolver.write().await;
            let mut new_resolver = IdentityResolver::new();
            Self::add_basic_handlers(&mut new_resolver);
            new_resolver.attach_iota_handler(iota_client);

            let new_arc = Arc::new(new_resolver);
            *resolver_guard = Some(new_arc.clone());
            resolver_arc = new_arc;

            // Update flags
            match network_name {
                "testnet" => clients_guard.testnet = true,
                "devnet" => clients_guard.devnet = true,
                _ => clients_guard.mainnet = true,
            }
        } else {
            // Already initialized.
            // We need to fetch the current resolver. We can take a read lock on it.
            // Note: We still hold clients_guard here, ensuring no one else is modifying the structure while we read.
            if let Some(current) = self.resolver.read().await.clone() {
                resolver_arc = current;
            }
        }

        Ok(resolver_arc)
    }

    fn add_basic_handlers(resolver: &mut IdentityResolver) {
        resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
        resolver.attach_handler("key".to_owned(), resolve_did_key);
        resolver.attach_handler("web".to_owned(), resolve_did_web);
    }

    pub async fn resolve(&self, did: &str) -> Result<CoreDocument, ConsumerError> {
        let did: CoreDID = CoreDID::parse(did)?;

        // Ensure resolver is initialized
        let resolver = self.get_or_init_resolver(did.authority()).await?;

        let document: CoreDocument = resolver.resolve(&did).await?;
        Ok(document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[test(tokio::test)]
    async fn resolve_all_supported_methods() {
        let resolver = Resolver::new();
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );

        let did = "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(document.id().to_string(), did);

        // TODO: add more ...
    }

    #[test(tokio::test)]
    async fn concurrent_resolutions_do_not_deadlock() {
        let resolver = Arc::new(Resolver::new());
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let mut handles = vec![];
        for _ in 0..50 {
            let resolver_clone = resolver.clone();
            handles.push(tokio::spawn(async move { resolver_clone.resolve(did).await }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent resolution failed: {:?}", result.err());
        }
    }

    #[test(tokio::test)]
    async fn iota_failure_does_not_break_basic_resolver() {
        // This test simulates a scenario where IOTA resolution might fail (due to network or config),
        // but validates that basic methods (key/jwk) continue to work.
        let resolver = Resolver::new();

        // 1. Resolve basic DID successfully
        let key_did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        assert!(resolver.resolve(key_did).await.is_ok());

        // 2. Attempt invalid IOTA network resolution
        // Note: Unless we have a real network, this will likely fail or timeout.
        // We just want to ensure it doesn't panic or poison the resolver for future calls.
        let iota_did = "did:iota:testnet:0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let _ = resolver.resolve(iota_did).await; // We ignore the result, potentially Err

        // 3. Resolve basic DID again - should still succeed
        assert!(resolver.resolve(key_did).await.is_ok());
    }

    #[test(tokio::test)]
    async fn fails_on_unsupported_method() {
        let resolver = Resolver::new();
        let did = "did:foo:bar";
        let result = resolver.resolve(did).await;

        assert!(result.is_err());
    }

    #[ignore]
    #[test(tokio::test)]
    async fn resolves_did_iota() {
        let resolver = Resolver::new();
        let did = "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }
}
