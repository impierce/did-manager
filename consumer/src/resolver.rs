use did_iota::consumer::iota_clients;
use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver as IdentityResolver;
use iota_sdk::client::node_manager::node::NodeAuth;
use iota_sdk::client::Client;
use shared::error::ConsumerError;

pub struct Resolver {
    pub(crate) resolver: IdentityResolver,
}

impl Resolver {
    pub async fn new() -> Self {
        let resolver = configure_resolver(IdentityResolver::new())
            .await
            .expect("Failed to configure resolver");
        Self { resolver }
    }

    pub async fn resolve(&self, did: &str) -> Result<CoreDocument, ConsumerError> {
        let did = CoreDID::parse(did)?;
        let document: CoreDocument = self.resolver.resolve(&did).await?;
        Ok(document)
    }

    /// Set a user-defined node by providing a URL (and optional authentication). Existing nodes will be overwritten.
    ///
    /// This can also be used to define a custom IOTA-based method (such as `iota:snd` for sandbox environments).
    ///
    /// **Disclaimer: Only works with IOTA DIDs.**
    pub async fn set_node_url(&mut self, url: &str, auth: Option<NodeAuth>) -> Result<(), ConsumerError> {
        let client = Client::builder().with_primary_node(url, auth)?.finish().await?;
        self.resolver.attach_iota_handler(client);
        Ok(())
    }
}

async fn configure_resolver(mut resolver: IdentityResolver) -> Result<IdentityResolver, ConsumerError> {
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver.attach_handler("web".to_owned(), resolve_did_web);
    resolver.attach_multiple_iota_handlers(iota_clients().await?);

    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[test(tokio::test)]
    async fn resolve_all_supported_methods() {
        let resolver = Resolver::new().await;
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );

        // TODO: add more ...
    }

    #[test(tokio::test)]
    async fn fails_on_unsupported_method() {
        let resolver = Resolver::new().await;
        let did = "did:foo:bar";
        let result = resolver.resolve(did).await;

        assert!(result.is_err());
    }

    #[ignore]
    #[test(tokio::test)]
    async fn resolves_did_iota() {
        let resolver = Resolver::new().await;
        let did = "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }

    #[ignore]
    #[test(tokio::test)]
    async fn resolves_did_iota_smr() {
        let resolver = Resolver::new().await;
        let did = "did:iota:smr:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:smr:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }

    #[ignore = "unnecessary"]
    #[test(tokio::test)]
    async fn resolves_did_iota_rms() {
        // TODO: are these tests really necessary? (they're essentially just testing the resolver from identity.rs and require internet)
        let resolver = Resolver::new().await;
        let did = "did:iota:rms:0x29418b0a0120d10e20d0dacc78896c200ecd1cc1e3b153be482f150859a96739";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:rms:0x29418b0a0120d10e20d0dacc78896c200ecd1cc1e3b153be482f150859a96739"
        );
    }

    #[ignore = "TODO"]
    #[test(tokio::test)]
    async fn overwrites_existing_node_url() {
        const DID: &str = "did:iota:smr:0x0000000000000000000000000000000000000000000000000000000000000000";

        let mut resolver = Resolver::new().await;

        // Assert the default Node URL
        let default_node_url_error = resolver.resolve(DID).await.unwrap_err();
        println!("{:?}", default_node_url_error);
        assert!(default_node_url_error
            .to_string()
            .contains("https://api.shimmer.network"));

        // Overwrite the Node URL and resolve again
        resolver
            .set_node_url("https://shimmer-node.tanglebay.com", None)
            .await
            .unwrap();
        let updated_node_url_error = resolver.resolve(DID).await.unwrap_err();
        assert!(updated_node_url_error
            .to_string()
            .contains("https://shimmer-node.tanglebay.com"));
    }

    #[ignore = "TODO"]
    #[test(tokio::test)]
    async fn set_custom_node_url() {
        const DID: &str = "did:iota:snd:0x0000000000000000000000000000000000000000000000000000000000000000";

        let mut resolver = Resolver::new().await;

        // Overwrite the Node URL and resolve again
        resolver.set_node_url("http://localhost", None).await.unwrap();
        let node_url_error = resolver.resolve(DID).await.unwrap_err();
        assert!(node_url_error.to_string().contains("http://localhost"));
    }
}
