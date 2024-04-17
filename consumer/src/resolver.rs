use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver as IdentityResolver;
use iota_sdk::client::Client;
use shared::error::ConsumerError;

pub struct Resolver {
    pub(crate) resolver: IdentityResolver,
}

impl Resolver {
    pub async fn new() -> Self {
        let resolver = configure_resolver(IdentityResolver::new()).await;
        Self { resolver }
    }

    pub async fn resolve(&self, did: &str) -> Result<CoreDocument, ConsumerError> {
        let did = CoreDID::parse(did)?;
        let document: CoreDocument = self.resolver.resolve(&did).await?;
        Ok(document)
    }
}

// TODO: error handling (return Result), use expect() for Client::builder()
async fn configure_resolver(mut resolver: IdentityResolver) -> IdentityResolver {
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver.attach_handler("web".to_owned(), resolve_did_web);

    // ------------------ IOTA resolvers ------------------
    static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
    static SHIMMER_URL: &str = "https://api.shimmer.network";
    static TESTNET_URL: &str = "https://api.testnet.shimmer.network";
    // ----------------------------------------------------

    let iota_client: Client = Client::builder()
        .with_primary_node(MAINNET_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    let smr_client: Client = Client::builder()
        .with_primary_node(SHIMMER_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    let shimmer_testnet_client: Client = Client::builder()
        .with_primary_node(TESTNET_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    resolver.attach_multiple_iota_handlers(vec![
        ("iota", iota_client),
        ("smr", smr_client),
        ("rms", shimmer_testnet_client),
    ]);

    resolver
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
}
