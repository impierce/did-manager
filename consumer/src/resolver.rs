use did_iota::consumer::iota_clients;
use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver as IdentityResolver;
use shared::error::ConsumerError;
use tracing::info;

pub struct Resolver {
    pub(crate) resolver: IdentityResolver,
}

impl Resolver {
    pub async fn new() -> Self {
        info!("Initializing DID resolver...");
        let resolver = configure_resolver(IdentityResolver::new())
            .await
            .expect("Failed to configure resolver");

        info!("Resolver initialized successfully.");

        Self { resolver }
    }

    pub async fn resolve(&self, did: &str) -> Result<CoreDocument, ConsumerError> {
        let did = CoreDID::parse(did)?;
        let document: CoreDocument = self.resolver.resolve(&did).await?;
        Ok(document)
    }
}

async fn configure_resolver(mut resolver: IdentityResolver) -> Result<IdentityResolver, ConsumerError> {
    info!("Configuring DID resolver...");
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    info!("Attached JWK handler.");
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    info!("Attached Key handler.");
    resolver.attach_handler("web".to_owned(), resolve_did_web);
    info!("Attached Web handler.");
    // resolver.attach_multiple_iota_handlers(
    //     iota_clients()
    //         .await
    //         .map_err(|e| ConsumerError::Generic(format!("Failed to attach IOTA handlers: {}", e)))?,
    // );
    // info!("Attached IOTA handlers.");

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
}
