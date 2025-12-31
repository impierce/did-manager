use did_iota::consumer::iota_clients;
use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver as IdentityResolver;
use shared::error::ConsumerError;

#[derive(Debug)]
pub struct Resolver {
    pub(crate) resolver: IdentityResolver,
}

impl Resolver {
    pub async fn new(node_url: Option<&str>, tls_config: Option<rustls::ClientConfig>) -> Self {
        let resolver = configure_resolver(IdentityResolver::new(), node_url, tls_config)
            .await
            .expect("Failed to configure resolver");
        Self { resolver }
    }

    pub async fn resolve(&self, did: &str) -> Result<CoreDocument, ConsumerError> {
        let did = CoreDID::parse(did)?;
        let document: CoreDocument = self.resolver.resolve(&did).await?;
        Ok(document)
    }
}

async fn configure_resolver(
    mut resolver: IdentityResolver,
    node_url: Option<&str>,
    tls_config: Option<rustls::ClientConfig>,
) -> Result<IdentityResolver, ConsumerError> {
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver.attach_handler("web".to_owned(), resolve_did_web);

    resolver.attach_multiple_iota_handlers(
        iota_clients(node_url, tls_config)
            .await
            .map_err(|e| ConsumerError::Generic(format!("Failed to attach IOTA handlers: {e}")))?,
    );

    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[test(tokio::test)]
    async fn resolve_all_supported_methods() {
        let resolver = Resolver::new(None, None).await;
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
        let resolver = Resolver::new(None, None).await;
        let did = "did:foo:bar";
        let result = resolver.resolve(did).await;

        assert!(result.is_err());
    }

    #[ignore]
    #[test(tokio::test)]
    async fn resolves_did_iota() {
        let resolver = Resolver::new(None, None).await;
        let did = "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = resolver.resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }
}
