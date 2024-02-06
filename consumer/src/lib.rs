pub mod did_jwk;
pub mod did_key;
pub mod did_web;

use did_jwk::resolve_did_jwk;
use did_key::resolve_did_key;
use did_web::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;

async fn configure_and_resolve(did: &str) -> std::result::Result<CoreDocument, Box<dyn std::error::Error>> {
    let did = CoreDID::parse(did)?;
    let resolver: Resolver = configure_resolver(Resolver::new());
    let document: CoreDocument = resolver.resolve(&did).await?;
    Ok(document)
}

fn configure_resolver(mut resolver: Resolver) -> Resolver {
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver.attach_handler("web".to_owned(), resolve_did_web);
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    resolver
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn resolves_did_key() {
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );
    }

    #[tokio::test]
    async fn resolves_did_web() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server.address().port());
        let document = configure_and_resolve(&did).await.unwrap();

        assert_eq!(document.id(), "did:web:foobar");
    }

    #[tokio::test]
    async fn resolves_did_jwk() {
        let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(document.id(), "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");
    }
}
