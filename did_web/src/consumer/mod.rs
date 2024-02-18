use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::DIDMethod;

pub async fn resolve_did_web(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    println!("Resolving DID: {}", did);
    let resolver = did_web_extern::DIDWeb.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        println!("Error: {:?}", error);
        // return Err(identity_iota::core::Error::OneOrSetEmpty);
        // return Err(Error::other(error));
    }

    println!("result: {:#?}", result);
    // let key = resolve(did.as_str()).unwrap();
    // println!("key: {:?}", key.fingerprint());
    // let document = key.get_did_document(Config::default());
    println!("document: {:#?}", document);
    println!("metadata: {:#?}", metadata);
    let document = CoreDocument::from_json(&document.to_json().unwrap());
    document
}

async fn configure() -> Resolver {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_handler("web".to_owned(), resolve_did_web);
    resolver
}

async fn resolve_did(did: &str) -> std::result::Result<CoreDocument, Box<dyn std::error::Error>> {
    let did = CoreDID::parse(did)?;
    let resolver: Resolver = configure().await;
    let document: CoreDocument = resolver.resolve(&did).await?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Issue: https://github.com/iotaledger/identity.rs/issues/1299
    #[tokio::test]
    async fn resolves_did_web() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": format!("did:web:localhost%3A{}", mock_server.address().port()),
              "verificationMethod": [{
                "id": "did:web:localhost#key1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:localhost",
                "publicKeyJwk": {
                  "key_id": "ed25519-2020-10-18",
                  "kty": "OKP",
                  "crv": "Ed25519",
                  "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww"
                }
              }],
              "assertionMethod": ["did:web:localhost#key1"]
            })))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server.address().port());
        let document = resolve_did(&did).await.unwrap();

        assert_eq!(document.id().as_str(), did);
    }
}
