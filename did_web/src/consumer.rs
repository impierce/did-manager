use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use log::{debug, info};
use shared::error::ConsumerError;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::DIDMethod;

pub async fn resolve_did_web(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: {}", did);
    let resolver = did_web_extern::DIDWeb.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        info!("Error: {:?}", error);
        return Err(ConsumerError::Generic(error));
    }

    debug!("Result: {:#?}", result);
    debug!("Document: {:#?}", document);
    debug!("Metadata: {:#?}", metadata);
    CoreDocument::from_json(&document.to_json().unwrap()).map_err(|e| ConsumerError::Generic(e.to_string()))
}

async fn configure() -> Resolver {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_handler("web".to_owned(), resolve_did_web);
    resolver
}

#[allow(dead_code)]
async fn resolve_did(did: &str) -> Result<CoreDocument, ConsumerError> {
    let did = CoreDID::parse(did)?;
    let resolver: Resolver = configure().await;
    let document: CoreDocument = resolver.resolve(&did).await?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use test_log::test;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test(tokio::test)]
    async fn resolves_did_web() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": format!("did:web:localhost%3A{}", mock_server.address().port()),
              "verificationMethod": [
                {
                  "id": "did:web:localhost#key-0",
                  "type": "Ed25519VerificationKey2018",
                  "controller": "did:web:localhost",
                  "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww"
                  }
                }
              ],
              "assertionMethod": [
                "did:web:localhost#key-0"
              ]
            })))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server.address().port());
        let document = resolve_did(&did).await.unwrap();

        assert_eq!(document.id().as_str(), did);
    }
}
