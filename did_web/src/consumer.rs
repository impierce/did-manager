use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use log::{debug, info};
use shared::error::ConsumerError;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::{DIDMethod, Document};

pub async fn resolve_did_web(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: `{did}`");
    let resolver = did_web_extern::DIDWeb.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        info!("Error: {error:?}");
        return Err(ConsumerError::Generic(error));
    }

    // FIXME: This is a workaround for a bug in the confomrance tests.
    let document = if let Some(document) = document.clone() {
        let mut json = serde_json::json!(document);

        let _test: Option<String> = json
            .get_mut("verificationMethod")
            .and_then(|vm| vm.get_mut(0))
            .and_then(|vm0| vm0.get_mut("controller"))
            .and_then(|controller| {
                let mut temp = controller.as_str().unwrap_or_default().to_string();
                if !temp.starts_with("did:web:") {
                    temp = format!("did:web:{}", temp);
                }
                *controller = serde_json::json!(temp);
                None
            });

        let _test: Option<String> = json
            .get_mut("authentication")
            .and_then(|authn| authn.get_mut(0))
            .and_then(|authn0| {
                let mut temp = authn0.as_str().unwrap_or_default().to_string();
                if !temp.starts_with("did:web:") {
                    temp = format!("did:web:{}", temp);
                }
                *authn0 = serde_json::json!(temp);
                None
            });

        let document =
            Document::from_json(json.to_string().as_str()).map_err(|e| ConsumerError::Generic(e.to_string()))?;

        Some(document)
    } else {
        None
    };

    CoreDocument::from_json(&document.to_json().unwrap()).map_err(|e| ConsumerError::Generic(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use test_log::test;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test(tokio::test)]
    async fn resolves_did_web_with_ed25519_key() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
              ],
              "id": format!("did:web:localhost%3A{}", mock_server.address().port()),
              "verificationMethod": [
                {
                  "id": "did:web:localhost#key-0",
                  "type": "JsonWebKey2020",
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
        let document = resolve_did_web(CoreDID::parse(&did).unwrap()).await.unwrap();

        // TODO: improve assertion
        assert_eq!(document.id().as_str(), did);
    }

    // Resolving other key types is pointless, since they are hosted by the DID document
}
