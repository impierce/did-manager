use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument, verification::VerificationMethod};
use log::{debug, info};
use shared::{error::ProducerError, JwkStorageWrapper};

pub async fn produce_did_web(
    storage: JwkStorageWrapper,
    key_id: &str,
    host: url::Host,
    port: Option<u16>,
) -> Result<CoreDocument, ProducerError> {
    // TODO: check if key exists for given key_id?

    let public_key_jwk = storage.get_public_key_jwk(key_id).await?;

    info!("Producing did:web for key_id=[{:?}] ...", key_id);

    // Construct the URL from host and (optional) port
    // TODO: is there a better default than having to parse to create a new Url?
    let mut url = url::Url::parse("https://example.net").unwrap();
    url.set_host(Some(&host.to_string())).unwrap();
    url.set_port(port).unwrap();

    debug!("HOST: {}", url.as_str());

    let host_port = if port.is_some() {
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
    } else {
        url.host_str().unwrap().to_string()
    };

    let host_port_encoded = urlencoding::encode(&host_port);

    let did_str = format!("did:web:{}", host_port_encoded);

    info!("DID: {:?}", did_str);

    let controller = CoreDID::parse(&did_str).unwrap();

    let verification_method = VerificationMethod::new_from_jwk(
        controller.clone(),
        serde_json::from_value(public_key_jwk).unwrap(),
        Some("key-0"),
    )
    .unwrap();

    let properties = storage.get_properties();

    let document = CoreDocument::builder(properties)
        .id(controller)
        .verification_method(verification_method)
        .build()
        .unwrap();

    info!("Host the following json under the following url:");
    info!("================================================");
    info!("{}", url.join(".well-known/did.json").unwrap());
    info!("================================================");
    info!("{}", document.to_json_pretty().unwrap());
    info!("================================================");

    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::consumer::resolve_did_web;

    use identity_iota::core::ToJson;
    use serde_json::json;
    use shared::test_utils::new_stronghold_storage;
    use test_log::test;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test(tokio::test)]
    async fn produces_did_web() {
        let (stronghold_storage, key_id, _) = new_stronghold_storage().await;

        // Start mock server and assert
        let mock_server = MockServer::start().await;

        let mock_server_port: u16 = mock_server.address().port();

        let document = produce_did_web(
            JwkStorageWrapper::Stronghold(stronghold_storage),
            key_id.as_str(),
            url::Host::parse("localhost").unwrap(),
            Some(mock_server_port),
        )
        .await
        .unwrap();

        info!("Document: {}", document.to_json_pretty().unwrap());

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server_port);
        let document = resolve_did_web(CoreDID::parse(&did).unwrap()).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
              ],
              "id": format!("did:web:localhost%3A{}", mock_server_port),
              "verificationMethod": [
                {
                  "id": format!("did:web:localhost%3A{}#key-0", mock_server_port),
                  "type": "JsonWebKey", // TODO: should be "JsonWebKey2020"?
                  "controller": format!("did:web:localhost%3A{}", mock_server_port),
                  "publicKeyJwk": {
                    "kty": "OKP",
                    "alg": "EdDSA",
                    "kid": "SFICW73HCwJoBTCiACF1E3Wmrh5LE0xj_G1JVSeXS-M",
                    "crv": "Ed25519",
                    "x": "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88"
                  }
                }
              ]
            })
        );
    }
}
