use identity_iota::{
    core::{FromJson, ToJson},
    did::CoreDID,
    document::CoreDocument,
    verification::{jwk::Jwk, jws::JwsAlgorithm, MethodType, VerificationMethod},
};
use log::{debug, info};
use serde_json::json;
use shared::{error::ProducerError, JwkStorageWrapper};
use std::collections::BTreeMap;

const FRAGMENT: &str = "key-0";

/// Currently, producing a `did:web` document is only supported for **one single key** (either `Ed25519`, `ES256` or `ES256K`).
pub async fn produce_did_web(
    storage: JwkStorageWrapper,
    key_id: &str,
    origin: url::Origin,
    alg: JwsAlgorithm,
) -> Result<CoreDocument, ProducerError> {
    // TODO: check if key exists for given key_id?

    let public_key_jwk = storage.get_public_key(key_id, alg).await?;

    info!("Producing `did:web` for key_id `{key_id}` ({alg}) ...");

    debug!("Origin: {}", &origin.ascii_serialization());

    let (_scheme, host, port) = match origin {
        url::Origin::Tuple(ref scheme, ref host, ref port) => (scheme, host, port),
        url::Origin::Opaque(_) => {
            return Err(ProducerError::Generic("Opaque origin not supported".to_string()));
        }
    };

    let host_port_encoded = urlencoding::encode(format!("{}:{}", host, port).as_str()).to_string();

    let did_str = format!("did:web:{}", host_port_encoded);

    info!("DID: `{did_str}`");

    let controller = CoreDID::parse(did_str).unwrap();

    let verification_method = VerificationMethod::new_from_jwk(
        controller.clone(),
        Jwk::from_json_value(public_key_jwk).unwrap(),
        Some(FRAGMENT),
    )
    .unwrap();

    // Patch the generated DID document since it's not according to spec.
    let properties = get_properties(MethodType::JSON_WEB_KEY_2020);

    let document = CoreDocument::builder(properties)
        .id(controller)
        .verification_method(verification_method)
        .build()
        .unwrap();

    let well_known = format!("{}/.well-known/did.json", origin.ascii_serialization());

    info!("Host the following json under the following url:");
    info!("================================================");
    info!("{}", well_known);
    info!("================================================");
    info!("{}", document.to_json_pretty().unwrap());
    info!("================================================");

    Ok(document)
}

fn get_properties(method_type: MethodType) -> BTreeMap<String, serde_json::Value> {
    let mut properties = BTreeMap::new();
    properties.insert(
        "@context".to_string(),
        match method_type.as_str() {
            "Ed25519VerificationKey2018" => json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2018/v1"
            ]),
            "JsonWebKey2020" => json!([
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ]),
            _ => unimplemented!("Unsupported method type"),
        },
    );
    properties
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
    async fn produces_did_web_ed25519() {
        let (stronghold_storage, key_id, _) = new_stronghold_storage().await;

        let mock_server = MockServer::start().await;

        let mock_server_port: u16 = mock_server.address().port();

        let document = produce_did_web(
            JwkStorageWrapper::Stronghold(stronghold_storage),
            key_id.as_str(),
            url::Origin::Tuple(
                "http".to_string(),
                url::Host::Domain("localhost".to_string()),
                mock_server_port,
            ),
            JwsAlgorithm::EdDSA,
        )
        .await
        .unwrap();

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
                "https://w3id.org/security/suites/jws-2020/v1"
              ],
              "id": format!("did:web:localhost%3A{}", mock_server_port),
              "verificationMethod": [
                {
                  "id": format!("did:web:localhost%3A{}#key-0", mock_server_port),
                  "type": "JsonWebKey2020",
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
