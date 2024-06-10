use identity_iota::{
    core::{Object, ToJson},
    did::CoreDID,
    document::CoreDocument,
    storage::KeyId,
    verification::VerificationMethod,
};
use log::{debug, info};
use serde_json::json;
use shared::JwkStorageWrapper;
use std::io::Error;

pub async fn produce_did_web(
    storage: JwkStorageWrapper,
    key_id: &KeyId,
    origin: url::Origin,
) -> Result<CoreDocument, Error> {
    // TODO: check if key exists for given key_id?

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage.get_public_key(key_id).await.unwrap(),
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    info!("Producing did:web for key_id=[{:?}] ...", key_id.as_str());

    debug!("Origin: {}", &origin.ascii_serialization());

    let (_scheme, host, port) = match origin {
        url::Origin::Tuple(ref scheme, ref host, ref port) => (scheme, host, port),
        url::Origin::Opaque(_) => {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Opaque origin not supported",
            ));
        }
    };

    let host_port_encoded = urlencoding::encode(format!("{}:{}", host, port).as_str()).to_string();

    let did_str = format!("did:web:{}", host_port_encoded);

    info!("DID: {:?}", did_str);

    let controller = CoreDID::parse(&did_str).unwrap();

    let verification_method =
        VerificationMethod::new_from_jwk(controller.clone(), public_key_jwk.clone(), Some("key-0")).unwrap();

    let mut properties = Object::new();
    properties.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1" // TODO: make dynamic
        ]),
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::consumer::resolve_did_web;

    use identity_iota::core::ToJson;
    use shared::test_utils::new_stronghold_storage;
    use test_log::test;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test(tokio::test)]
    async fn produces_did_web() {
        let (stronghold_storage, key_id) = new_stronghold_storage().await;

        // Start mock server and assert
        let mock_server = MockServer::start().await;

        let mock_server_port: u16 = mock_server.address().port();

        let document = produce_did_web(
            JwkStorageWrapper::Stronghold(stronghold_storage),
            &key_id,
            url::Origin::Tuple(
                "http".to_string(),
                url::Host::Domain("localhost".to_string()),
                mock_server_port,
            ),
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
