use identity_iota::{
    core::{Object, ToJson},
    did::CoreDID,
    document::CoreDocument,
    storage::KeyId,
    verification::VerificationMethod,
};
use serde_json::json;
use shared::JwkStorageWrapper;
use std::io::Error;

pub async fn produce_did_web(
    storage: JwkStorageWrapper,
    key_id: &KeyId,
    host: url::Host,
    port: Option<u16>,
) -> std::result::Result<CoreDocument, Error> {
    // let exists = storage.key_storage().exists(key_id).await.unwrap();

    // if !exists {
    //     return Err(Error::other(format!("Key with id=[{}] does not exist", key_id)));
    // }

    let public_key_jwk = match storage {
        JwkStorageWrapper::Stronghold(stronghold_storage) => stronghold_storage.get_public_key(key_id).await.unwrap(),
        JwkStorageWrapper::PKCS11 => todo!(),
    };

    println!(
        "Producing DID for key_id=[{:?}] from storage=[{:?}] ...",
        key_id.as_str(),
        "TODO_get_name"
    );

    // Construct the URL from host and (optional) port
    // TODO: is there a better default than having to parse to create a new Url?
    let mut url = url::Url::parse("https://example.net").unwrap();
    url.set_host(Some(&host.to_string())).unwrap();
    url.set_port(port).unwrap();

    println!("URL: {}", url.as_str());

    let host_port = if port.is_some() {
        format!("{}:{}", url.host_str().unwrap(), url.port().unwrap())
    } else {
        url.host_str().unwrap().to_string()
    };

    // let host_port = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap_or_default());
    let host_port_encoded = urlencoding::encode(&host_port);

    let did_str = format!("did:web:{}", host_port_encoded);

    // let did_str = match port {
    //     Some(p) => format!("did:web:{}%3A{}", host, p),
    //     None => format!("did:web:{}", host),
    // };

    // let url = url::Url::parse(&format!("https://{}/.well-known/did.json", host)).unwrap();
    // println!("{}", url.port().unwrap());

    // if let Some(did_str) = did_web_extern::DIDWeb.generate(&Source::Key(&jwk)) {
    println!("DID: {:?}", did_str);

    let controller = CoreDID::parse(&did_str).unwrap();

    // println!("Controller: {:?}", controller.method_id());

    let verification_method =
        VerificationMethod::new_from_jwk(controller.clone(), public_key_jwk.clone(), Some("key-0")).unwrap();

    // let assertion_method =
    //     VerificationMethod::builder(BTreeMap::from([("foo".to_string(), "bar".to_json_value().unwrap())]))
    //         .id(DIDUrl::new(did, url))
    //         .build()
    //         .unwrap();

    let mut properties = Object::new();
    properties.insert(
        "@context".to_string(),
        json!([
            "https://www.w3.org/ns/did/v1",
            // "https://w3id.org/security/suites/ed25519-2020/v1"
        ]),
    );

    let document = CoreDocument::builder(properties)
        .id(controller)
        .verification_method(verification_method)
        // .assertion_method(assertion_method)
        .build()
        .unwrap();

    // TODO: Add "@context" to the document

    println!("Host the following json under the following url:\n================================================");
    println!("{}", url.join(".well-known/did.json").unwrap());
    println!("================================================");
    println!("{}", document.to_json_pretty().unwrap());

    Ok(document)
}

#[cfg(test)]
mod tests {
    use crate::consumer::resolve_did_web;

    use super::*;

    use identity_iota::core::ToJson;
    use identity_iota::did::DID;
    use identity_iota::storage::JwkStorage;
    use identity_stronghold::StrongholdStorage;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use shared::test_utils::{get_test_jwk, random_stronghold_path};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Issue: https://github.com/iotaledger/identity.rs/issues/1299
    #[tokio::test]
    async fn produces_did_web() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        println!("====== Preparing Stronghold");

        // Create stronghold
        let stronghold = StrongholdSecretManager::builder()
            .password(Password::from("secure_password".to_owned()))
            .build(random_stronghold_path())
            .unwrap();

        let stronghold_storage = StrongholdStorage::new(stronghold);

        // Generate key
        let jwk = get_test_jwk();
        // println!("JWK: {}", jwk.params().to_json().unwrap());
        // Insert into stronghold
        let key_id = stronghold_storage.insert(jwk.clone()).await.unwrap();
        println!("====== Done");

        // Start mock server and assert
        let mock_server = MockServer::start().await;

        let document = produce_did_web(
            JwkStorageWrapper::Stronghold(stronghold_storage),
            &key_id,
            url::Host::parse("localhost").unwrap(),
            Some(mock_server.address().port()),
        )
        .await
        .unwrap();

        println!("Document: {}", document.to_json_pretty().unwrap());

        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&mock_server)
            .await;

        let did = format!("did:web:localhost%3A{}", mock_server.address().port());
        let document = resolve_did_web(CoreDID::parse(&did).unwrap()).await.unwrap();

        assert_eq!(document.id().as_str(), did);
    }
}
