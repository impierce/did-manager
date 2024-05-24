use did_key_extern::DIDKey;
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use log::info;
use shared::error::ConsumerError;
use ssi_dids::did_resolve::dereference;

pub async fn resolve_did_key(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: {}", did);
    let (_, document, _) = dereference(&DIDKey, did.as_str(), &Default::default()).await;
    info!("{}", document.to_json_pretty().unwrap());
    CoreDocument::from_json(&document.to_json().unwrap()).map_err(|e| ConsumerError::Generic(e.to_string()))
}

async fn configure() -> Resolver {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_handler("key".to_owned(), resolve_did_key);
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

    use identity_iota::verification::jwk::Jwk;
    use serde_json::json;
    use test_log::test;

    // DISCLAIMER: The resolved DID documents are not according to spec!
    // However, this does not matter that much since they are deterministically resolved
    // and all that matters is that the public key is correct.

    #[test(tokio::test)]
    async fn resolves_did_key_ed25519() {
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = resolve_did(did).await.unwrap();

        let actual = document
            .verification_method()
            .first()
            .unwrap()
            .data()
            .public_key_jwk()
            .unwrap()
            .to_owned();

        let expected = Jwk::from_json_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"}))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test(tokio::test)]
    async fn resolves_did_key_es256() {
        // Test vector from https://w3c-ccg.github.io/did-method-key/#p-256 (p256 always start with `zDn`)
        let did = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let document = resolve_did(did).await.unwrap();

        let actual = document
            .verification_method()
            .first()
            .unwrap()
            .data()
            .public_key_jwk()
            .unwrap()
            .to_owned();

        let expected = Jwk::from_json_value(json!({
          "kty": "EC",
          "crv": "P-256",
          "x": "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
          "y": "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"}))
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test(tokio::test)]
    async fn resolves_did_key_es256k() {
        // Test vector from https://w3c-ccg.github.io/did-method-key/#secp256k1 (secp256k1 always start with `zQ3s`)
        let did = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        let document = resolve_did(did).await.unwrap();

        let actual = document
            .verification_method()
            .first()
            .unwrap()
            .data()
            .public_key_jwk()
            .unwrap()
            .to_owned();

        let expected = Jwk::from_json_value(json!({
          "kty": "EC",
          "crv": "secp256k1",
          "x": "h0wVx_2iDlOcblulc8E5iEw1EYh5n1RYtLQfeSTyNc0",
          "y": "O2EATIGbu6DezKFptj5scAIRntgfecanVNXxat1rnwE"}))
        .unwrap();

        assert_eq!(actual, expected);
    }
}
