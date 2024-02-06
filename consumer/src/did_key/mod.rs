use did_key::{resolve, Config, DIDCore, Fingerprint};
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;

/// https://github.com/decentralized-identity/did-key.rs

pub async fn resolve_did_key(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    println!("Resolving DID: {}", did);
    let key = resolve(did.as_str()).unwrap();
    println!("key: {:?}", key.fingerprint());
    let document = key.get_did_document(Config::default());
    println!("document: {:#?}", document);
    let document = CoreDocument::from_json(&document.to_json().unwrap());
    document
}

// #[cfg(test)]
mod tests {
    use super::*;

    // #[tokio::test]
    async fn it_works() {
        let did = CoreDID::parse("did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL").unwrap();
        // let result = configure_and_resolve(did).await.unwrap();

        // assert_eq!(result.id(), "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL");
    }
}
