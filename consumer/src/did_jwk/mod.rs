use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::DIDMethod;

/// https://github.com/spruceid/ssi/tree/main/did-jwk/

pub async fn resolve_did_jwk(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    println!("Resolving DID: {}", did);
    let resolver = did_jwk::DIDJWK.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        println!("Error: {:?}", error);
        return Err(identity_iota::core::Error::OneOrSetEmpty);
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
