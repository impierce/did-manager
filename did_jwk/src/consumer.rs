use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use log::info;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::DIDMethod;

pub async fn resolve_did_jwk(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    info!("Resolving DID: {}", did);
    let resolver = did_jwk_extern::DIDJWK.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        info!("Error: {:?}", error);
        return Err(identity_iota::core::Error::OneOrSetEmpty);
        // return Err(Error::other(error));
    }

    info!("result: {:#?}", result);
    // let key = resolve(did.as_str()).unwrap();
    // info!("key: {:?}", key.fingerprint());
    // let document = key.get_did_document(Config::default());
    info!("document: {:#?}", document);
    info!("metadata: {:#?}", metadata);
    CoreDocument::from_json(&document.to_json().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_did_jwk() {
        let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let document = resolve_did_jwk(CoreDID::parse(did).unwrap()).await.unwrap();

        assert_eq!(document.id(), "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9");
    }
}
