use did_key_extern::{resolve, DIDCore, Fingerprint, CONFIG_JOSE_PUBLIC};
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use log::info;

pub async fn resolve_did_key(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    info!("Resolving DID: {}", did);
    let key = resolve(did.as_str()).unwrap();
    info!("key fingerprint: {:?}", key.fingerprint());
    let document = key.get_did_document(CONFIG_JOSE_PUBLIC);
    info!("document: {:#?}", document);
    CoreDocument::from_json(&document.to_json().unwrap())
}

async fn configure() -> Resolver {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver
}

#[allow(dead_code)]
async fn resolve_did(did: &str) -> std::result::Result<CoreDocument, Box<dyn std::error::Error>> {
    let did = CoreDID::parse(did)?;
    let resolver: Resolver = configure().await;
    let document: CoreDocument = resolver.resolve(&did).await?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_did_key() {
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = resolve_did(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );

        assert_eq!(
            document.verification_method().first().unwrap().id().to_string(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );
    }
}
