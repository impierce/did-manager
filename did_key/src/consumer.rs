use did_key_extern::{resolve, Config, DIDCore, Fingerprint};
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;

pub async fn resolve_did_key(did: CoreDID) -> std::result::Result<CoreDocument, identity_iota::core::Error> {
    println!("Resolving DID: {}", did);
    let key = resolve(did.as_str()).unwrap();
    println!("key fingerprint: {:?}", key.fingerprint());
    let document = key.get_did_document(Config::default());
    println!("document: {:#?}", document);
    let document = CoreDocument::from_json(&document.to_json().unwrap());
    document
}

async fn configure() -> Resolver {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver
}

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
