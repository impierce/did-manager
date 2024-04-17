use did_key_extern::{resolve, DIDCore, CONFIG_JOSE_PUBLIC};
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use log::info;
use shared::error::ConsumerError;

pub async fn resolve_did_key(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: {}", did);
    let key = resolve(did.as_str()).unwrap();
    let document = key.get_did_document(CONFIG_JOSE_PUBLIC);
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

    use serde_json::json;
    use test_log::test;

    #[test(tokio::test)]
    async fn resolves_did_key() {
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = resolve_did(did).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
                "@context": "https://www.w3.org/ns/did/v1", // TODO: <== not according to spec! (should be array)
                "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
                "verificationMethod": [
                  {
                    "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
                    "type": "JsonWebKey2020",
                    "controller": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
                    "publicKeyJwk": {
                      "kty": "OKP",
                      "crv": "Ed25519",
                      "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
                    }
                  },
                  {
                    "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6LSrdqo4M24WRDJj1h2hXxgtDTyzjjKCiyapYVgrhwZAySn",
                    "type": "OKP", // TODO: <== not according to spec! (should be "JsonWebKey2020")
                    "controller": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
                    "publicKeyJwk": {
                      "kty": "OKP",
                      "crv": "X25519",
                      "x": "3kY9jl1by7pLzgJktUH-e9H6fihdVUb00-sTzkfmIl8"
                    }
                  }
                ],
                "authentication": [
                  "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
                ],
                "assertionMethod": [
                  "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
                ],
                "capabilityDelegation": [
                  "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
                ],
                "capabilityInvocation": [
                  "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
                ],
                "keyAgreement": [
                  "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6LSrdqo4M24WRDJj1h2hXxgtDTyzjjKCiyapYVgrhwZAySn"
                ]
            })
        );
    }
}
