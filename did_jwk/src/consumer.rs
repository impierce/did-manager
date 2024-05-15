use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use log::{debug, info};
use shared::error::ConsumerError;
use ssi_dids::did_resolve::ResolutionInputMetadata;
use ssi_dids::DIDMethod;

pub async fn resolve_did_jwk(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: {}", did);
    let resolver = did_jwk_extern::DIDJWK.to_resolver();
    let input_metadata = ResolutionInputMetadata::default();
    let (result, document, metadata) = resolver.resolve(did.as_str(), &input_metadata).await;

    if let Some(error) = result.error.clone() {
        info!("Error: {:?}", error);
        return Err(ConsumerError::Generic(error));
    }

    debug!("Result: {:#?}", result);
    debug!("Document: {:#?}", document);
    debug!("Metadata: {:#?}", metadata);
    CoreDocument::from_json(&document.to_json().unwrap()).map_err(|e| ConsumerError::Generic(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use test_log::test;

    #[test(tokio::test)]
    async fn resolves_did_jwk_eddsa() {
        let did = "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJTRklDVzczSEN3Sm9CVENpQUNGMUUzV21yaDVMRTB4al9HMUpWU2VYUy1NIiwia3R5IjoiT0tQIiwieCI6IjZCeG92MWxoSFltQVVHMWNibDM1eUcyYzZtcFpsOVdkeXNqSUhhSjdhODgifQ";
        let document = resolve_did_jwk(CoreDID::parse(did).unwrap()).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
                "@context": [
                  "https://www.w3.org/ns/did/v1",
                  "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [
                  {
                    "id": format!("{}#0", did),
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": {
                      "kty": "OKP",
                      "alg": "EdDSA",
                      "kid": "SFICW73HCwJoBTCiACF1E3Wmrh5LE0xj_G1JVSeXS-M",
                      "crv": "Ed25519",
                      "x": "6Bxov1lhHYmAUG1cbl35yG2c6mpZl9WdysjIHaJ7a88"
                    }
                  }
                ],
                "authentication": [
                  format!("{}#0", did)
                ],
                "assertionMethod": [
                  format!("{}#0", did)
                ],
                "capabilityDelegation": [
                  format!("{}#0", did)
                ],
                "capabilityInvocation": [
                  format!("{}#0", did)
                ],
                "keyAgreement": [
                  format!("{}#0", did)
                ]
            })
        );
    }

    #[test(tokio::test)]
    async fn resolves_did_jwk_es256() {
        let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let document = resolve_did_jwk(CoreDID::parse(did).unwrap()).await.unwrap();

        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
                "@context": [
                  "https://www.w3.org/ns/did/v1",
                  "https://w3id.org/security/suites/jws-2020/v1"
                ],
                "id": did,
                "verificationMethod": [
                  {
                    "id": format!("{}#0", did),
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                      "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
                    }
                  }
                ],
                "authentication": [
                  format!("{}#0", did)
                ],
                "assertionMethod": [
                  format!("{}#0", did)
                ],
                "capabilityDelegation": [
                  format!("{}#0", did)
                ],
                "capabilityInvocation": [
                  format!("{}#0", did)
                ],
                "keyAgreement": [
                  format!("{}#0", did)
                ]
            })
        );
    }
}
