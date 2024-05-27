use did_jwk_extern::DIDJWK;
use identity_iota::core::{FromJson, ToJson};
use identity_iota::did::{CoreDID, DID};
use identity_iota::document::CoreDocument;
use log::{debug, info};
use shared::error::ConsumerError;
use ssi_dids::did_resolve::dereference;

pub async fn resolve_did_jwk(did: CoreDID) -> Result<CoreDocument, ConsumerError> {
    info!("Resolving DID: `{did}`");
    let (_, document, _) = dereference(&DIDJWK, did.as_str(), &Default::default()).await;
    debug!("{}", document.to_json_pretty().unwrap());
    CoreDocument::from_json(&document.to_json().unwrap()).map_err(|e| ConsumerError::Generic(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use test_log::test;

    #[test(tokio::test)]
    async fn resolves_did_jwk_ed25519() {
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
        // Test vector from https://github.com/quartzjer/did-jwk/blob/main/spec.md#p-256
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
                      "crv": "P-256",
                      "kty": "EC",
                      "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                      "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
                    }
                  }
                ],
                "assertionMethod": [format!("{}#0", did)],
                "authentication": [format!("{}#0", did)],
                "capabilityInvocation": [format!("{}#0", did)],
                "capabilityDelegation": [format!("{}#0", did)],
                "keyAgreement": [format!("{}#0", did)]
            })
        );
    }

    #[test(tokio::test)]
    async fn resolves_did_jwk_es256k() {
        // Test vector from https://github.com/iotaledger/identity.rs/tree/main/identity_ecdsa_verifier
        let did = "did:jwk:eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJCQm9iYlpraUM4RTRDNEVZZWtQTkprY1hGQ3NNTkhoaDBBVjJVU3lfeFNzIiwieSI6IlZRY1BIaklRQ2xYMGI1VExsdUZsNmpwSWY5VS1ub3JXQzBvRXZJUVJOeVUifQ";
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
                      "crv": "secp256k1",
                      "kty": "EC",
                      "x": "BBobbZkiC8E4C4EYekPNJkcXFCsMNHhh0AV2USy_xSs",
                      "y": "VQcPHjIQClX0b5TLluFl6jpIf9U-norWC0oEvIQRNyU"
                    }
                  }
                ],
                "assertionMethod": [format!("{}#0", did)],
                "authentication": [format!("{}#0", did)],
                "capabilityInvocation": [format!("{}#0", did)],
                "capabilityDelegation": [format!("{}#0", did)],
                "keyAgreement": [format!("{}#0", did)]
            })
        );
    }
}
