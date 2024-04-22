use base64::{engine::general_purpose::URL_SAFE_NO_PAD, DecodeError, Engine as _};
use futures::executor::block_on;
use identity_iota::did::DID;
use identity_iota::document::DIDUrlQuery;
use identity_iota::verification::jwk::JwkParams;
use oid4vc_core::{Sign, Subject, Verify};
use shared::error::ProducerError;

use crate::did_document::DidMethod;
use crate::SecretManager;

impl Sign for SecretManager {
    fn key_id(&self) -> Option<String> {
        block_on(async {
            self.produce_document(DidMethod::Key)
                .await
                .ok()
                .and_then(|document| document.verification_method().first().cloned())
                .map(|first| first.id().to_string())
        })
    }

    fn sign(&self, message: &str) -> anyhow::Result<Vec<u8>> {
        Ok(block_on(async { self.sign(message.as_bytes()).await })?)
    }

    fn external_signer(&self) -> Option<std::sync::Arc<dyn oid4vc_core::authentication::sign::ExternalSign>> {
        None
    }
}

impl Subject for SecretManager {
    /// Returns the id of the DID document for the default method (`did:key`).
    fn identifier(&self) -> anyhow::Result<String> {
        Ok(block_on(async {
            self.produce_document(DidMethod::Key)
                .await
                .map(|document| document.id().to_string())
        })?)
    }
}

// TODO: this should be `impl Subject for SecretManager`
impl SecretManager {
    /// Returns the id of the DID document for the given method.
    pub fn identifier_for_method(&self, method: &str) -> Result<String, ProducerError> {
        let method: DidMethod = serde_json::from_str(&format!("{:?}", method)).unwrap();
        block_on(async {
            self.produce_document(method)
                .await
                .map(|document| document.id().to_string())
        })
    }
}

// TODO: shouldn't this be in consumer::Resolver? Does it even make sense to have a separate Resolver or should everything be in SecretManager?
#[async_trait::async_trait]
impl Verify for SecretManager {
    async fn public_key(&self, did_url: &str) -> anyhow::Result<Vec<u8>> {
        let did_url = identity_iota::did::DIDUrl::parse(did_url).unwrap();

        let resolver = consumer::resolver::Resolver::new().await;

        let document = resolver.resolve(did_url.did().as_str()).await.unwrap();

        let verification_method = document
            .resolve_method(
                DIDUrlQuery::from(&did_url),
                Some(identity_iota::verification::MethodScope::VerificationMethod),
            )
            .ok_or(ProducerError::Generic(format!(
                "No verification method found for fragment=[{}]",
                did_url.fragment().unwrap()
            )))?;

        // Try decode from `MethodData` directly, else use public JWK params.
        verification_method
            .data()
            .try_decode()
            .or_else(|_| {
                verification_method
                    .data()
                    .public_key_jwk()
                    .and_then(|public_key_jwk| match public_key_jwk.params() {
                        JwkParams::Okp(okp_params) => Some(okp_params.x.as_bytes().to_vec()),
                        JwkParams::Ec(ec_params) => Some(ec_params.x.as_bytes().to_vec()),
                        _ => None,
                    })
                    .ok_or(anyhow::anyhow!("Failed to decode public key for DID URL: {}", did_url))
            })
            .map(|x| URL_SAFE_NO_PAD.decode(x).map_err(|e: DecodeError| anyhow::anyhow!(e)))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_iota::did::{CoreDID, DIDUrl, RelativeDIDUrl};
    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn successfully_finds_an_existing_public_key_in_did_key_by_fragment() {
        let res = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let core_did = CoreDID::parse("did:key:z6MkiieyoLMSVsJAZv7Jje5wWSkDEymUgkyF8kbcrjZpX3qd").unwrap();
        let mut url = RelativeDIDUrl::new();
        url.set_fragment(Some(core_did.method_id())).unwrap();
        let did_url = DIDUrl::new(CoreDID::parse(core_did).unwrap(), Some(url));
        let pub_key = res.public_key(&did_url.to_string()).await.unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&pub_key),
            "P2BkYS6z4UHmsxn6FX1oHsyx7eiUSFEMJ1D_RC8M0-w"
        );
    }

    #[test(tokio::test)]
    async fn successfully_finds_an_existing_public_key_in_did_jwk_by_fragment() {
        let res = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let core_did = CoreDID::parse("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9").unwrap();
        let mut url = RelativeDIDUrl::new();
        url.set_fragment(Some("#0")).unwrap();
        let did_url = DIDUrl::new(CoreDID::parse(core_did).unwrap(), Some(url));
        let pub_key = res.public_key(&did_url.to_string()).await.unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&pub_key),
            "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0"
        );
    }

    #[test(tokio::test)]
    async fn throws_error_when_no_public_key_found_in_document_for_fragment() {
        let res = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();
        let core_did = CoreDID::parse("did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9").unwrap();
        let mut url = RelativeDIDUrl::new();
        url.set_fragment(Some("#foobar")).unwrap();
        let did_url = DIDUrl::new(CoreDID::parse(core_did).unwrap(), Some(url));
        assert!(res.public_key(&did_url.to_string()).await.is_err());
    }
}
