use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use futures::executor::block_on;
use identity_iota::did::{DIDUrl, DID};
use identity_iota::resolver::{self, Resolver};
use oid4vc_core::{Sign, Subject, Verify};

use crate::did_document::Method;
use crate::SecretManager;

impl Sign for SecretManager {
    fn key_id(&self) -> Option<String> {
        block_on(async {
            self.produce_document(Method::Key)
                .await
                .ok()
                .and_then(|document| document.verification_method().first().cloned())
                .map(|first| first.id().to_string())
        })
    }

    fn sign(&self, message: &str) -> anyhow::Result<Vec<u8>> {
        block_on(async { self.sign(message.as_bytes()).await })
    }

    fn external_signer(&self) -> Option<std::sync::Arc<dyn oid4vc_core::authentication::sign::ExternalSign>> {
        None
    }
}

impl Subject for SecretManager {
    fn identifier(&self) -> anyhow::Result<String> {
        block_on(async {
            self.produce_document(Method::Key)
                .await
                .map(|document| document.id().to_string())
                .map_err(|e| anyhow::anyhow!(e))
        })
    }
}

#[async_trait::async_trait]
impl Verify for SecretManager {
    async fn public_key(&self, kid: &str) -> anyhow::Result<Vec<u8>> {
        let mut resolver: Resolver = resolver::Resolver::new();

        let did_url: DIDUrl = kid.parse()?;
        let did = did_url.did();

        // Attach the appropriate handler for the given DID method.
        match did.method() {
            "jwk" => resolver.attach_handler(did.method().to_string(), resolve_did_jwk),
            "key" => resolver.attach_handler(did.method().to_string(), resolve_did_key),
            "web" => resolver.attach_handler(did.method().to_string(), resolve_did_web),
            _ => unimplemented!(),
        }

        let document = resolver.resolve(did).await?;

        // Resolve the method data from the given `kid`.
        let method_data = document
            .resolve_method(kid, None)
            .ok_or(anyhow::anyhow!("Verification method not found for DID URL: {}", kid))?
            .data();

        method_data
            // Try decoding the public key from base encoded method data.
            .try_decode()
            .ok()
            .or_else(|| {
                // Or else try decoding the public key from a JWK.
                method_data.public_key_jwk().and_then(|public_key| {
                    public_key
                        .try_okp_params()
                        .map(|okp_params| okp_params.x.as_bytes().to_vec())
                        .ok()
                })
            })
            .ok_or(anyhow::anyhow!("Failed to decode public key for DID URL: {}", kid))
    }
}
