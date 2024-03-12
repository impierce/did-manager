use futures::executor::block_on;
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
    async fn public_key(&self, _kid: &str) -> anyhow::Result<Vec<u8>> {
        let x = block_on(async {
            self.stronghold_storage
                .get_public_key(&self.key_id)
                .await
                .unwrap()
                .try_okp_params()
                .unwrap()
                .x
                .clone()
        });
        Ok(base64_url::decode(&x).unwrap())
    }
}
