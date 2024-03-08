use anyhow::Result;
use identity_iota::storage::JwkStorage;

use crate::SecretManager;

impl SecretManager {
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let public_key = self.stronghold_storage.get_public_key(&self.key_id).await.unwrap();
        let signature = self
            .stronghold_storage
            .sign(&self.key_id, data, &public_key)
            .await
            .unwrap();
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[tokio::test]
    async fn produces_the_expected_signature() {
        let secret_manager = SecretManager::load(SNAPSHOT_PATH.to_owned(), PASSWORD.to_owned(), KEY_ID.to_owned())
            .await
            .unwrap();

        let signature = secret_manager.sign("foobar".as_bytes()).await;

        assert!(signature.is_ok());

        assert_eq!(
            hex::encode(signature.unwrap()),
            "6f2a95169514bc2080928d7a1c7c40e3\
             b2629a2e25f9211c6621edc4564dbef0\
             55000dc9ea2498b622cfcc8f9ea00dec\
             e53ede14e1d9991d67dd0ff474e53d03"
        );
    }
}
