use anyhow::Result;
use identity_iota::storage::{JwkStorage, KeyId};

use crate::SecretManager;

impl SecretManager {
    pub async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        // TODO: remove this hard-coded value and replace it with: get_key_id(method_digest)
        let key_id = KeyId::new("9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS");
        let public_key = self.stronghold_storage.get_public_key(&key_id).await.unwrap();
        let signature = self.stronghold_storage.sign(&key_id, data, &public_key).await.unwrap();
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn produces_the_expected_signature() {
        let secret_manager =
            SecretManager::load("tests/res/test.stronghold".to_string(), "secure_password".to_string()).unwrap();

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
