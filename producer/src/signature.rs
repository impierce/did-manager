use identity_iota::{storage::JwkStorage, verification::jws::JwsAlgorithm};
use identity_storage::JwkStorage as _;
use shared::error::ProducerError;

use crate::SecretManager;

impl SecretManager {
    pub async fn sign(&self, data: &[u8], jws_algorithm: JwsAlgorithm) -> Result<Vec<u8>, ProducerError> {
        match jws_algorithm {
            JwsAlgorithm::ES256 => {
                let key_id = self
                    .es256_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("es256".to_string()))?;
                let public_key = self
                    .stronghold_ext_storage
                    .get_public_key(key_id)
                    .await
                    .expect("failed to get public key");
                let signature = self
                    .stronghold_ext_storage
                    .sign(key_id, data, &public_key)
                    .await
                    .expect("failed to sign data");
                Ok(signature)
            }
            JwsAlgorithm::EdDSA => {
                let key_id = self
                    .ed25519_key_id
                    .as_ref()
                    .ok_or(ProducerError::MissingKeyIdError("ed25519".to_string()))?;
                let public_key = self
                    .stronghold_storage
                    .get_public_key(key_id)
                    .await
                    .expect("failed to get public key");
                let signature = self
                    .stronghold_storage
                    .sign(key_id, data, &public_key)
                    .await
                    .expect("failed to sign data");
                Ok(signature)
            }
            _ => Err(ProducerError::Generic("Unsupported JWS algorithm".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
    const PASSWORD: &str = "secure_password";
    const KEY_ID: &str = "9O66nzWqYYy1LmmiOudOlh2SMIaUWoTS";

    #[test(tokio::test)]
    async fn produces_the_expected_signature() {
        let secret_manager = SecretManager::load(
            SNAPSHOT_PATH.to_owned(),
            PASSWORD.to_owned(),
            Some(KEY_ID.to_owned()),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let signature = secret_manager.sign("foobar".as_bytes(), JwsAlgorithm::EdDSA).await;

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
