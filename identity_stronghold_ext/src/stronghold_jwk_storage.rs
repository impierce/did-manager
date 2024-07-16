use async_trait::async_trait;
use identity_storage::key_storage::JwkStorage;
use identity_storage::JwkGenOutput;
use identity_storage::KeyId;
use identity_storage::KeyStorageError;
use identity_storage::KeyStorageErrorKind;
use identity_storage::KeyStorageResult;
use identity_storage::KeyType;
use identity_verification::jwk::EcCurve;
use identity_verification::jwk::EdCurve;
use identity_verification::jwk::Jwk;
use identity_verification::jwk::JwkParamsEc;
use identity_verification::jwk::JwkParamsOkp;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_stronghold::procedures::GenerateKey;
use iota_stronghold::procedures::KeyType as ProceduresKeyType;
use iota_stronghold::procedures::PublicKey;
use iota_stronghold::procedures::StrongholdProcedure;
use iota_stronghold::Location;
use iota_stronghold::Stronghold;
use log::info;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use stronghold_ext::execute_procedure_ext;
use stronghold_ext::procs::es256::{self, Es256Procs};
use stronghold_ext::procs::es256k::{self, Es256kProcs};
use tokio::sync::MutexGuard;

use crate::utils::{get_client, persist_changes};

static IDENTITY_VAULT_PATH: &str = "iota_identity_vault";

/// Wrapper around a [`StrongholdSecretManager`] that implements the [`KeyIdStorage`](crate::KeyIdStorage)
/// and [`JwkStorage`](crate::JwkStorage) interfaces.
#[derive(Clone, Debug)]
pub struct StrongholdExtStorage(Arc<SecretManager>);

impl StrongholdExtStorage {
    /// Creates a new [`StrongholdStorage`].
    pub fn new(stronghold_secret_manager: StrongholdSecretManager) -> Self {
        Self(Arc::new(SecretManager::Stronghold(stronghold_secret_manager)))
    }

    /// Shared reference to the inner [`SecretManager`].
    pub fn as_secret_manager(&self) -> &SecretManager {
        self.0.as_ref()
    }

    /// Acquire lock of the inner [`Stronghold`].
    pub(crate) async fn get_stronghold(&self) -> MutexGuard<'_, Stronghold> {
        match *self.0 {
            SecretManager::Stronghold(ref stronghold) => stronghold.inner().await,
            _ => unreachable!("secret manager can be only constructed from stronghold"),
        }
    }

    /// Retrieve the public Ed25519 key corresponding to `key_id`.
    pub async fn get_ed25519_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
        let stronghold = self.get_stronghold().await;
        let client = get_client(&stronghold)?;

        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );

        let public_key_procedure = iota_stronghold::procedures::PublicKey {
            ty: ProceduresKeyType::Ed25519,
            private_key: location,
        };

        let procedure_result = client
            .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
            .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_source(err))?;

        let public_key: Vec<u8> = procedure_result.into();

        let mut params = JwkParamsOkp::new();
        params.x = jwu::encode_b64(public_key);
        EdCurve::Ed25519.name().clone_into(&mut params.crv);
        let mut jwk: Jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::EdDSA.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(jwk)
    }

    /// Retrieve the public ES256 key corresponding to `key_id`.
    pub async fn get_es256_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
        let stronghold = self.get_stronghold().await;
        let client = get_client(&stronghold)?;

        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );

        let pub_key = Es256Procs::PublicKey(stronghold_ext::procs::es256::PublicKey {
            private_key: location.clone(),
        });

        let procedure_result = execute_procedure_ext(&client, pub_key).unwrap();

        let public_key: Vec<u8> = procedure_result.into();

        let encoded_point = p256::EncodedPoint::from_bytes(public_key).expect("Invalid encoded point");

        let verifying_key =
            p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let encoded_point = p256::EncodedPoint::from_bytes(public_key).expect("Failed to parse compressed public key");

        let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<p256::NistP256>(&encoded_point)
            .expect("Failed to decompress point");

        // TODO: use better solution for converting to `JwkParamsEc`.
        let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

        let mut jwk: Jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::ES256.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(jwk)
    }

    /// Retrieve the public ES256K key corresponding to `key_id`.
    pub async fn get_es256k_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
        let stronghold = self.get_stronghold().await;
        let client = get_client(&stronghold)?;

        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );

        let pub_key = Es256kProcs::PublicKey(stronghold_ext::procs::es256k::PublicKey {
            private_key: location.clone(),
        });

        let procedure_result = execute_procedure_ext(&client, pub_key).unwrap();

        let public_key: Vec<u8> = procedure_result.into();

        let encoded_point = k256::EncodedPoint::from_bytes(public_key).expect("Invalid encoded point");

        let verifying_key =
            k256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let encoded_point = k256::EncodedPoint::from_bytes(public_key).expect("Failed to parse compressed public key");

        let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<k256::Secp256k1>(&encoded_point)
            .expect("Failed to decompress point");

        // TODO: use better solution for converting to `JwkParamsEc`.
        let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

        let mut jwk: Jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::ES256K.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(jwk)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for StrongholdExtStorage {
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
        let stronghold = self.get_stronghold().await;

        let client = get_client(&stronghold)?;

        let keytype: ExtProceduresKeyType = ExtProceduresKeyType::try_from(&key_type)?;

        let key_id: KeyId = match alg {
            JwsAlgorithm::EdDSA => KeyId::new("ed25519-0"),
            JwsAlgorithm::ES256 => KeyId::new("es256-0"),
            JwsAlgorithm::ES256K => KeyId::new("es256k-0"),
            _ => unimplemented!("Unsupported algorithm"),
        };

        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );

        match keytype {
            ExtProceduresKeyType::Ed25519 => {
                let generate_key_procedure = StrongholdProcedure::GenerateKey(GenerateKey {
                    ty: ProceduresKeyType::Ed25519,
                    output: location.clone(),
                });
                client.execute_procedure(generate_key_procedure).map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message("stronghold GenerateKey procedure failed")
                        .with_source(err)
                })?;
            }
            ExtProceduresKeyType::ES256 => {
                let generate_key_procedure = Es256Procs::GenerateKey(es256::GenerateKey {
                    output: location.clone(),
                });
                execute_procedure_ext(&client, generate_key_procedure).map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message("stronghold GenerateKey procedure failed")
                        .with_source(err)
                })?;
            }
            ExtProceduresKeyType::ES256K => {
                let generate_key_procedure = Es256kProcs::GenerateKey(es256k::GenerateKey {
                    output: location.clone(),
                });
                execute_procedure_ext(&client, generate_key_procedure).map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message("stronghold GenerateKey procedure failed")
                        .with_source(err)
                })?;
            }
        };

        let jwk = match keytype {
            ExtProceduresKeyType::Ed25519 => {
                let public_key_procedure = PublicKey {
                    ty: ProceduresKeyType::Ed25519,
                    private_key: location,
                };
                let public_key: Vec<u8> = client.execute_procedure(public_key_procedure).map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message("stronghold PublicKey procedure failed")
                        .with_source(err)
                })?;

                let mut params = JwkParamsOkp::new();
                params.x = jwu::encode_b64(public_key);
                EdCurve::Ed25519.name().clone_into(&mut params.crv);
                let mut jwk: Jwk = Jwk::from_params(params);
                jwk.set_alg(JwsAlgorithm::EdDSA.name());
                jwk.set_kid(jwk.thumbprint_sha256_b64());
                jwk
            }
            ExtProceduresKeyType::ES256 => {
                let public_key_procedure = Es256Procs::PublicKey(es256::PublicKey {
                    private_key: location.clone(),
                });
                let public_key: Vec<u8> = execute_procedure_ext(&client, public_key_procedure)
                    .map_err(|err| {
                        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                            .with_custom_message("stronghold PublicKey procedure failed")
                            .with_source(err)
                    })?
                    .into();
                let encoded_point = p256::EncodedPoint::from_bytes(public_key).expect("Invalid encoded point");

                let verifying_key =
                    p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

                let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

                let encoded_point =
                    p256::EncodedPoint::from_bytes(public_key).expect("Failed to parse compressed public key");

                let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<p256::NistP256>(&encoded_point)
                    .expect("Failed to decompress point");

                // TODO: use better solution for converting to `JwkParamsEc`.
                let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

                // info!("{:?}", public_key.len());

                // persist_changes(self.as_secret_manager(), stronghold).await?;

                // let mut params = JwkParamsEc::new();
                // params.x = jwu::encode_b64(public_key);
                let mut jwk = Jwk::from_params(params);
                jwk.set_alg(alg.name());
                jwk.set_kid(jwk.thumbprint_sha256_b64());
                jwk
            }
            ExtProceduresKeyType::ES256K => {
                let public_key_procedure = Es256kProcs::PublicKey(es256k::PublicKey {
                    private_key: location.clone(),
                });
                let public_key: Vec<u8> = execute_procedure_ext(&client, public_key_procedure)
                    .map_err(|err| {
                        KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                            .with_custom_message("stronghold PublicKey procedure failed")
                            .with_source(err)
                    })?
                    .into();
                let encoded_point = k256::EncodedPoint::from_bytes(public_key).expect("Invalid encoded point");

                let verifying_key =
                    k256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

                let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

                let encoded_point =
                    k256::EncodedPoint::from_bytes(public_key).expect("Failed to parse compressed public key");

                let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<k256::Secp256k1>(&encoded_point)
                    .expect("Failed to decompress point");

                // TODO: use better solution for converting to `JwkParamsEc`.
                let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

                // info!("{:?}", public_key.len());

                // persist_changes(self.as_secret_manager(), stronghold).await?;

                // let mut params = JwkParamsEc::new();
                // params.x = jwu::encode_b64(public_key);
                let mut jwk = Jwk::from_params(params);
                jwk.set_alg(alg.name());
                jwk.set_kid(jwk.thumbprint_sha256_b64());
                jwk
            }
        };

        // let public_key_procedure = match keytype {
        //     ExtProceduresKeyType::ES256 => Es256Procs::PublicKey(es256::PublicKey {
        //         private_key: location.clone(),
        //     }),
        //     // es256::PublicKey {
        //     // private_key: location.clone(),
        //     _ => unimplemented!("not implemented"),
        // };

        // let public_key: Vec<u8> = execute_procedure_ext(&client, public_key_procedure)
        //     .map_err(|err| {
        //         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //             .with_custom_message("stronghold PublicKey procedure failed")
        //             .with_source(err)
        //     })?
        //     .into();

        // let public_key: Vec<u8> = procedure_result.into();

        // let encoded_point = p256::EncodedPoint::from_bytes(public_key).expect("Invalid encoded point");

        // let verifying_key =
        //     p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

        // let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // let encoded_point = p256::EncodedPoint::from_bytes(public_key).expect("Failed to parse compressed public key");

        // let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<p256::NistP256>(&encoded_point)
        //     .expect("Failed to decompress point");

        // // TODO: use better solution for converting to `JwkParamsEc`.
        // let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

        // // info!("{:?}", public_key.len());

        persist_changes(self.as_secret_manager(), stronghold).await?;

        info!("Changes persisted to Stronghold (key_id: {key_id})");

        // // let mut params = JwkParamsEc::new();
        // // params.x = jwu::encode_b64(public_key);
        // let mut jwk = Jwk::from_params(params);
        // jwk.set_alg(alg.name());
        // jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(JwkGenOutput::new(key_id, jwk))
    }

    // TODO: implement
    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId> {
        unimplemented!("insert key not implemented");
    }

    async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>> {
        // Extract the required alg from the given public key
        let alg = public_key
            .alg()
            .ok_or(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            .and_then(|alg_str| {
                JwsAlgorithm::from_str(alg_str).map_err(|_| KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
            })?;

        // Check that `kty` is `Ec` and `crv = P-256`.
        match alg {
            JwsAlgorithm::ES256 => {
                let ec_params = public_key.try_ec_params().map_err(|err| {
                    KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                        .with_custom_message(format!("expected a Jwk with Ec params in order to sign with {alg}"))
                        .with_source(err)
                })?;
                if ec_params.crv != EcCurve::P256.name() {
                    return Err(
                        KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(format!(
                            "expected Jwk with Ec {} crv in order to sign with {alg}",
                            EcCurve::P256
                        )),
                    );
                }
            }
            other => {
                return Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
                    .with_custom_message(format!("{other} is not supported")));
            }
        };

        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );

        let procedure = Es256Procs::Sign(stronghold_ext::procs::es256::Sign {
            private_key: location,
            msg: data.to_vec(),
        });

        let stronghold = self.get_stronghold().await;
        let client = get_client(&stronghold)?;

        let signature: Vec<u8> = execute_procedure_ext(&client, procedure)
            .map_err(|err| {
                KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                    .with_custom_message("stronghold Es256Procs::Sign procedure failed")
                    .with_source(err)
            })?
            .into();

        Ok(signature)
    }

    // TODO: implement
    async fn delete(&self, _key_id: &KeyId) -> KeyStorageResult<()> {
        unimplemented!("delete key not implemented");
    }

    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool> {
        let stronghold = self.get_stronghold().await;
        let client = get_client(&stronghold)?;
        let location = Location::generic(
            IDENTITY_VAULT_PATH.as_bytes().to_vec(),
            key_id.to_string().as_bytes().to_vec(),
        );
        let exists = client.record_exists(&location).map_err(|err| {
            KeyStorageError::new(KeyStorageErrorKind::Unspecified)
                .with_custom_message("stronghold client error")
                .with_source(err)
        })?;
        Ok(exists)
    }
}

#[derive(Debug, Clone)]
enum ExtProceduresKeyType {
    Ed25519,
    ES256,
    ES256K,
}

impl TryFrom<&KeyType> for ExtProceduresKeyType {
    type Error = KeyStorageError;

    fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
        match value.as_str() {
            "Ed25519" => Ok(ExtProceduresKeyType::Ed25519),
            "ES256" => Ok(ExtProceduresKeyType::ES256),
            "ES256K" => Ok(ExtProceduresKeyType::ES256K),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)),
        }
    }
}
