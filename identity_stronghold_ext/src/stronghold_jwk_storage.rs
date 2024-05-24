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
use iota_stronghold::procedures::KeyType as ProceduresKeyType;
use iota_stronghold::procedures::StrongholdProcedure;
use iota_stronghold::Client;
use iota_stronghold::ClientError;
use iota_stronghold::Location;
use iota_stronghold::Stronghold;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use stronghold_ext::execute_procedure_ext;
use stronghold_ext::procs::es256::Es256Procs;
use tokio::sync::{Mutex, MutexGuard};

static IDENTITY_VAULT_PATH: &str = "iota_identity_vault";
pub(crate) static IDENTITY_CLIENT_PATH: &[u8] = b"iota_identity_client";

/// Wrapper around a [`StrongholdSecretManager`] that implements the [`KeyIdStorage`](crate::KeyIdStorage)
/// and [`JwkStorage`](crate::JwkStorage) interfaces.
#[derive(Clone, Debug)]
pub struct StrongholdExtStorage(Arc<Mutex<Stronghold>>);

impl StrongholdExtStorage {
    /// Creates a new [`StrongholdStorage`].
    pub fn new(stronghold: Stronghold) -> Self {
        Self(Arc::new(Mutex::new(stronghold)))
    }

    /// Acquire lock of the inner [`Stronghold`].
    pub(crate) async fn get_stronghold(&self) -> MutexGuard<'_, Stronghold> {
        self.0.lock().await
    }

    /// Retrieve the public key corresponding to `key_id`.
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

        let encoded_point = p256::EncodedPoint::from_bytes(&public_key).expect("Invalid encoded point");

        let verifying_key =
            p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point).expect("Failed to decompress point");

        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let encoded_point = p256::EncodedPoint::from_bytes(&public_key).expect("Failed to parse compressed public key");

        let jwk_ec_key = elliptic_curve::JwkEcKey::from_encoded_point::<p256::NistP256>(&encoded_point)
            .expect("Failed to decompress point");

        // TODO: use better solution for converting to `JwkParamsEc`.
        let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

        let mut jwk: Jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::ES256.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        Ok(jwk)
    }

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
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for StrongholdExtStorage {
    async fn generate(&self, _key_type: KeyType, _alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
        unimplemented!("generate key not implemented");
    }

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

pub fn get_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
    let client = stronghold.get_client(IDENTITY_CLIENT_PATH);
    match client {
        Ok(client) => Ok(client),
        Err(ClientError::ClientDataNotPresent) => load_or_create_client(stronghold),
        Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
    }
}

fn load_or_create_client(stronghold: &Stronghold) -> KeyStorageResult<Client> {
    match stronghold.load_client(IDENTITY_CLIENT_PATH) {
        Ok(client) => Ok(client),
        Err(ClientError::ClientDataNotPresent) => stronghold
            .create_client(IDENTITY_CLIENT_PATH)
            .map_err(|err| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
        Err(err) => Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(err)),
    }
}
