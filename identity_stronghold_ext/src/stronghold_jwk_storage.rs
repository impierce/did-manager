// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Wrapper around [`StrongholdSecretManager`](StrongholdSecretManager).

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
// use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::Curve;
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
use identity_verification::jwk::JwkType;
use identity_verification::jws::JwsAlgorithm;
use identity_verification::jwu;
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::Password;
use iota_stronghold::procedures::Ed25519Sign;
use iota_stronghold::procedures::GenerateKey;
use iota_stronghold::procedures::KeyType as ProceduresKeyType;
use iota_stronghold::procedures::StrongholdProcedure;
use iota_stronghold::Client;
use iota_stronghold::ClientError;
use iota_stronghold::KeyProvider;
use iota_stronghold::SnapshotPath;
use iota_stronghold::Stronghold;
use iota_stronghold::{
    procedures::{FatalProcedureError, GenerateSecret, ProcedureOutput, Products, UseSecret},
    Location,
};
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;
use rand::distributions::DistString;
use serde::Serialize;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use stronghold_ext::execute_procedure_ext;
use stronghold_ext::procs::es256::Es256Procs;
use stronghold_ext::{
    ext_procs, generic_procedures, AlgoSignature, Algorithm, Es256, ProcedureExt, SigningKey, VerifyingKey,
};
use tokio::sync::{Mutex, MutexGuard};

use identity_iota::core::Object;
use identity_iota::verification::VerificationMethod;
use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument};
use serde_json::json;
use ssi_dids::{DIDMethod, Source};
use std::io::Error;
use std::io::ErrorKind;

// const ED25519_KEY_TYPE_STR: &str = "Ed25519";
static IDENTITY_VAULT_PATH: &str = "iota_identity_vault";
pub(crate) static IDENTITY_CLIENT_PATH: &[u8] = b"iota_identity_client";

/// The Ed25519 key type.
// pub const ED25519_KEY_TYPE: &KeyType = &KeyType::from_static_str(ED25519_KEY_TYPE_STR);

const STRONGHOLD: &str = "../res/multi-key-stronghold.bin";
// static STRONGHOLD_VAULT_PATH: &str = "iota_identity_vault";
// static STRONGHOLD_CLIENT_PATH: &[u8] = b"iota_identity_client";

fn base64_url_encode<T>(value: &T) -> anyhow::Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?.as_slice()))
}

#[test]
fn temp() {
    let test_string = "74ccd8a62fba0e667c50929a53f78c21b8ff0c3c737b0b40b1750b2302b0bde8";

    let hex = hex::decode(&test_string).unwrap();
    let base64_url = URL_SAFE_NO_PAD.decode(&test_string).unwrap();

    println!("hex: {:#?}", hex);
    println!("base64_url: {:#?}", base64_url);
}

#[tokio::test]
async fn test() {
    engine::snapshot::try_set_encrypt_work_factor(0).unwrap();
    let stronghold = Stronghold::default();

    let client = get_client(&stronghold).unwrap();

    let key_id = KeyId::new("key-1");

    println!("HER4");
    let location = Location::generic(
        IDENTITY_VAULT_PATH.as_bytes().to_vec(),
        key_id.to_string().as_bytes().to_vec(),
    );

    let gen_key = Es256Procs::GenerateKey(stronghold_ext::procs::es256::GenerateKey {
        output: location.clone(),
    });

    // create es256 secret key and put it into the stronghold vault.
    let _ = execute_procedure_ext(&client, gen_key).unwrap();

    println!("HER1");
    let stronghold_storage = StrongholdExtStorage::new(stronghold);

    println!("HER12");
    let public_key_jwk = stronghold_storage.get_public_key(&key_id).await.unwrap();

    println!("HER13");

    println!("{:?}", public_key_jwk);

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&public_key_jwk.try_ec_params().unwrap().x)
        .unwrap();
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&public_key_jwk.try_ec_params().unwrap().y)
        .unwrap();

    let encoded_point = p256::EncodedPoint::from_affine_coordinates(
        &p256::FieldBytes::from_slice(&x_bytes),
        &p256::FieldBytes::from_slice(&y_bytes),
        false, // false for uncompressed point
    );

    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
        .expect("Failed to create verifying key from encoded point");

    // Print the public key in its compressed form
    let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    println!("pk bytes: {:?}", public_key.len());

    let payload = json!({
      "client_id": "did:jwk:eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiaFRYTlZHSVlrQUp4c2RJNEw5c3pOV1VWVy1acnhQcmxWZUVHYUd0UmdmTSIsImt0eSI6IkVDIiwieCI6InNMUHExbWQzM3Zsal9sQVVmT29KaHZ1TDdWekRVLW91aWMzeWE2M2RDWVUiLCJ5IjoiIn0",
      "redirect_uri": "http://127.0.0.1:41849/redirect_uri",
      "response_type": "id_token",
      "scope": "openid phone",
      "response_mode": "direct_post",
      "nonce": "n-0S6_WzA2Mj",
      "client_metadata": {
        "subject_syntax_types_supported": [
          "did:test"
        ]
      }
    });

    let kid = "did:jwk:eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiaFRYTlZHSVlrQUp4c2RJNEw5c3pOV1VWVy1acnhQcmxWZUVHYUd0UmdmTSIsImt0eSI6IkVDIiwieCI6InNMUHExbWQzM3Zsal9sQVVmT29KaHZ1TDdWekRVLW91aWMzeWE2M2RDWVUiLCJ5IjoiIn0#0";
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid.to_string());

    let message = [
        base64_url_encode(&header).unwrap(),
        base64_url_encode(&payload).unwrap(),
    ]
    .join(".");

    let proof_value = stronghold_storage
        .sign(&key_id, message.as_bytes(), &public_key_jwk)
        .await
        .unwrap();

    let signature = URL_SAFE_NO_PAD.encode(proof_value.as_slice());

    let message = [message, signature].join(".");

    //////////////////////////////////////////

    let key = DecodingKey::from_ec_der(public_key.as_slice());

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let result = jsonwebtoken::decode::<serde_json::Value>(&message, &key, &validation)
        .unwrap()
        .claims;

    println!("res: {}", result);
}

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
    pub async fn get_public_key(&self, key_id: &KeyId) -> KeyStorageResult<Jwk> {
        engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

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

        let params: JwkParamsEc = serde_json::from_value(json!(jwk_ec_key)).unwrap();

        let mut jwk: Jwk = Jwk::from_params(params);
        jwk.set_alg(JwsAlgorithm::ES256.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());

        // stronghold
        //     .write_client(IDENTITY_CLIENT_PATH)
        //     .expect("store client state into snapshot state failed");

        // let key_provider =
        //     KeyProvider::with_passphrase_hashed_blake2b("sup3rSecr3t".as_bytes().to_vec()).expect("failed to load key");

        // let snapshot_path = SnapshotPath::from_path(STRONGHOLD);

        // stronghold
        //     .commit_with_keyprovider(&snapshot_path, &key_provider)
        //     .expect("stronghold could not commit");

        Ok(jwk)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkStorage for StrongholdExtStorage {
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput> {
        unimplemented!("generate key not implemented");

        // let stronghold = self.get_stronghold().await;

        // let client = get_client(&stronghold)?;
        // let key_type = StrongholdKeyType::try_from(&key_type)?;
        // check_key_alg_compatibility(key_type, alg)?;

        // let keytype: ProceduresKeyType = match key_type {
        //     StrongholdKeyType::Ed25519 => ProceduresKeyType::Ed25519,
        // };

        // let key_id: KeyId = random_key_id();
        // let location = Location::generic(
        //     IDENTITY_VAULT_PATH.as_bytes().to_vec(),
        //     key_id.to_string().as_bytes().to_vec(),
        // );

        // let generate_key_procedure = GenerateKey {
        //     ty: keytype.clone(),
        //     output: location.clone(),
        // };

        // client
        //     .execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure))
        //     .map_err(|err| {
        //         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //             .with_custom_message("stronghold generate key procedure failed")
        //             .with_source(err)
        //     })?;

        // let public_key_procedure = iota_stronghold::procedures::PublicKey {
        //     ty: keytype,
        //     private_key: location,
        // };

        // let procedure_result = client
        //     .execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure))
        //     .map_err(|err| {
        //         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //             .with_custom_message("stronghold public key procedure failed")
        //             .with_source(err)
        //     })?;
        // persist_changes(self, stronghold).await?;
        // let public_key: Vec<u8> = procedure_result.into();

        // let mut params = JwkParamsOkp::new();
        // params.x = jwu::encode_b64(public_key);
        // params.crv = EdCurve::Ed25519.name().to_string();
        // let mut jwk: Jwk = Jwk::from_params(params);
        // jwk.set_alg(alg.name());
        // jwk.set_kid(jwk.thumbprint_sha256_b64());

        // Ok(JwkGenOutput::new(key_id, jwk))
    }

    async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId> {
        unimplemented!("insert key not implemented");

        // let key_type: StrongholdKeyType = StrongholdKeyType::try_from(&jwk)?;
        // if !jwk.is_private() {
        //     return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //         .with_custom_message("expected a Jwk with all private key components set"));
        // }

        // match jwk.alg() {
        //     Some(alg) => {
        //         let alg: JwsAlgorithm = JwsAlgorithm::from_str(alg).map_err(|err| {
        //             KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm).with_source(err)
        //         })?;
        //         check_key_alg_compatibility(key_type, alg)?;
        //     }
        //     None => {
        //         return Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm)
        //             .with_custom_message("expected a Jwk with an `alg` parameter"));
        //     }
        // }
        // let secret_key = ed25519::expand_secret_jwk(&jwk)?;
        // let key_id: KeyId = random_key_id();

        // let location = Location::generic(
        //     IDENTITY_VAULT_PATH.as_bytes().to_vec(),
        //     key_id.to_string().as_bytes().to_vec(),
        // );
        // let stronghold = self.get_stronghold().await;
        // let client = get_client(&stronghold)?;
        // client
        //     .vault(IDENTITY_VAULT_PATH.as_bytes())
        //     .write_secret(location, zeroize::Zeroizing::from(secret_key.to_bytes().to_vec()))
        //     .map_err(|err| {
        //         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //             .with_custom_message("stronghold write secret failed")
        //             .with_source(err)
        //     })?;
        // persist_changes(self, stronghold).await?;

        // Ok(key_id)
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

    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()> {
        unimplemented!("delete key not implemented");

        // let stronghold = self.get_stronghold().await;
        // let client = get_client(&stronghold)?;
        // let deleted = client
        //     .vault(IDENTITY_VAULT_PATH.as_bytes())
        //     .delete_secret(key_id.to_string().as_bytes())
        //     .map_err(|err| {
        //         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
        //             .with_custom_message("stronghold client error")
        //             .with_source(err)
        //     })?;

        // if !deleted {
        //     return Err(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound));
        // }
        // persist_changes(self, stronghold).await?;

        // Ok(())
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

// /// Generate a random alphanumeric string of len 32.
// fn random_key_id() -> KeyId {
//     KeyId::new(rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32))
// }

// /// Check that the key type can be used with the algorithm.
// fn check_key_alg_compatibility(key_type: StrongholdKeyType, alg: JwsAlgorithm) -> KeyStorageResult<()> {
//     match (key_type, alg) {
//         (StrongholdKeyType::Ed25519, JwsAlgorithm::EdDSA) => Ok(()),
//         (key_type, alg) => Err(
//             KeyStorageError::new(identity_storage::KeyStorageErrorKind::KeyAlgorithmMismatch)
//                 .with_custom_message(format!("cannot use key type `{key_type}` with algorithm `{alg}`")),
//         ),
//     }
// }

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

// async fn persist_changes(
//     secret_manager: &StrongholdExtStorage,
//     stronghold: MutexGuard<'_, Stronghold>,
// ) -> KeyStorageResult<()> {
//     stronghold.write_client(IDENTITY_CLIENT_PATH).map_err(|err| {
//         KeyStorageError::new(KeyStorageErrorKind::Unspecified)
//             .with_custom_message("stronghold write client error")
//             .with_source(err)
//     })?;
//     // Must be dropped since `write_stronghold_snapshot` needs to acquire the stronghold lock.
//     drop(stronghold);

//     match secret_manager.as_secret_manager() {
//         iota_sdk::client::secret::SecretManager::Stronghold(stronghold_manager) => {
//             stronghold_manager
//                 .write_stronghold_snapshot(None)
//                 .await
//                 .map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::Unspecified)
//                         .with_custom_message("writing to stronghold snapshot failed")
//                         .with_source(err)
//                 })?;
//         }
//         _ => {
//             return Err(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
//                 .with_custom_message("secret manager is not of type stronghold"))
//         }
//     };
//     Ok(())
// }

// /// Key Types supported by the stronghold storage implementation.
// #[derive(Debug, Copy, Clone)]
// enum StrongholdKeyType {
//     Ed25519,
// }

// impl StrongholdKeyType {
//     /// String representation of the key type.
//     const fn name(&self) -> &'static str {
//         match self {
//             StrongholdKeyType::Ed25519 => "Ed25519",
//         }
//     }
// }

// impl Display for StrongholdKeyType {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.write_str(self.name())
//     }
// }

// impl TryFrom<&KeyType> for StrongholdKeyType {
//     type Error = KeyStorageError;

//     fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
//         match value.as_str() {
//             ED25519_KEY_TYPE_STR => Ok(StrongholdKeyType::Ed25519),
//             _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)),
//         }
//     }
// }

// impl TryFrom<&Jwk> for StrongholdKeyType {
//     type Error = KeyStorageError;

//     fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
//         match jwk.kty() {
//             JwkType::Okp => {
//                 let okp_params = jwk.try_okp_params().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("expected Okp parameters for a JWK with `kty` Okp")
//                         .with_source(err)
//                 })?;
//                 match okp_params.try_ed_curve().map_err(|err| {
//                     KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message("only Ed curves are supported for signing")
//                         .with_source(err)
//                 })? {
//                     EdCurve::Ed25519 => Ok(StrongholdKeyType::Ed25519),
//                     curve => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                         .with_custom_message(format!("{curve} not supported"))),
//                 }
//             }
//             other => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType)
//                 .with_custom_message(format!("Jwk `kty` {other} not supported"))),
//         }
//     }
// }
