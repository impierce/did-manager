use identity_iota::{
    core::{FromJson, ToJson},
    document::CoreDocument,
    iota::IotaDID,
    verification::{jwk::Jwk, jws::JwsAlgorithm},
};
use log::{debug, info};
use shared::{error::ProducerError, JwkStorageWrapper};

use crate::producer::resolve::resolve;

pub enum IotaMethod {
    Testnet,
    Shimmer,
    Mainnet,
}

/// Note: Producing a DID document on an IOTA network involves publishing it to the network.
/// Currently only works for pre-funded, pre-published DID documents (runs a few sanity checks before returning the document).
pub async fn produce_did_iota(
    storage: &JwkStorageWrapper,
    key_id: &str,
    iota_method: IotaMethod,
    alg: JwsAlgorithm,
    managed_did: IotaDID,     // TODO(selv): see README.md
    managed_fragment: String, // TODO(selv): see README.md
) -> Result<CoreDocument, ProducerError> {
    let public_key_jwk = storage.get_public_key(key_id, alg).await?;

    let _ = match iota_method {
        IotaMethod::Testnet => {
            info!("Producing `did:iota:rms` for key_id `{key_id}` ({alg}) ...");
        }
        IotaMethod::Shimmer => {
            info!("Producing `did:iota:smr` for key_id `{key_id}` ({alg}) ...");
        }
        IotaMethod::Mainnet => {
            info!("Producing `did:iota` for key_id `{key_id}` ({alg}) ...");
        }
    };

    // Sanity check: Can the document be resolved from the ledger?
    let published_document = resolve(managed_did)
        .await
        .map_err(|e| ProducerError::Generic(e.to_string()))?;

    // Sanity check: Is the method in the document?
    let verification_method = published_document.resolve_method(&managed_fragment, None).unwrap();

    // Sanity check: Do the public keys match?
    assert_eq!(
        Jwk::from_json_value(public_key_jwk).unwrap(),
        verification_method.data().public_key_jwk().unwrap().clone()
    );

    info!("DID: `{:?}`", published_document.id());

    debug!("DID Document: {}", published_document.to_json_pretty().unwrap());

    Ok(published_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use identity_stronghold::StrongholdStorage;
    use iota_sdk_legacy::client::{secret::stronghold::StrongholdSecretManager, Password};
    use serde_json::json;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "../shared/tests/res/selv.stronghold";
    const PASSWORD: &str = "VNvRtH4tKyWwvJDpL6Vuc2aoLiKAecGQ";
    const KEY_ID: &str = "UVDxWhG2rB39FkaR7I27mHeUNrGtUgcr";

    #[test(tokio::test)]
    async fn produce_did_iota_testnet() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        const IOTA_DID: &str = "did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90";
        const FRAGMENT: &str = "bQKQRzaop7CgEvqVq8UlgLGsdF-R-hnLFkKFZqW2VN0";

        let document = produce_did_iota(
            &storage,
            KEY_ID,
            IotaMethod::Testnet,
            JwsAlgorithm::EdDSA,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(
            document.id(),
            "did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90"
        );

        // Expect public key of first verification method
        assert_eq!(
            document.to_json_value().unwrap(),
            json!({
                "id": "did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90",
                "verificationMethod": [
                  {
                    "id": "did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90#bQKQRzaop7CgEvqVq8UlgLGsdF-R-hnLFkKFZqW2VN0",
                    "controller": "did:iota:rms:0x42ad588322e58b3c07aa39e4948d021ee17ecb5747915e9e1f35f028d7ecaf90",
                    "type": "JsonWebKey",
                    "publicKeyJwk": {
                      "kty": "OKP",
                      "alg": "EdDSA",
                      "kid": "bQKQRzaop7CgEvqVq8UlgLGsdF-R-hnLFkKFZqW2VN0",
                      "crv": "Ed25519",
                      "x": "GlnK9ePs802XxAglROQzoGurm9Qpv0IFPEbdMCILN_U"
                    }
                  }
                ]
            })
        );
    }

    #[ignore]
    #[test(tokio::test)]
    async fn produce_did_iota_shimmer() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        const IOTA_DID: &str = "did:iota:smr:0x_";
        const FRAGMENT: &str = "_";

        let document = produce_did_iota(
            &storage,
            KEY_ID,
            IotaMethod::Shimmer,
            JwsAlgorithm::EdDSA,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(document.id(), "did:iota:smr:0x_");
    }

    #[ignore]
    #[test(tokio::test)]
    async fn produce_did_iota_mainnet() {
        let stronghold_adapter = StrongholdSecretManager::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH.to_owned())
            .unwrap();

        let storage = JwkStorageWrapper::Stronghold(StrongholdStorage::new(stronghold_adapter));

        const IOTA_DID: &str = "did:iota:0x_";
        const FRAGMENT: &str = "_";

        let document = produce_did_iota(
            &storage,
            KEY_ID,
            IotaMethod::Mainnet,
            JwsAlgorithm::EdDSA,
            IotaDID::parse(IOTA_DID).unwrap(),
            FRAGMENT.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(document.id(), "did:iota:0x_");
    }
}
