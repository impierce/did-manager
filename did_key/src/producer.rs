use identity_iota::{
    core::{FromJson, ToJson},
    did::{CoreDID, DID},
    document::CoreDocument,
    verification::{jwk::Jwk, jws::JwsAlgorithm, VerificationMethod},
};
use log::{debug, info};
use shared::{error::ProducerError, JwkStorageWrapper};
use ssi_dids::{DIDMethod, Source};

pub async fn produce_did_key(
    storage: JwkStorageWrapper,
    key_id: &str,
    alg: JwsAlgorithm,
) -> Result<CoreDocument, ProducerError> {
    // TODO: Check if key exists in key_id_storage, if not return error
    // let exists = storage.key_storage().exists(key_id).await.unwrap();

    // if !exists {
    //     return Err(Error::other(format!("Key with id=[{}] does not exist", key_id)));
    // }

    let public_key_jwk = storage.get_public_key(key_id, alg).await?;

    info!("Producing `did:key` for key_id `{key_id}` ({alg}) ...");

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.clone()).unwrap();

    if let Some(did_str) = did_key_extern::DIDKey.generate(&Source::Key(&jwk)) {
        info!("DID: `{did_str}`");

        let controller = CoreDID::parse(did_str).unwrap();

        let verification_method = VerificationMethod::new_from_jwk(
            controller.clone(),
            Jwk::from_json_value(public_key_jwk).unwrap(),
            Some(controller.method_id()),
        )
        .unwrap();

        let document = CoreDocument::builder(Default::default())
            .id(controller)
            .verification_method(verification_method)
            .build()
            .unwrap();

        debug!("DID Document: {}", document.to_json_pretty().unwrap());

        return Ok(document);
    };
    Err(ProducerError::Generic("Done without result".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::test_utils::existing_stronghold_storage;
    use test_log::test;

    const SNAPSHOT_PATH: &str = "../shared/tests/res/multi.stronghold";
    const PASSWORD: &str = "sup3rSecr3t";

    #[test(tokio::test)]
    async fn produces_did_key_ed25519() {
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;
        let key_id = "key-0";

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_key(storage, key_id, JwsAlgorithm::EdDSA).await.unwrap();

        // Only the resulting `DID` is asserted instead of the entire `DID document` since it is not transferred anyway.
        assert_eq!(
            document.id(),
            "did:key:z6MkvStWVzSLzVnSXfXB2AxgtuStsanmJjSMEyUGy9ZJmWaw"
        );
    }

    #[test(tokio::test)]
    async fn produces_did_key_es256() {
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;
        let key_id = "key-1";

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_key(storage, key_id, JwsAlgorithm::ES256).await.unwrap();

        // Only the resulting `DID` is asserted instead of the entire `DID document` since it is not transferred anyway.
        assert_eq!(
            document.id(),
            "did:key:zDnaebq568DdHEjAY95yngDEEzJvJLPyEmDA8pS8VxVLBB3pp"
        );
    }
}
