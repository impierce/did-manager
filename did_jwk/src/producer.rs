use identity_iota::{
    core::{FromJson, ToJson},
    did::CoreDID,
    document::CoreDocument,
    verification::{jwk::Jwk, jws::JwsAlgorithm, VerificationMethod},
};
use log::{debug, info};
use shared::{error::ProducerError, JwkStorageWrapper};
use ssi_dids::{DIDMethod, Source};

// See specification: "Since did:jwk only contains a single key, the DID URL fragment identifier is always a fixed #0 value."
const FRAGMENT: &str = "0";

pub async fn produce_did_jwk(
    storage: JwkStorageWrapper,
    key_id: &str,
    alg: JwsAlgorithm,
) -> Result<CoreDocument, ProducerError> {
    let public_key_jwk = storage.get_public_key(key_id, alg).await?;

    info!("Producing `did:jwk` for key_id `{key_id}` ({alg}) ...");

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.clone()).unwrap();

    if let Some(did_str) = did_jwk_extern::DIDJWK.generate(&Source::Key(&jwk)) {
        info!("DID: `{did_str}`");

        let controller = CoreDID::parse(did_str).unwrap();

        let verification_method = VerificationMethod::new_from_jwk(
            controller.clone(),
            Jwk::from_json_value(public_key_jwk).unwrap(),
            Some(FRAGMENT),
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

    const SNAPSHOT_PATH: &str = "../shared/tests/res/full.stronghold";
    const PASSWORD: &str = "sup3rSecr3t";

    #[test(tokio::test)]
    async fn produces_did_jwk_ed25519() {
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;
        let key_id = "ed25519-0";

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_jwk(storage, key_id, JwsAlgorithm::EdDSA).await.unwrap();

        assert_eq!(
            document
                .verification_method()
                .first()
                .unwrap()
                .data()
                .public_key_jwk()
                .unwrap()
                .alg()
                .unwrap(),
            "EdDSA"
        );

        // Only the resulting `DID` is asserted instead of the entire `DID document` since it is not transferred anyway.
        assert_eq!(document.id(), "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJEN2szeEc1WVF6NjJONGpVRzhvVVNZU0lURVFZLUs5b2RCejNlY0xGSElBIiwia3R5IjoiT0tQIiwieCI6ImZLVFVnUnZ1czRZWGJfeFFNSmhRZVFta2Z1Zk1TX1I1QjhxelZaaDlrNEUifQ");
    }

    #[test(tokio::test)]
    async fn produces_did_jwk_es256() {
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;
        let key_id = "es256-0";

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_jwk(storage, key_id, JwsAlgorithm::ES256).await.unwrap();

        assert_eq!(
            document
                .verification_method()
                .first()
                .unwrap()
                .data()
                .public_key_jwk()
                .unwrap()
                .alg()
                .unwrap(),
            "ES256"
        );

        // Only the resulting `DID` is asserted instead of the entire `DID document` since it is not transferred anyway.
        assert_eq!(document.id(), "did:jwk:eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoicnBYMFExMDdmWkd0NUJnRVVROUVjSl9OQWRMSEczQk5udGlHRjBuRTIxRSIsImt0eSI6IkVDIiwieCI6Img1TnBFb3RqUmxYTWxjcmdxWnEwSEFvZVVMYkt6WHVPVlh5S3M2ZHo0ZEEiLCJ5IjoiR2t3WUdsU0Y1LXVSSlo1cGpKSlhsM2tLamZlWlpMbHNfUEM0bWhEYXZZayJ9");
    }

    #[test(tokio::test)]
    async fn produces_did_jwk_es256k() {
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;
        let key_id = "es256k-0";

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_jwk(storage, key_id, JwsAlgorithm::ES256K).await.unwrap();

        assert_eq!(
            document
                .verification_method()
                .first()
                .unwrap()
                .data()
                .public_key_jwk()
                .unwrap()
                .alg()
                .unwrap(),
            "ES256K"
        );

        // Only the resulting `DID` is asserted instead of the entire `DID document` since it is not transferred anyway.
        assert_eq!(document.id(), "did:jwk:eyJhbGciOiJFUzI1NksiLCJjcnYiOiJzZWNwMjU2azEiLCJraWQiOiJkY0NlWWxnR1RHRkh0bEJIcXVyRXN6LUlBUk1ZOG8wbG5BOTNCLVZaSktBIiwia3R5IjoiRUMiLCJ4IjoiNWlTNEZTV0tJLTB0NC1RNDZJY0dObTR1NHpJR0xRMjZkZzI5TzhkZXhzdyIsInkiOiI1elhBeDFRWENzUDhjbm40VEhXMndTYmtwOE9xYnlBdmNETzIyWTN0UnNZIn0");
    }
}
