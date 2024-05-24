use identity_iota::core::FromJson;
use identity_iota::verification::jwk::Jwk;
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::VerificationMethod;
use identity_iota::{core::ToJson, did::CoreDID, document::CoreDocument};
use log::info;
use shared::error::ProducerError;
use shared::JwkStorageWrapper;
use ssi_dids::{DIDMethod, Source};

// See specification: "Since did:jwk only contains a single key, the DID URL fragment identifier is always a fixed #0 value."
const FRAGMENT: &str = "0";

pub async fn produce_did_jwk(
    storage: JwkStorageWrapper,
    key_id: &str,
    alg: JwsAlgorithm,
) -> Result<CoreDocument, ProducerError> {
    let public_key_jwk = storage.get_public_key(key_id, alg).await?;

    info!("Producing did:jwk for key_id=[{:?}] ...", key_id);

    let jwk: ssi_jwk::JWK = serde_json::from_value(public_key_jwk.clone()).unwrap();

    if let Some(did_str) = did_jwk_extern::DIDJWK.generate(&Source::Key(&jwk)) {
        info!("DID: {:?}", did_str);

        let controller = CoreDID::parse(did_str).unwrap();

        let verification_method = VerificationMethod::new_from_jwk(
            controller.clone(),
            Jwk::from_json_value(public_key_jwk).unwrap(),
            Some(FRAGMENT),
        )
        .unwrap();

        let properties = storage.get_properties();

        let document = CoreDocument::builder(properties)
            .id(controller)
            .verification_method(verification_method)
            .build()
            .unwrap();

        info!("DID Document: {}", document.to_json_pretty().unwrap());

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
    async fn produces_did_jwk_ed25519() {
        // let (stronghold_storage, key_id, _) = new_stronghold_storage().await;
        let key_id = "key-0";
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;

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

        assert_eq!(document.id(), "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJmMDJTaFlyYWsyZW56VTJoS2E5Qkt5LXY3SEdLM3NVcDNYbEU0Ym9qY1gwIiwia3R5IjoiT0tQIiwieCI6IjdhS2owdmpNWW9iZ180TWg1TWF0RkhlREZFaWlZdEhfLWdoajkxWF9TTFEifQ");
    }

    #[test(tokio::test)]
    async fn produces_did_jwk_es256() {
        // let (stronghold_storage, key_id, _) = new_stronghold_storage().await;
        let key_id = "key-1";
        let stronghold_storage = existing_stronghold_storage(SNAPSHOT_PATH, PASSWORD).await;

        let storage = JwkStorageWrapper::StrongholdExt(stronghold_storage);
        let document = produce_did_jwk(storage, key_id, JwsAlgorithm::ES256).await.unwrap();

        assert_eq!(document.id(), "did:jwk:eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiMGFIcU54SmViSEJ2MWFlOEhKTUFCekNDTjBmbWFSYmFvcWdmTG5MQ0ZCRSIsImt0eSI6IkVDIiwieCI6InFWdV9aR2xRb1M0c0xPSmdtaFc2N0lzeERRcW05NEtXT1VJNC1RQWsxcTAiLCJ5Ijoid1kydGt6aFlhWnc1bGxaZi1RTkR4MDNPUVZNMUo2X2g5LW1sN2tUVWlVdyJ9");
    }
}
