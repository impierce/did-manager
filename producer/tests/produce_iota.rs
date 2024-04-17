use log::info;
use producer::iota::produce::{produce_did_iota, IotaMethod};
use shared::{test_utils::new_stronghold_storage, JwkStorageWrapper};
use test_log::test;

#[test(tokio::test)]
pub async fn produce_and_publish_and_destroy_a_new_iota_testnet_did() {
    let (storage, key_id) = new_stronghold_storage().await;

    let r = produce_did_iota(JwkStorageWrapper::Stronghold(storage), &key_id, IotaMethod::Testnet).await;
    info!("{:?}", r);
}
