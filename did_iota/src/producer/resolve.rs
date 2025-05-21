use identity_iota::{document::CoreDocument, iota::IotaDID, resolver::Resolver};

use crate::consumer::iota_clients;

pub async fn resolve(did: IotaDID) -> Result<CoreDocument, anyhow::Error> {
    let mut resolver = Resolver::<CoreDocument>::new();
    resolver.attach_multiple_iota_handlers(iota_clients().await.unwrap());
    let document = resolver.resolve(&did).await?;
    Ok(document)
}
