use identity_iota::{did::DID as _, document::CoreDocument, iota::IotaDID, resolver::Resolver};

use crate::consumer::get_iota_client;

pub async fn resolve(did: IotaDID) -> Result<CoreDocument, anyhow::Error> {
    let mut resolver = Resolver::<CoreDocument>::new();

    let authority = did.authority();

    let iota_client = get_iota_client(authority, None, None, None)
        .await
        .ok_or_else(|| anyhow::anyhow!("Failed to get IOTA client for authority `{authority}`"))?;

    resolver.attach_iota_handler(iota_client);

    let document = resolver.resolve(&did).await?;
    Ok(document)
}
