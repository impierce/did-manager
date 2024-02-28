use did_jwk::consumer::resolve_did_jwk;
use did_key::consumer::resolve_did_key;
use did_web::consumer::resolve_did_web;
use identity_iota::did::CoreDID;
use identity_iota::document::CoreDocument;
use identity_iota::resolver::Resolver;
use iota_sdk::client::Client;

async fn configure_and_resolve(did: &str) -> std::result::Result<CoreDocument, Box<dyn std::error::Error>> {
    let did = CoreDID::parse(did)?;
    let resolver: Resolver = configure_resolver(Resolver::new()).await;
    let document: CoreDocument = resolver.resolve(&did).await?;
    Ok(document)
}

async fn configure_resolver(mut resolver: Resolver) -> Resolver {
    resolver.attach_handler("jwk".to_owned(), resolve_did_jwk);
    resolver.attach_handler("key".to_owned(), resolve_did_key);
    resolver.attach_handler("web".to_owned(), resolve_did_web);

    // ------------------ IOTA resolver ------------------
    static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
    static SHIMMER_URL: &str = "https://api.shimmer.network";
    static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

    // let client: Client = Client::builder()
    //     .with_primary_node(MAINNET_URL, None)
    //     .unwrap()
    //     .finish()
    //     .await
    //     .unwrap();

    // resolver.attach_iota_handler(client);
    // ---------------------------------------------------
    let iota_client: Client = Client::builder()
        .with_primary_node(MAINNET_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    // ------------------ SHIMMER resolver ------------------
    let smr_client: Client = Client::builder()
        .with_primary_node(SHIMMER_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();
    // let arc_client = std::sync::Arc::new(smr_client);

    // resolver.attach_handler("smr".to_owned(), move |did: CoreDID| {
    //     let future_client = arc_client.clone();
    //     async move { future_client.resolve_did(&did).await }
    // });
    // ---------------------------------------------------

    // ------------------ SHIMMER resolver ------------------
    let shimmer_testnet_client: Client = Client::builder()
        .with_primary_node(TESTNET_URL, None)
        .unwrap()
        .finish()
        .await
        .unwrap();

    resolver.attach_multiple_iota_handlers(vec![
        ("iota", iota_client),
        ("smr", smr_client),
        ("rms", shimmer_testnet_client),
    ]);

    // resolver.attach_iota_handler(shimmer_testnet_client);
    // resolver.attach_iota_handler(smr_client);

    // let arc_client = std::sync::Arc::new(shimmer_testnet_client);

    // println!("client info: {:?}", arc_client.network_name().await.unwrap());

    // resolver.attach_handler("iota".to_owned(), move |did: IotaDID| {
    //     let future_client = arc_client.clone();
    //     async move {
    //         // println!("client network: {:?}", future_client.network_name().await.unwrap());
    //         future_client.resolve_did(&did).await
    //     }
    // });
    // ---------------------------------------------------

    resolver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_all_supported_methods() {
        let did = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
        );

        // add more ...
    }

    #[tokio::test]
    async fn fails_on_unsupported_method() {
        let did = "did:foobar:123456";
        let result = configure_and_resolve(did).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn resolves_did_iota() {
        let did = "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn resolves_did_iota_smr() {
        let did = "did:iota:smr:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:smr:0xe4edef97da1257e83cbeb49159cfdd2da6ac971ac447f233f8439cf29376ebfe"
        );
    }

    #[tokio::test]
    async fn resolves_did_iota_rms() {
        let did = "did:iota:rms:0x4868d61773a9f8e54741261a0e82fc883e299c2614c94b2400e2423d4c5bbe6a";
        let document = configure_and_resolve(did).await.unwrap();

        assert_eq!(
            document.id(),
            "did:iota:rms:0x4868d61773a9f8e54741261a0e82fc883e299c2614c94b2400e2423d4c5bbe6a"
        );
    }
}
