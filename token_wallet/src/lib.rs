use iota_sdk::client::node_api::indexer::query_parameters::QueryParameter;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::{
    client::{api::GetAddressesOptions, secret::SecretManager, Client},
    crypto::keys::bip39,
    types::block::address::Bech32Address,
};
use log::info;
use std::str::FromStr;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

/// Returns the first address derived from the underlying Stronghold snapshot.
pub async fn get_first_address(secret_manager: &SecretManager) -> anyhow::Result<Bech32Address> {
    create_and_store_mnemonic(secret_manager).await?;

    // TODO: make dynamic
    let bech32_hrp = Hrp::from_str("rms").unwrap();

    let address = secret_manager
        .generate_ed25519_addresses(
            GetAddressesOptions::default()
                .with_range(0..1)
                .with_bech32_hrp(bech32_hrp),
        )
        .await?[0];

    info!("Address: {}", address.to_string());

    Ok(address)
}

// TODO: Should mnemonic be created and stored already on creation?
async fn create_and_store_mnemonic(secret_manager: &SecretManager) -> anyhow::Result<()> {
    let random: [u8; 32] = rand::random();

    let mnemonic = bip39::wordlist::encode(random.as_ref(), &bip39::wordlist::ENGLISH)
        .map_err(|err| anyhow::anyhow!(format!("{err:?}")))?;

    if let SecretManager::Stronghold(ref stronghold) = secret_manager {
        match stronghold.store_mnemonic(mnemonic).await {
            Ok(()) => (),
            Err(iota_sdk::client::stronghold::Error::MnemonicAlreadyStored) => {
                info!("Stronghold already contains a mnemonic")
            }
            Err(err) => anyhow::bail!(err),
        }
    } else {
        anyhow::bail!("expected a `StrongholdSecretManager`");
    }

    Ok(())
}

pub async fn get_balance(address: &Bech32Address) -> anyhow::Result<u64> {
    let client = match address.hrp().to_string().as_str() {
        "rms" => Client::builder().with_primary_node(TESTNET_URL, None)?.finish().await?,
        "smr" => Client::builder().with_primary_node(SHIMMER_URL, None)?.finish().await?,
        "iota" => Client::builder().with_primary_node(MAINNET_URL, None)?.finish().await?,
        _ => unimplemented!(),
    };

    let output_ids = client
        .basic_output_ids(vec![
            QueryParameter::Address(address.to_owned()),
            QueryParameter::HasExpiration(false),
            QueryParameter::HasTimelock(false),
            QueryParameter::HasStorageDepositReturn(false),
        ])
        .await?;

    let outputs = client.get_outputs(&output_ids).await?;

    let mut total_amount = 0;
    for output_response in outputs {
        total_amount += output_response.output().amount();
    }

    info!("Balance address=[{}]: {}", address.to_string(), total_amount);

    Ok(total_amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use std::str::FromStr;
    use test_log::test;

    #[test(tokio::test)]
    async fn creates_address() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let address = get_first_address(&secret_manager).await.unwrap();

        assert_eq!(
            address.to_string(),
            "rms1qzy8ew7p64tcns9d26ekcch0m0ht33a0w0vrr99hapqeyw38qzk0vct7y2s"
        );
    }

    #[test(tokio::test)]
    async fn gets_balance() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let address = get_first_address(&secret_manager).await.unwrap();

        let balance = get_balance(&address).await.unwrap();

        assert_eq!(balance > 0, true);
    }

    #[test(tokio::test)]
    async fn unsupported_network() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        // valid rms: rms1qzxs8xdk3mskea9kuchc54lrhjaktyfdr3jh4a72smf04397ly6euwas7q6
        // valid smr: smr1qpjva0y6qwjmv42dspw2se2776l5qr0r5p2s5m7nrg73qhvm6a6y7uvqxn6
        // valid iota: iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx

        let address =
            Bech32Address::from_str("iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx").unwrap();

        let balance = get_balance(&address).await.unwrap();

        assert_eq!(balance > 0, true);
    }
}
