use iota_sdk::client::constants::SHIMMER_COIN_TYPE;
use iota_sdk::client::node_api::indexer::query_parameters::QueryParameter;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::wallet::ClientOptions;
use iota_sdk::Wallet;
use iota_sdk::{
    client::{api::GetAddressesOptions, secret::SecretManager, Client},
    crypto::keys::bip39,
    types::block::address::Bech32Address,
};
use log::{info, warn};
use shared::error::WalletError;
use std::str::FromStr;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

/// Returns the first address derived from the underlying Stronghold snapshot.
pub async fn get_first_address(secret_manager: &SecretManager, network: &str) -> Result<Bech32Address, WalletError> {
    // Note: generating ed25519 addresses fails when no Mnemonic is present in Stronghold?
    create_and_store_mnemonic(secret_manager)
        .await
        .map_err(|e| WalletError::Generic(e.to_string()))?;

    let network = match network {
        "rms" => network,
        _ => return Err(WalletError::Generic("Unsupported network".to_string())),
    };

    // TODO: make dynamic
    let bech32_hrp = Hrp::from_str(network).unwrap();

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

// TODO: Should mnemonic be created and stored already on creation of Stronghold (or even initialized with it)?
/// Helper function for `get_first_address()`
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

/// Send funds back to originating address that exceed the required storage deposit.
pub async fn sync_funds(secret_manager: SecretManager) -> Result<(), WalletError> {
    let client_options = ClientOptions::new().with_node(TESTNET_URL).unwrap();
    let coin_type = SHIMMER_COIN_TYPE;

    let wallet = Wallet::builder()
        .with_secret_manager(secret_manager)
        .with_client_options(client_options)
        .with_coin_type(coin_type)
        .finish()
        .await
        .unwrap();

    // Create account with alias: "0" (default)
    let account = wallet.create_account().finish().await?;

    // Get balance for default account
    let balance = account.sync(None).await?;
    info!("{balance:#?}");

    // Option A
    if balance.base_coin().total() != balance.required_storage_deposit().alias() {
        warn!("Amount of total tokens exceeds required storage deposit")
    }

    // Option B
    if balance.base_coin().available() > 0 {
        warn!("TODO: send back to origin address (State Controller? Governor?)")
    }

    Ok(())
}

/// Gets the current balance of the given Bech32-encoded address from the respective IOTA network.
/// https://github.com/iotaledger/identity.rs/blob/main/examples/utils/utils.rs
pub async fn get_address_balance(address: &Bech32Address) -> Result<u64, WalletError> {
    let client = match address.hrp().to_string().as_str() {
        "rms" => Client::builder().with_primary_node(TESTNET_URL, None)?.finish().await?,
        "smr" => Client::builder().with_primary_node(SHIMMER_URL, None)?.finish().await?,
        "iota" => Client::builder().with_primary_node(MAINNET_URL, None)?.finish().await?,
        _ => return Err(WalletError::Generic("Unsupported network".to_string())),
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

    info!("Balance for address `{}`: {}", address.to_string(), total_amount);

    Ok(total_amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    use iota_sdk::client::constants::SHIMMER_COIN_TYPE;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use iota_sdk::wallet::ClientOptions;
    use iota_sdk::{types::block::address::Bech32Address, Wallet};
    use std::str::FromStr;
    use test_log::test;

    #[test(tokio::test)]
    async fn recreates_an_expected_address_from_a_given_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let address = get_first_address(&secret_manager, "rms").await.unwrap();

        assert_eq!(
            address.to_string(),
            "rms1qrdgpq8a4xjetgf79gnx7g5n0rfeykm30rek9fpjef6dnx3md929ksv04a0"
        );
    }

    #[test(tokio::test)]
    async fn gets_the_current_balance_for_a_given_address() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let address = get_first_address(&secret_manager, "rms").await.unwrap();

        let balance = get_address_balance(&address).await.unwrap();

        assert_eq!(balance > 0, true);
    }

    #[test(tokio::test)]
    async fn fails_to_get_the_balance_for_an_unsupported_network() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let address =
            Bech32Address::from_str("foobar1qp7m6flrdjxwhul2kh0zf0wj73vdxk6p9cy8pdkt00dpsf92xkqe6975kp8").unwrap();

        assert!(get_address_balance(&address).await.is_err());
    }

    #[test(tokio::test)]
    async fn successfully_checks_funds() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        assert!(sync_funds(secret_manager).await.is_ok());
    }

    #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn send_tokens_to_alice() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let client_options = ClientOptions::new()
            .with_node("https://api.testnet.shimmer.network")
            .unwrap();

        let wallet = Wallet::builder()
            .with_secret_manager(secret_manager)
            .with_client_options(client_options)
            .with_coin_type(SHIMMER_COIN_TYPE)
            .finish()
            .await
            .unwrap();

        let account = wallet.create_account().finish().await.unwrap();

        let first_address = &account.addresses().await.unwrap()[0];
        println!("{}", first_address.address());

        let balance = account.sync(None).await.unwrap();
        println!("{balance:#?}");

        let receiving_address = "rms1qp99pya2keu6sgdtmlhu6xdktt5c84wewu7sd5usta2q88mgue4zxq5fen8"
            .parse::<Bech32Address>()
            .unwrap();

        // Required amount of tokens:
        // basic output: 42600
        // alias output: 89300
        let amount = 89299;

        let transaction = account.send(amount, receiving_address, None).await.unwrap();

        let block_id = account
            .retry_transaction_until_included(&transaction.transaction_id, None, None)
            .await
            .unwrap();

        println!("Block included: https://explorer.iota.org/testnet/block/{}", block_id);
    }

    #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn send_tokens_back_to_funding_address() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/alice.stronghold";
        const PASSWORD: &str = "secure_password";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let client_options = ClientOptions::new()
            .with_node("https://api.testnet.shimmer.network")
            .unwrap();

        let wallet = Wallet::builder()
            .with_secret_manager(secret_manager)
            .with_client_options(client_options)
            .with_coin_type(SHIMMER_COIN_TYPE)
            .finish()
            .await
            .unwrap();

        let account = wallet.create_account().finish().await.unwrap();

        let first_address = &account.addresses().await.unwrap()[0];
        println!("{}", first_address.address());

        let balance = account.sync(None).await.unwrap();
        println!("{balance:#?}");

        let receiving_address = "rms1qrdgpq8a4xjetgf79gnx7g5n0rfeykm30rek9fpjef6dnx3md929ksv04a0"
            .parse::<Bech32Address>()
            .unwrap();

        // Required amount of tokens for alias output: 89300
        let amount = balance.base_coin().available();

        let transaction = account.send(amount, receiving_address, None).await.unwrap();

        let block_id = account
            .retry_transaction_until_included(&transaction.transaction_id, None, None)
            .await
            .unwrap();

        println!("Block included: https://explorer.iota.org/testnet/block/{}", block_id);
    }
}
