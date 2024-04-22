pub mod iota;

use iota_sdk::client::constants::SHIMMER_COIN_TYPE;
use iota_sdk::types::block::address::Hrp;
use iota_sdk::wallet::ClientOptions;
use iota_sdk::Wallet;
use iota_sdk::{
    client::{api::GetAddressesOptions, secret::SecretManager},
    types::block::address::Bech32Address,
};
use log::info;
use shared::error::WalletError;
use std::str::FromStr;

static MAINNET_URL: &str = "https://api.stardust-mainnet.iotaledger.net";
static SHIMMER_URL: &str = "https://api.shimmer.network";
static TESTNET_URL: &str = "https://api.testnet.shimmer.network";

pub trait TokenWallet {
    async fn new() -> Self;
    /// Get the balance for any given address on the network.
    async fn get_balance(&self, address: &str) -> Result<u64, WalletError>;
    /// Get the total balance for the current account.
    async fn get_account_balance(&self) -> Result<u64, WalletError>;
}

/// Returns the first address derived from the underlying Stronghold snapshot.
pub async fn get_first_address(secret_manager: &SecretManager, network: &str) -> Result<Bech32Address, WalletError> {
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

/// Send all available funds from the funding address to a given receiving address.
pub async fn return_all_funds(secret_manager: SecretManager, receiver: Bech32Address) -> Result<(), WalletError> {
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

    // Create and publish transaction
    let tx = account.send(balance.base_coin().available(), receiver, None).await?;

    #[cfg(feature = "wait")]
    wait_for_inclusion(&tx.transaction_id, &account).await?;

    Ok(())
}

#[cfg(feature = "wait")]
async fn wait_for_inclusion(transaction_id: &TransactionId, account: &Account) -> Result<(), WalletError> {
    info!(
        "Transaction sent: {}/transaction/{}",
        std::env::var("EXPLORER_URL").unwrap(),
        transaction_id
    );
    // Wait for transaction to get included
    let block_id = account
        .retry_transaction_until_included(transaction_id, None, None)
        .await?;
    info!(
        "Block included: {}/block/{}",
        std::env::var("EXPLORER_URL").unwrap(),
        block_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::iota::IotaWallet;

    use super::*;

    use iota_sdk::client::constants::SHIMMER_COIN_TYPE;
    use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
    use iota_sdk::client::Password;
    use iota_sdk::types::block::address::Bech32Address;
    use iota_sdk::wallet::{ClientOptions, Wallet};
    use std::str::FromStr;
    use test_log::test;

    #[test(tokio::test)]
    async fn recreates_an_expected_address_from_a_given_stronghold() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let wallet = IotaWallet::new().await;

        let address = wallet.get_funding_address().await;

        assert_eq!(
            address.to_string(),
            "rms1qrc369hrnga48s7jzwm5a2d7m70zjq4gjjvcsngvewgnlhu8ac89wrak7p9"
        );
    }

    #[test(tokio::test)]
    async fn gets_the_current_balance_for_a_given_address() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let wallet = IotaWallet::new().await;
        let balance = wallet.get_account_balance().await.unwrap();

        // let address = get_first_address(&secret_manager, "rms").await.unwrap();

        // let balance = get_bala(&address).await.unwrap();

        assert_eq!(balance > 0, true);
    }

    #[test(tokio::test)]
    async fn fails_to_get_the_balance_for_unsupported_network() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        let address_str = "foobar1qp7m6flrdjxwhul2kh0zf0wj73vdxk6p9cy8pdkt00dpsf92xkqe6975kp8";

        let wallet = IotaWallet::new().await;

        assert!(wallet.get_balance(address_str).await.is_err());
    }

    // #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn successfully_fund_the_governor_address_when_funds_available() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        // const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        // const PASSWORD: &str = "secure_password";

        // let secret_manager: SecretManager = SecretManager::Stronghold(
        //     StrongholdSecretManager::builder()
        //         .password(Password::from(PASSWORD.to_owned()))
        //         .build(SNAPSHOT_PATH.to_owned())
        //         .unwrap(),
        // );

        // let governor = ""; //Bech32Address::from_str().unwrap();

        // let client_options = ClientOptions::new().with_node(TESTNET_URL).unwrap();
        // let coin_type = SHIMMER_COIN_TYPE;

        // let wallet = Wallet::builder()
        //     .with_secret_manager(secret_manager)
        //     .with_client_options(client_options)
        //     .with_coin_type(coin_type)
        //     .finish()
        //     .await
        //     .unwrap();

        // let account = wallet.create_account().finish().await.unwrap();

        let wallet = IotaWallet::new().await;

        assert_eq!(
            wallet.get_governor_address().await,
            "rms1qzlj3hjhn2lc570xmzutltztvuxjj9wzh7kx82fkvz6chdlvgkqrcpw3vnd"
        );

        // assert!(wallet.fund_storage_deposit().await.is_ok());
    }

    #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn send_tokens_to_alice() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/wallet.stronghold";
        const PASSWORD: &str = "secur3_wall3t";

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

    #[ignore = "manual test"]
    #[test(tokio::test)]
    async fn successfully_returns_all_available_funds_from_funding_address() {
        iota_stronghold::engine::snapshot::try_set_encrypt_work_factor(0).unwrap();

        const SNAPSHOT_PATH: &str = "tests/res/wallet.stronghold";
        const PASSWORD: &str = "secur3_wall3t";

        let secret_manager: SecretManager = SecretManager::Stronghold(
            StrongholdSecretManager::builder()
                .password(Password::from(PASSWORD.to_owned()))
                .build(SNAPSHOT_PATH.to_owned())
                .unwrap(),
        );

        let receiver =
            Bech32Address::from_str("rms1qrdgpq8a4xjetgf79gnx7g5n0rfeykm30rek9fpjef6dnx3md929ksv04a0").unwrap();

        assert!(return_all_funds(secret_manager, receiver).await.is_ok());
    }
}
