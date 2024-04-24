use crypto::keys::bip39;
use iota_sdk::{
    client::{
        constants::SHIMMER_COIN_TYPE, node_api::indexer::query_parameters::QueryParameter, secret::SecretManager,
        stronghold::StrongholdAdapter, Password,
    },
    types::block::address::Bech32Address,
    wallet::ClientOptions,
    Wallet,
};
use log::info;
use shared::error::WalletError;
use std::str::FromStr;

use crate::{TokenWallet, TESTNET_URL};

const SNAPSHOT_PATH: &str = "tests/res/wallet.stronghold"; // TODO: make parameter of "new()"
const PASSWORD: &str = "secur3_wall3t"; // TODO: make parameter of "new()"
const ACCOUNT_INDEX: u32 = 0;

pub struct IotaWallet {
    wallet: Wallet,
}

impl TokenWallet for IotaWallet {
    async fn new() -> Self {
        // Stronghold
        let stronghold_adapter = StrongholdAdapter::builder()
            .password(Password::from(PASSWORD.to_owned()))
            .build(SNAPSHOT_PATH)
            .unwrap();
        let secret_manager = SecretManager::Stronghold(stronghold_adapter);

        create_and_store_mnemonic(&secret_manager).await.unwrap();

        // Wallet
        let client_options = ClientOptions::new().with_node(TESTNET_URL).unwrap();
        let coin_type = SHIMMER_COIN_TYPE; // TODO: hardcoded for now
        let wallet = Wallet::builder()
            .with_secret_manager(secret_manager)
            .with_client_options(client_options)
            .with_coin_type(coin_type)
            .finish()
            .await
            .unwrap();

        // Account
        wallet
            .create_account()
            .with_alias(ACCOUNT_INDEX.to_string())
            .finish()
            .await
            .unwrap();

        Self { wallet }
    }

    async fn get_balance(&self, address: &str) -> Result<u64, WalletError> {
        let client = self.wallet.client();

        let output_ids = client
            .basic_output_ids(vec![
                QueryParameter::Address(Bech32Address::from_str(address).unwrap()),
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

    async fn get_account_balance(&self) -> Result<u64, WalletError> {
        let account = self.wallet.get_account(ACCOUNT_INDEX).await.unwrap();
        account.sync(None).await.unwrap();
        let balance = account.balance().await.unwrap();
        Ok(balance.base_coin().available())
    }
}

impl IotaWallet {
    /// TODO: currently hard-coded to be the _first_ address in the Stronghold
    pub async fn get_funding_address(&self) -> Bech32Address {
        const ADDRESS_INDEX: u32 = 0;
        let first_address = self
            .wallet
            .generate_ed25519_address(ACCOUNT_INDEX, ADDRESS_INDEX, None)
            .await
            .unwrap();
        let funding_address = Bech32Address::new(self.wallet.get_bech32_hrp().await.unwrap(), first_address);
        info!("Funding address: {}", funding_address);
        funding_address
    }

    /// TODO: currently hard-coded to be the _second_ address in the Stronghold
    pub async fn get_governor_address(&self) -> Bech32Address {
        const ADDRESS_INDEX: u32 = 1;
        let second_address = self
            .wallet
            .generate_ed25519_address(ACCOUNT_INDEX, ADDRESS_INDEX, None)
            .await
            .unwrap();
        let governor = Bech32Address::new(self.wallet.get_bech32_hrp().await.unwrap(), second_address);
        // TODO: governor address should use a different different key
        info!("Governor address: {}", governor);
        governor
    }

    /// Send the required amount of tokens for an Alias Output from the funding address to the given Governor address.
    pub async fn fund_storage_deposit(
        &self,
        // secret_manager: SecretManager,
        // account: &Account,
        // wallet: Wallet,
        // governor: Bech32Address,
    ) -> Result<(), WalletError> {
        // TODO: only creating a new one, because reference does not work: .with_secret_manager(&secret_manager)
        // const SNAPSHOT_PATH: &str = "tests/res/test.stronghold";
        // const PASSWORD: &str = "secure_password";
        // let secret_manager: SecretManager = SecretManager::Stronghold(
        //     StrongholdSecretManager::builder()
        //         .password(Password::from(PASSWORD.to_owned()))
        //         .build(SNAPSHOT_PATH.to_owned())
        //         .unwrap(),
        // );

        // let wallet = Wallet::builder()
        //     .with_secret_manager(secret_manager)
        //     .with_client_options(client_options)
        //     .with_coin_type(coin_type)
        //     .finish()
        //     .await
        //     .unwrap();
        let account = self.wallet.get_account(ACCOUNT_INDEX).await.unwrap();

        // Get balance for default account
        let balance = account.sync(None).await?;
        info!("{balance:#?}");

        let funding_address = self.get_funding_address().await;
        let governor = self.get_governor_address().await;
        // let funding_address = account.addresses().await?.first().unwrap().to_owned().into_bech32();
        // let funding_address = get_first_address(&secret_manager, "rms").await?;

        // TODO: Is this really correct? The funding address could also give up its own Basic Output (not included in "base_coin.available"?).
        if balance.base_coin().available() < 89300 {
            return Err(WalletError::InsufficientFunds {
                required_amount: 89300 - balance.base_coin().available(),
                funding_address,
            });
        }

        info!("Sending 89300 tokens to Governor address: {}", governor.to_string());

        // let transaction = account.send(89300, governor, None).await.unwrap();

        // let block_id = account
        //     .retry_transaction_until_included(&transaction.transaction_id, None, None)
        //     .await
        //     .unwrap();

        Ok(())
    }

    /// Returns a reference to the encapsulated `iota_sdk::Wallet`.
    pub async fn inner(&self) -> &Wallet {
        &self.wallet
    }
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
