use anyhow::Result;
use aptos_sdk;
use aptos_sdk::coin_client::CoinClient;
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
use aptos_sdk::rest_client::Client;
use aptos_sdk::types::account_address::AccountAddress;
use aptos_sdk::types::{AccountKey, LocalAccount};
use dotenv::dotenv;
use reqwest;
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;
use tokio;
use url::Url;

#[derive(Deserialize)]
struct AccountData {
    sequence_number: String,
}

async fn create_wallet(address: &str, priv_key: &str, seq_number: u64) -> LocalAccount {
    let account = LocalAccount::new(
        AccountAddress::from_str(address).unwrap(),
        AccountKey::from_private_key(Ed25519PrivateKey::from_encoded_string(priv_key).unwrap()),
        seq_number,
    );

    account
}
async fn get_account_sequence_number(address: &str, node_url: &str) -> u64 {
    let account_data = reqwest::get(format!("{node_url}v1/accounts/{address}"))
        .await
        .unwrap()
        .json::<AccountData>()
        .await
        .unwrap_or_else(|err| {
            println!("Account has 0 transactions. Error: {:?}", err);
            AccountData {
                sequence_number: String::from("0"),
            }
        });
    account_data.sequence_number.parse::<u64>().unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let transaction_fee: u64 = 54100;
    let node_env = std::env::var("NODE_URL").unwrap();
    let node_url: Url = Url::from_str(&node_env[..]).unwrap_or_else(|_| {
        println!("Use default node");
        return Url::from_str("https://aptos-mainnet.pontem.network").unwrap();
    });

    print!("Address: ");
    io::stdout().flush().expect("flush failed.");
    let mut from_address = String::new();
    io::stdin()
        .read_line(&mut from_address)
        .expect("Failed to read address");
    from_address = from_address.trim().parse()?;

    print!("Private key: ");
    io::stdout().flush().expect("flush failed.");
    let mut from_private_key = String::new();
    io::stdin()
        .read_line(&mut from_private_key)
        .expect("Failed to read private key");
    from_private_key = from_private_key.trim().parse()?;

    print!("Amount: ");
    io::stdout().flush().expect("flush failed.");
    let mut amount_string = String::new();
    io::stdin()
        .read_line(&mut amount_string)
        .expect("Failed to read amount");

    let amount = amount_string
        .trim()
        .parse::<u64>()
        .expect("Can't convert amount to u64");

    let mut addresses = vec![];
    let mut addresses_data = String::new();
    File::open("addresses.txt")
        .expect("File with addresses not found!")
        .read_to_string(&mut addresses_data)
        .expect("Can't read addresses file to variable");

    for address in addresses_data.split("\n") {
        if address == "" {
            continue;
        }
        addresses.push(address);
    }

    let seq_number = get_account_sequence_number(&from_address[..], &node_url.as_str()).await;
    let mut wallet = create_wallet(&from_address[..], &from_private_key[..], seq_number).await;

    let rest_client = Client::new(node_url.clone());
    let coin_client = CoinClient::new(&rest_client);
    let balance = coin_client
        .get_account_balance(&wallet.address())
        .await
        .unwrap();

    if balance
        < (amount * (addresses.len() as u64) + transaction_fee * (addresses.len() as u64)) as u64
    {
        println!("You don't have enough balance!");
        return Ok(());
    }

    for address in addresses {
        let txn_hash = coin_client
            .transfer(
                &mut wallet,
                AccountAddress::from_str(address).unwrap(),
                amount,
                None,
            )
            .await
            .unwrap();
        println!("{:?}", txn_hash.hash)
    }

    Ok(())
}
