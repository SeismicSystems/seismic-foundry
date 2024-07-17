use crate::utils::http_provider_with_signer;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{b256, hex::FromHex, Bytes, U128, U256, B256,hex, bytes, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use anvil::{spawn, NodeConfig};
use alloy_rlp::{Decodable, Encodable, Header, EMPTY_STRING_CODE};
use hyper::header::USER_AGENT;
use seismic_db::CommitmentDatabase;
use seismic_preimages::PreImageValue;
use seismic_types::Secret;
use anvil_core::eth::transaction::seismic::{SeismicTransactionFields, SecretData};
use std::{fs, str::FromStr};
use seismic_types::secret::use_zero_salt;
use tokio::runtime::Handle;
// common utils

pub const TEST_BYTECODE_PATH: &str = "/tests/it/seismic_test_bytecode.txt";
pub const SET_NUMBER_SELECTOR: &str = "3fb5c1cb";
pub const ADD_SELECTOR: &str = "1003e2d2"; // add(uint256)
pub const GET_NUMBER_SELECTOR: &str = "f2c9ecd8";


/// Loads the bytecode from a file and returns it as a vector of bytes.
pub fn load_bytecode_from_file(file_path: &str) -> Vec<u8> {
    let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), file_path);
    let bytecode_str = fs::read_to_string(path).expect("Failed to read bytecode file");
    hex::decode(bytecode_str.trim()).expect("Failed to decode bytecode")
}


pub fn get_commitment(value: U256) -> B256 {
    let secret = Secret::new(value);
    secret.commit_b256()
}

pub fn get_input_data(selector: &str, secret_a: B256, secret_b: Option<B256>) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");

    // Convert secret_a to bytes
    let secret_a_bytes: Bytes = secret_a.into();

    // Initialize the input data with the selector and secret_a
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&secret_a_bytes);

    // If secret_b is Some, convert to bytes and extend the input data
    if let Some(secret_b) = secret_b {
        let secret_b_bytes: Bytes = secret_b.into();
        input_data.extend_from_slice(&secret_b_bytes);
    }

    input_data.into()
}


#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_transaction() {
    use_zero_salt();
    let (api, handle) = spawn(NodeConfig::test()).await;
    let provider = handle.http_provider();
    let deployer = handle.dev_accounts().next().unwrap();
    let bytecode = load_bytecode_from_file(TEST_BYTECODE_PATH);

    let deploy_tx = TransactionRequest::default()
        .from(deployer)
        .with_deploy_code(bytecode.clone());    
    let deploy_tx = WithOtherFields::new(deploy_tx);

    let pending = provider.send_transaction(deploy_tx).await.unwrap();

        // mine block
        api.evm_mine(None).await.unwrap();
    
        let receipt =
        provider.get_transaction_receipt(pending.tx_hash().to_owned()).await.unwrap().unwrap();
        assert!(receipt.contract_address.is_some());
        println!(" --- Contract deployed at: {:?} --- ", receipt.contract_address.unwrap());


        let accounts: Vec<_> = handle.dev_wallets().collect();
        
        let from = accounts[0].address();

        let to = receipt.contract_address.unwrap();

        let value = U256::from(10);

        let input_data = get_input_data(SET_NUMBER_SELECTOR, get_commitment(value), None);

        let tx = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_gas_limit(210000)
            .with_input(input_data);
        let tx = WithOtherFields {
            inner: tx,
            other: SeismicTransactionFields {
            secret_data: Some(vec![SecretData {
                    index: 0,
                    preimage: PreImageValue::Uint(10),
                    preimage_type: "uint256".to_string(),
                    salt: B256::from(U256::from(0)).into(),
                }]),
            }
            .into(),
        };

        println!("The local hash is: {:?}", get_commitment(value));

    let pending_set = provider.send_transaction(tx).await.unwrap();
    

    api.evm_mine(None).await.unwrap();

    let receipt = provider.get_transaction_receipt(pending_set.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());
    println!(" --- Set receipt: {:?} --- ", receipt);

    let mut to_hash = get_commitment(value).to_vec();
    to_hash.extend_from_slice(&to.as_ref());
    let commitment_key = keccak256(to_hash);

    println!("The commitment key on the test is: {:?}", B256::from(commitment_key));

    let commitment = anvil::eth::SEISMIC_DB.clone().get_commitment(commitment_key).unwrap().unwrap();

    println!("The commitment is: {:?}", commitment);

        let value = U256::from(20);

        let input_data = get_input_data(ADD_SELECTOR, get_commitment(value), None);


        let tx = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_gas_limit(210000)
            .with_input(input_data);
        let tx = WithOtherFields {
            inner: tx,
            other: SeismicTransactionFields {
            secret_data: Some(vec![SecretData {
                    index: 0,
                    preimage: PreImageValue::Uint(20),
                    preimage_type: "uint256".to_string(),
                    salt: B256::from(U256::from(0)).into(),
                }]),
            }
            .into(),
        };

    let pending_add = provider.send_transaction(tx).await.unwrap();

    api.evm_mine(None).await.unwrap();

    let receipt = provider.get_transaction_receipt(pending_add.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());

    println!(" --- Add receipt: {:?} --- ", receipt);

    let input_data_get = hex::decode(GET_NUMBER_SELECTOR).unwrap();

    let tx = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_gas_limit(210000)
            .with_input(input_data_get);

    let get_tx = WithOtherFields::new(tx);

    let pending_get = provider.send_transaction(get_tx).await.unwrap();

    api.evm_mine(None).await.unwrap();

   

    let receipt = provider.get_transaction_receipt(pending_get.tx_hash().to_owned()).await.unwrap().unwrap();
    println!(" --- Get receipt: {:?} --- ", receipt);
    panic!();

    // assert_eq!(receipt.from, from);
    // assert_eq!(receipt.to, Some(to));
}

