use alloy_consensus::transaction::TxSeismic;
use alloy_network::TransactionBuilder;
use alloy_primitives::{hex, Bytes, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::{OtherFields, WithOtherFields};
use anvil::{spawn, NodeConfig};
use anvil_core::eth::transaction::crypto;
use serde::{Deserialize, Serialize};
use std::fs;
use tee_service_api::{get_sample_secp256k1_pk, get_sample_secp256k1_sk};

/// Seismic specific transaction field(s)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SeismicTransactionFields {
    /// Encryption public key
    #[serde(rename = "encryptionPubkey")]
    pub encryption_pubkey: Bytes,
}

impl From<SeismicTransactionFields> for OtherFields {
    fn from(value: SeismicTransactionFields) -> Self {
        serde_json::to_value(value).unwrap().try_into().unwrap()
    }
}

// common utils
pub const TEST_BYTECODE_PATH: &str = "/tests/it/seismic_test_bytecode.txt";
pub const SET_NUMBER_SELECTOR: &str = "3fb5c1cb"; // setNumber(uint256)
pub const INCREMENT_SELECTOR: &str = "d09de08a"; // increment()
pub const GET_NUMBER_SELECTOR: &str = "f2c9ecd8"; // getNumber()

/// Loads the bytecode from a file and returns it as a vector of bytes.
pub fn load_bytecode_from_file(file_path: &str) -> Vec<u8> {
    let path = format!("{}{}", env!("CARGO_MANIFEST_DIR"), file_path);
    let bytecode_str = fs::read_to_string(path).expect("Failed to read bytecode file");
    hex::decode(bytecode_str.trim()).expect("Failed to decode bytecode")
}

/// Gets the input data for a given selector function and one B256 value
pub fn get_input_data(selector: &str, value: B256) -> Bytes {
    let selector_bytes: Vec<u8> = hex::decode(&selector[0..8]).expect("Invalid selector");

    // Convert value to bytes
    let value_bytes: Bytes = value.into();

    // Initialize the input data with the selector and value
    let mut input_data = Vec::new();
    input_data.extend_from_slice(&selector_bytes);
    input_data.extend_from_slice(&value_bytes);

    input_data.into()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_transaction() {
    let (api, handle) = spawn(NodeConfig::test()).await;

    // set automine to false
    api.anvil_set_auto_mine(false).await.unwrap();

    let provider = handle.http_provider();
    let deployer = handle.dev_accounts().next().unwrap();

    let bytecode = load_bytecode_from_file(TEST_BYTECODE_PATH);

    let deploy_tx = TransactionRequest::default().from(deployer).with_deploy_code(bytecode.clone());
    let deploy_tx = WithOtherFields::new(deploy_tx);

    let pending = provider.send_transaction(deploy_tx).await.unwrap();

    // mine block
    api.mine_one().await;

    let receipt =
        provider.get_transaction_receipt(pending.tx_hash().to_owned()).await.unwrap().unwrap();
    assert!(receipt.contract_address.is_some());

    let accounts: Vec<_> = handle.dev_wallets().collect();

    let from = accounts[0].address();
    let encryption_sk = get_sample_secp256k1_sk();
    let encryption_pk = Bytes::from(get_sample_secp256k1_pk().serialize());

    let to = receipt.contract_address.unwrap();

    let encoded_setnumber_data = get_input_data(SET_NUMBER_SELECTOR, B256::from(U256::from(10)));
    let set_data = crypto::client_encrypt(&encryption_sk, &encoded_setnumber_data, 1).unwrap();

    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(1)
        .with_gas_limit(210000)
        .with_chain_id(31337)
        .with_input(set_data);

    let seismic_tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields { encryption_pubkey: encryption_pk.clone() }.into(),
    };

    let pending_set = provider.send_transaction(seismic_tx).await.unwrap();

    api.mine_one().await;

    let receipt: Option<
        WithOtherFields<
            alloy_rpc_types::TransactionReceipt<
                alloy_network::AnyReceiptEnvelope<alloy_rpc_types::Log>,
            >,
        >,
    > = provider.get_transaction_receipt(pending_set.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());

    let encoded_increment_data = get_input_data(INCREMENT_SELECTOR, B256::from(U256::from(10)));
    let increment_data =
        crypto::client_encrypt(&encryption_sk, &encoded_increment_data, 2).unwrap();

    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(2)
        .with_gas_limit(210000)
        .with_chain_id(31337)
        .with_input(increment_data);

    let seismic_tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields { encryption_pubkey: encryption_pk.clone() }.into(),
    };

    let pending_increment = provider.send_transaction(seismic_tx).await.unwrap();

    api.mine_one().await;

    let receipt =
        provider.get_transaction_receipt(pending_increment.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());

    let encoded_getnumber_data = hex::decode(GET_NUMBER_SELECTOR).unwrap();
    let get_data = crypto::client_encrypt(&encryption_sk, &encoded_getnumber_data, 3).unwrap();

    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(3)
        .with_gas_limit(210000)
        .with_chain_id(31337)
        .with_input(get_data);

    let seismic_tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields { encryption_pubkey: encryption_pk.clone() }.into(),
    };

    let pending_get = provider.send_transaction(seismic_tx).await.unwrap();

    api.mine_one().await;

    let receipt = provider.get_transaction_receipt(pending_get.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());
}
