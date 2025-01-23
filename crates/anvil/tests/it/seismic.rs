use alloy_consensus::{transaction::TxSeismic, SignableTransaction, Signed, TypedTransaction};
use alloy_dyn_abi::{DynSolType, EventExt};
use alloy_json_abi::{Event, EventParam};
use alloy_network::{ReceiptResponse, TransactionBuilder, TxSigner};
use alloy_primitives::{aliases::{B96, U96}, hex::{self, FromHex}, Bytes, FixedBytes, IntoLogData, TxKind, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::{OtherFields, WithOtherFields};
use anvil::{spawn, NodeConfig};
use anvil_core::eth::transaction::{crypto, SeismicCallRequest};
use alloy_eips::eip2718::{Decodable2718, Eip2718Error, Encodable2718};
use serde::{Deserialize, Serialize};
use std::fs;
use tee_service_api::{get_sample_secp256k1_pk, get_sample_secp256k1_sk};
use alloy_sol_types::{sol, SolValue, SolCall};

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
pub const TEST_PRECOMPILES_BYTECODE_PATH: &str = "/tests/it/seismic_precompiles_test_bytecode.txt";
pub const SET_NUMBER_SELECTOR: &str = "3fb5c1cb"; // setNumber(uint256)
pub const INCREMENT_SELECTOR: &str = "d09de08a"; // increment()
pub const GET_NUMBER_SELECTOR: &str = "f2c9ecd8"; // getNumber()
pub const PRECOMPILES_TEST_SET_AES_KEY_SELECTOR: &str = "a0619040"; // setAESKey(suint256) 
pub const PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR: &str = "28696e36"; // submitMessage(bytes) 

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

pub fn concat_input_data(selector: &str, value: Bytes) -> Bytes {
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
    let provider = handle.http_provider();
    let deployer = handle.dev_accounts().next().unwrap();

    let bytecode = load_bytecode_from_file(TEST_BYTECODE_PATH);

    let deploy_tx = TransactionRequest::default().from(deployer).with_deploy_code(bytecode.clone());
    let deploy_tx = WithOtherFields::new(deploy_tx);

    let pending = provider.send_transaction(deploy_tx).await.unwrap();

    // mine block
    api.evm_mine(None).await.unwrap();

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

    api.evm_mine(None).await.unwrap();

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

    api.evm_mine(None).await.unwrap();

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

    api.evm_mine(None).await.unwrap();

    let receipt = provider.get_transaction_receipt(pending_get.tx_hash().to_owned()).await.unwrap();
    assert!(receipt.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_precompiles_end_to_end() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(false).await.unwrap();
    let provider = handle.http_provider();
    let deployer = handle.dev_accounts().next().unwrap();

    let bytecode = load_bytecode_from_file(TEST_PRECOMPILES_BYTECODE_PATH);

    let deploy_tx = TransactionRequest::default().from(deployer).with_deploy_code(bytecode.clone());
    let deploy_tx = WithOtherFields::new(deploy_tx);

    let pending = provider.send_transaction(deploy_tx).await.unwrap();

    // mine block
    api.mine_one().await;

    let receipt =
        provider.get_transaction_receipt(pending.tx_hash().to_owned()).await;
    let receipt_ref = receipt.as_ref().unwrap().as_ref().unwrap();
    assert!(receipt_ref.contract_address.is_some());
    assert!(receipt_ref.status());
    
    let accounts: Vec<_> = handle.dev_wallets().collect();

    let from = accounts[0].address();
    let encryption_sk = get_sample_secp256k1_sk();
    let encryption_pk = Bytes::from(get_sample_secp256k1_pk().serialize());
    let encryption_pk_write_tx = FixedBytes::<33>::from(get_sample_secp256k1_pk().serialize());
    let to = receipt.unwrap().unwrap().contract_address.unwrap();
    let nonce = provider.get_transaction_count(from).await.unwrap();
    
    let private_key = B256::from_hex("7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b").unwrap();
    let encoded_input = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    let set_data = crypto::client_encrypt(&encryption_sk, &encoded_input, 1).unwrap();

    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(nonce)
        .with_gas_limit(410000)
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
    assert!(receipt.unwrap().status());
    
    let nonce = provider.get_transaction_count(from).await.unwrap();
    let message = Bytes::from("hello world".as_bytes());
    type PlaintextType = Bytes;

    let encoded: Vec<u8> = PlaintextType::abi_encode(&message);

    let encoded_input = concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded.into());
    println!("encoded_input: {:?}", encoded_input);
    let set_data = crypto::client_encrypt(&encryption_sk, &encoded_input, 2).unwrap();

    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(nonce)
        .with_gas_limit(410000)
        .with_chain_id(31337)
        .with_input(set_data);

    let seismic_tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields { encryption_pubkey: encryption_pk.clone() }.into(),
    };

    println!("should be signed seismic_tx: {:?}", seismic_tx);

    let pending_set = provider.send_transaction(seismic_tx).await.unwrap();

    api.mine_one().await;

    let receipt: Option<
        WithOtherFields<
            alloy_rpc_types::TransactionReceipt<
                alloy_network::AnyReceiptEnvelope<alloy_rpc_types::Log>,
            >,
        >,
    > = provider.get_transaction_receipt(pending_set.tx_hash().to_owned()).await.unwrap();
    let receipt_ref = receipt.as_ref().unwrap();
    assert!(receipt_ref.status());
    
    let logs = receipt_ref.inner.inner.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].inner.address, to);
    let log = logs[0].inner.data.clone();
    println!("log_topic: {:?}", log.topics());
    println!("log_data: {:?}", log.to_log_data());
    let raw_nonce: B256 = log.topics()[1].into();
    println!("nonce: {:?}", raw_nonce);
   
    let event = Event {
            name: "EncryptedMessage".into(),
            inputs: vec![
                EventParam { ty: "int96".into(), indexed: true, ..Default::default() },
                EventParam { ty: "bytes".into(), indexed: false, ..Default::default() },
            ],
            anonymous: false,
        };

    let result = event.decode_log(&log.into_log_data(), false).unwrap();
    
    sol! {
        #[derive(Debug, PartialEq)]
        interface Encryption {
            function decrypt(uint96 nonce,bytes calldata ciphertext) external view onlyOwner returns (bytes memory plaintext);
        }
    }
    
    let nonce: U96 = U96::from_be_bytes(B96::from_slice(&result.indexed[0].abi_encode_packed()).into());
    let ciphertext = Bytes::from(result.body[0].abi_encode_packed());
    let call = Encryption::decryptCall{
        nonce, 
        ciphertext,
    };

    println!("result size: {:?}", result.body[0].abi_packed_encoded_size());
    println!("result: {:?}", hex::encode(call.abi_encode()));

    let set_data = crypto::client_encrypt(&encryption_sk, &call.abi_encode(), 3).unwrap();
    let nonce = provider.get_transaction_count(from).await.unwrap();

    let mut seismic_tx = TxSeismic {
        chain_id: 31337u64,
        nonce,
        gas_price: 1000000000,
        gas_limit: 410000,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: set_data.into(),
        encryption_pubkey: encryption_pk_write_tx,
    };
    
    let signature = accounts[0].sign_transaction(&mut seismic_tx).await.unwrap();
    let signed_tx: Signed<TxSeismic> = seismic_tx.into_signed(signature);
    let typed_tx = TypedTransaction::Seismic(signed_tx.tx().clone());

    //    Or if you want to encode the signed version:
    let mut rlp_encoded = Vec::new();
    signed_tx.rlp_encode(&mut rlp_encoded);

    let encoded_bytes = Bytes::from(rlp_encoded);

    let final_request = SeismicCallRequest::Bytes(encoded_bytes);

    let actual_plaintext = api.call(final_request, None, None).await.unwrap();
    
    println!("actual_plaintext: {:?}", actual_plaintext);
}
