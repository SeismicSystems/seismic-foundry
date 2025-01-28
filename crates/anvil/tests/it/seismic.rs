use alloy_consensus::{transaction::TxSeismic, SignableTransaction, Signed, TxLegacy};
use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{ReceiptResponse, TransactionBuilder, TxSigner};
use alloy_primitives::{aliases::{B96, U96}, hex::{self, FromHex}, Address, Bytes, FixedBytes, IntoLogData, TxKind, B256, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::{OtherFields, WithOtherFields};
use anvil::{eth::EthApi, spawn, NodeConfig};
use anvil_core::eth::transaction::{crypto, SeismicCallRequest, TypedTransaction};
use foundry_common::provider::RetryProvider;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use alloy_eips::eip2718::{Decodable2718, Eip2718Error, Encodable2718};
use alloy_rlp::{length_of_length, Decodable, Encodable, Header};
use bytes::BufMut;
use std::fs;
use tee_service_api::{aes_decrypt, aes_encrypt, get_sample_secp256k1_pk, get_sample_secp256k1_sk};
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

// Helpful type alias for the receipt you retrieve
type SeismicReceipt = WithOtherFields<
    alloy_rpc_types::TransactionReceipt<
        alloy_network::AnyReceiptEnvelope<alloy_rpc_types::Log>,
    >
>;

// 1. Deploy a contract from bytecode. Returns its deployed address.
async fn deploy_contract(
    api: &EthApi,
    provider: &RetryProvider,
    deployer: Address,
    bytecode: Bytes,
) -> Address {
    let deploy_tx = TransactionRequest::default().from(deployer).with_deploy_code(bytecode);
    let deploy_tx = WithOtherFields::new(deploy_tx);

    let pending = provider.send_transaction(deploy_tx).await.unwrap();
    api.mine_one().await;

    let receipt = provider
        .get_transaction_receipt(pending.tx_hash().clone())
        .await
        .unwrap()
        .expect("No deployment receipt found");

    assert!(receipt.contract_address.is_some(), "Contract address missing in receipt");
    assert!(receipt.status(), "Contract deployment failed");

    receipt.contract_address.unwrap()
}

// 2. Sends an encrypted transaction, mines a block, and returns the receipt.
async fn send_encrypted_tx(
    api: &EthApi,
    provider: &RetryProvider,
    from: Address,
    to: Address,
    encryption_sk: &SecretKey,
    encryption_pk: Bytes,
    unencrypted_data: &[u8],
    encryption_nonce: u64,
) -> SeismicReceipt {
    let encrypted_input =
        crypto::client_encrypt(encryption_sk, unencrypted_data, encryption_nonce)
            .expect("Encryption failed");

    let nonce = provider.get_transaction_count(from).await.unwrap();
    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE)
        .with_from(from)
        .with_to(to)
        .with_nonce(nonce)
        .with_gas_limit(410000)
        .with_chain_id(31337)
        .with_input(encrypted_input);

    let seismic_tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields { encryption_pubkey: encryption_pk }.into(),
    };

    let pending = provider.send_transaction(seismic_tx).await.unwrap();
    api.mine_one().await;

    let maybe_receipt: Option<SeismicReceipt> =
        provider.get_transaction_receipt(pending.tx_hash().clone()).await.unwrap();

    let receipt = maybe_receipt.expect("No transaction receipt returned");
    assert!(receipt.status(), "Encrypted transaction failed");
    receipt
}

// 3. Helper to build the final “call” with encryption for read-only methods (e.g. your decrypt).
async fn seismic_read_call(
    api: &EthApi,
    provider: &RetryProvider,
    from: Address,
    to: Address,
    encryption_sk: &SecretKey,
    encryption_pk_write_tx: FixedBytes<33>,
    unencrypted_data: &[u8],
    encryption_nonce: u64,
) -> Bytes {
    let encrypted_call =
        crypto::client_encrypt(encryption_sk, unencrypted_data, encryption_nonce)
            .expect("Encryption for read call failed");

    let nonce = provider.get_transaction_count(from).await.unwrap();
    let tx = TransactionRequest::default()
        .transaction_type(TxSeismic::TX_TYPE as u8)
        .with_from(from)
        .with_to(to)
        .with_nonce(nonce)
        .with_gas_limit(410000)
        .with_chain_id(31337)
        .with_input(encrypted_call)
        .encryption_pubkey(encryption_pk_write_tx);

    let seismic_tx = WithOtherFields::new(tx);

    // The signing step
    let transaction = api.sign_transaction(seismic_tx).await.unwrap();
    let final_call = SeismicCallRequest::Bytes(Bytes::from_hex(transaction).unwrap());

    // Off-chain call
    api.call(final_call, None, None).await.unwrap()
}

// Actual contract being tested:
// https://github.com/SeismicSystems/early-builds/blob/main/encrypted_logs/src/end-to-end-mvp/EncryptedLogs.sol
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_precompiles_end_to_end() {
    // Spin up node, get provider & deployer
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(false).await.unwrap();
    let provider = handle.http_provider();
    let deployer = handle.dev_accounts().next().unwrap();

    // 1. Deploy test contract
    let bytecode = Bytes::from(load_bytecode_from_file(TEST_PRECOMPILES_BYTECODE_PATH));
    let contract_addr = deploy_contract(&api, &provider, deployer, bytecode).await;

    // Prepare addresses & keys
    let accounts: Vec<_> = handle.dev_wallets().collect();
    let from = accounts[0].address();
    let encryption_sk = get_sample_secp256k1_sk();
    let encryption_pk = Bytes::from(get_sample_secp256k1_pk().serialize());
    let encryption_pk_write_tx = FixedBytes::<33>::from(get_sample_secp256k1_pk().serialize());
    let private_key = B256::from_hex(
        "7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b"
    ).unwrap();

    //
    // 2. Tx #1: Set AES key in the contract
    //
    let unencrypted_aes_key = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    send_encrypted_tx(
        &api,
        &provider,
        from,
        contract_addr,
        &encryption_sk,
        encryption_pk.clone(),
        &unencrypted_aes_key,
        /* encryption_nonce */ 1,
    ).await;

    //
    // 3. Tx #2: Encrypt & send "hello world"
    //
    let message = Bytes::from("hello world");
    type PlaintextType = Bytes; // used for AbiEncode / AbiDecode

    let encoded_message = PlaintextType::abi_encode(&message);
    let unencrypted_input =
        concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded_message.into());
    let receipt = send_encrypted_tx(
        &api,
        &provider,
        from,
        contract_addr,
        &encryption_sk,
        encryption_pk.clone(),
        &unencrypted_input,
        /* encryption_nonce */ 2,
    ).await;

    //
    // 4. Tx #3: On-chain decrypt
    //
    let logs = receipt.inner.inner.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].inner.address, contract_addr);

    // Decode the EncryptedMessage event
    let log_data = logs[0].inner.data.clone();
    let event = Event {
        name: "EncryptedMessage".into(),
        inputs: vec![
            EventParam { ty: "int96".into(), indexed: true, ..Default::default() },
            EventParam { ty: "bytes".into(),  indexed: false, ..Default::default() },
        ],
        anonymous: false,
    };
    let decoded = event.decode_log(&log_data.into_log_data(), false).unwrap();

    sol! {
        #[derive(Debug, PartialEq)]
        interface Encryption {
            function decrypt(uint96 nonce, bytes calldata ciphertext)
                external
                view
                onlyOwner
                returns (bytes memory plaintext);
        }
    }

    // Extract (nonce, ciphertext)
    let nonce: U96 = U96::from_be_bytes(
        B96::from_slice(&decoded.indexed[0].abi_encode_packed()).into()
    );
    let ciphertext = Bytes::from(decoded.body[0].abi_encode_packed());

    let call = Encryption::decryptCall { nonce, ciphertext: ciphertext.clone() };
    let unencrypted_decrypt_call = call.abi_encode();

    // Perform the read call with encryption
    let output = seismic_read_call(
        &api,
        &provider,
        from,
        contract_addr,
        &encryption_sk,
        encryption_pk_write_tx,
        &unencrypted_decrypt_call,
        /* encryption_nonce */ 3,
    ).await;

    //
    // 5. Locally decrypt to cross-check
    //
    // 5a. AES decryption with your local private key
    let secp_private = secp256k1::SecretKey::from_slice(private_key.as_ref()).unwrap();
    let aes_key: &[u8; 32] = &secp_private.secret_bytes()[0..32].try_into().unwrap();
    let decrypted_locally =
        aes_decrypt(aes_key.into(), &ciphertext, decoded.indexed[0].abi_encode_packed())
            .expect("AES decryption failed");
    assert_eq!(decrypted_locally, message);

    // 5b. Decrypt the "output" from the read call
    let call_nonce = provider.get_transaction_count(from).await.unwrap();
    let decrypted_output =
        crypto::client_decrypt(&encryption_sk, output.as_ref(), call_nonce)
            .expect("client_decrypt of read-output failed");

    let result_bytes = PlaintextType::abi_decode(&Bytes::from(decrypted_output), false)
        .expect("failed to decode the bytes");
    let final_string = String::from_utf8(result_bytes.to_vec())
        .expect("invalid utf8 in decrypted bytes");

    assert_eq!(final_string, "hello world");
}
