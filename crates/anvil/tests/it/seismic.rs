use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::TransactionBuilder;
use alloy_primitives::{
    aliases::{B96, U96},
    hex::{self, FromHex},
    Bytes, IntoLogData, TxKind, B256, U256,
};
use alloy_provider::{Provider, SendableTx};
use alloy_rpc_types::{
    state::EvmOverrides, TransactionInput, TransactionRequest as AlloyTransactionRequest,
};
use alloy_serde::WithOtherFields;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{sol, SolCall, SolValue};
use anvil::{spawn, NodeConfig};
use secp256k1::{PublicKey, SecretKey};
use seismic_enclave::aes_decrypt;
use std::{fs, str::FromStr};

use seismic_prelude::foundry::{
    test_utils, tx_builder, AnyNetwork, AnyTxEnvelope, EthereumWallet, SeismicCallRequest,
    SeismicProviderExt, SeismicSignedProvider, SeismicUnsignedProvider, TransactionRequest,
    TxSeismic, TxSeismicElements, TypedDataRequest,
};

// common utils
pub const TEST_PRECOMPILES_BYTECODE_PATH: &str = "/tests/it/seismic_precompiles_test_bytecode.txt";
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

pub fn get_encryption_nonce() -> U96 {
    U96::MAX
}

pub fn get_seismic_elements() -> TxSeismicElements {
    let encryption_sk = get_encryption_private_key();
    let encryption_pk = PublicKey::from_secret_key_global(&encryption_sk);
    let encryption_nonce = get_encryption_nonce();
    TxSeismicElements { encryption_pubkey: encryption_pk, encryption_nonce, message_version: 0 }
}

pub fn get_encryption_private_key() -> SecretKey {
    SecretKey::from_str("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("Invalid private key")
}

pub async fn get_unsigned_seismic_tx_request(
    signer: &PrivateKeySigner,
    pk: &PublicKey,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
) -> TransactionRequest {
    let encrypted_input = get_seismic_elements()
        .client_encrypt(&plaintext, &pk, &get_encryption_private_key())
        .unwrap();

    TransactionRequest {
        inner: AlloyTransactionRequest {
            from: Some(signer.address()),
            nonce: Some(nonce),
            value: Some(U256::from(0)),
            to: Some(to),
            gas: Some(6000000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(Bytes::from(encrypted_input)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            ..Default::default()
        },
        seismic_elements: Some(get_seismic_elements()),
    }
}

pub async fn sign_tx(wallet: PrivateKeySigner, tx: TransactionRequest) -> AnyTxEnvelope {
    let signer = EthereumWallet::from(wallet);
    <TransactionRequest as TransactionBuilder<AnyNetwork>>::build(tx, &signer).await.unwrap()
}

/// Create a seismic transaction with typed data
pub async fn get_signed_seismic_tx_typed_data(
    signer: &PrivateKeySigner,
    pk: &PublicKey,
    nonce: u64,
    to: TxKind,
    chain_id: u64,
    plaintext: Bytes,
) -> TypedDataRequest {
    let mut tx = get_unsigned_seismic_tx_request(signer, pk, nonce, to, chain_id, plaintext).await;
    tx.seismic_elements = Some(tx.seismic_elements.unwrap().with_message_version(2));

    let signed = sign_tx(signer.clone(), tx).await;

    match signed {
        AnyTxEnvelope::Seismic(tx) => tx.into(),
        _ => panic!("Signed transaction is not a seismic transaction"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_transaction_rpc() {
    // send a send_raw_transaction bytes
    // send a unsigned call with transactionrequest type
    // send a send_raw_transaction typeddata type
    // send a call bytes
    // send a call typeddata

    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicSignedProvider::new(
        EthereumWallet::new(signer.clone()),
        reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap(),
    );
    let url = handle.http_endpoint().as_str().parse().unwrap();
    let unsigned_provider = SeismicUnsignedProvider::<AnyNetwork>::new_http(url);
    let deployer = handle.dev_accounts().next().unwrap();
    let network_pubkey = provider.get_tee_pubkey().await.unwrap();

    let plaintext_bytecode = test_utils::ContractTestContext::get_deploy_input_plaintext();

    let req = tx_builder()
        .with_from(deployer)
        .with_kind(TxKind::Create)
        .with_input(plaintext_bytecode.clone())
        .into();
    // send a send_raw_transaction bytes
    let contract_address = provider
        .send_transaction(req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();
    let code = provider.get_code_at(contract_address).await.unwrap();
    assert_eq!(code, test_utils::ContractTestContext::get_code());

    // send a call bytes
    let res = provider
        .seismic_call(SendableTx::Builder(
            tx_builder()
                .with_from(deployer)
                .with_kind(TxKind::Create)
                .with_input(plaintext_bytecode.clone())
                .into()
                .into(),
        ))
        .await
        .unwrap();
    assert_eq!(res, test_utils::ContractTestContext::get_code());

    // send a unsigned call
    let res = unsigned_provider
        .seismic_call(SendableTx::Builder(
            tx_builder()
                .with_kind(TxKind::Create)
                .with_input(plaintext_bytecode.clone())
                .into()
                .into(),
        ))
        .await
        .unwrap();
    assert_eq!(res, test_utils::ContractTestContext::get_code());

    // send a signed typed data transaction
    let tx_hash = api
        .send_signed_typed_data_tx(
            get_signed_seismic_tx_typed_data(
                &signer,
                &network_pubkey,
                provider.get_transaction_count(deployer).await.unwrap(),
                TxKind::Create,
                provider.get_chain_id().await.unwrap(),
                plaintext_bytecode.clone(),
            )
            .await,
        )
        .await
        .unwrap();
    api.mine_one().await;
    let receipt = provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap();
    assert!(receipt.inner.inner.status());
    let code = provider.get_code_at(receipt.contract_address.unwrap()).await.unwrap();
    assert_eq!(code, test_utils::ContractTestContext::get_code());

    // a signed data call
    let res = api
        .call(
            SeismicCallRequest::TypedData(
                get_signed_seismic_tx_typed_data(
                    &signer,
                    &network_pubkey,
                    provider.get_transaction_count(deployer).await.unwrap(),
                    TxKind::Create,
                    provider.get_chain_id().await.unwrap(),
                    plaintext_bytecode.clone(),
                )
                .await,
            ),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();

    let decrypted = get_seismic_elements()
        .client_decrypt(&res, &network_pubkey, &get_encryption_private_key())
        .unwrap();
    assert_eq!(Bytes::from(decrypted), test_utils::ContractTestContext::get_code());

    let chain_id = provider.get_chain_id().await.unwrap();

    // estiamte gas
    let gas_estimate = api
        .estimate_gas(
            WithOtherFields::new(
                get_unsigned_seismic_tx_request(
                    &signer,
                    &network_pubkey,
                    2,
                    TxKind::Create,
                    chain_id,
                    plaintext_bytecode.clone(),
                )
                .await,
            ),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();
    assert!(gas_estimate > U256::ZERO);
}

// Actual contract being tested:
// https://github.com/SeismicSystems/early-builds/blob/main/EIP7702_experiment/end-to-end-mvp/EncryptedLogs.sol
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_precompiles_end_to_end() {
    // Spin up node, get provider & deployer
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let wallet = EthereumWallet::new(handle.dev_wallets().next().unwrap().clone());
    let provider = SeismicSignedProvider::new(
        wallet,
        reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap(),
    );
    let deployer = handle.dev_accounts().next().unwrap();

    // 1. Deploy test contract
    let bytecode = Bytes::from(load_bytecode_from_file(TEST_PRECOMPILES_BYTECODE_PATH));
    let tx_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(bytecode).into();

    let tx_result = provider.send_transaction(tx_req.into()).await.unwrap();

    let contract_addr = tx_result.get_receipt().await.unwrap().contract_address.unwrap();

    // Prepare addresses & keys
    let accounts: Vec<_> = handle.dev_wallets().collect();
    let from = accounts[0].address();
    let private_key =
        B256::from_hex("7e34abdcd62eade2e803e0a8123a0015ce542b380537eff288d6da420bcc2d3b").unwrap();

    //
    // 2. Tx #1: Set AES key in the contract
    //
    let unencrypted_aes_key = get_input_data(PRECOMPILES_TEST_SET_AES_KEY_SELECTOR, private_key);
    provider
        .send_transaction(
            tx_builder()
                .with_from(from)
                .with_to(contract_addr)
                .with_input(unencrypted_aes_key)
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    //
    // 3. Tx #2: Encrypt & send "hello world"
    //
    let message = Bytes::from("hello world");
    type PlaintextType = Bytes; // used for AbiEncode / AbiDecode

    let encoded_message = PlaintextType::abi_encode(&message);
    let unencrypted_input =
        concat_input_data(PRECOMPILES_TEST_ENCRYPTED_LOG_SELECTOR, encoded_message.into());

    let receipt = provider
        .send_transaction(
            tx_builder()
                .with_from(from)
                .with_to(contract_addr)
                .with_input(unencrypted_input)
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

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
            EventParam { ty: "uint96".into(), indexed: true, ..Default::default() },
            EventParam { ty: "bytes".into(), indexed: false, ..Default::default() },
        ],
        anonymous: false,
    };
    let decoded = event.decode_log(&log_data.into_log_data()).unwrap();

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
    let nonce: U96 =
        U96::from_be_bytes(B96::from_slice(&decoded.indexed[0].abi_encode_packed()).into());
    let ciphertext = Bytes::from(decoded.body[0].abi_encode_packed());

    let call = Encryption::decryptCall { nonce, ciphertext: ciphertext.clone() };
    let unencrypted_decrypt_call = call.abi_encode();

    let mut tx_req = tx_builder()
        .with_from(from)
        .with_to(contract_addr)
        .with_input(unencrypted_decrypt_call)
        .into();
    tx_req.inner.transaction_type = Some(TxSeismic::TX_TYPE);
    /*
    // TODO: seismic call with Builder does not work
    let mut tx_req = tx_builder()
        .with_from(from)
        .with_to(contract_addr)
        .with_input(unencrypted_decrypt_call)
        .into();
    tx_req.inner.transaction_type = Some(TxSeismic::TX_TYPE);
    tx_req.seismic_elements = Some(TxSeismicElements::default());

    let signed_tx = provider.sign_transaction(tx_req.into()).await.unwrap();
    let mut buf: &[u8] = signed_tx.iter().as_slice();
    let envelope = AnyTxEnvelope::decode_2718(&mut buf).unwrap();

    // Perform the read call with encryption
    let output = provider
        .seismic_call(SendableTx::Envelope(envelope))
        .await
        .unwrap();

    */

    // Perform the read call with encryption
    // TODO: seismic call with Builder does not work
    let output = provider.seismic_call(SendableTx::Builder(tx_req.into())).await.unwrap();

    //
    // 5. Locally decrypt to cross-check
    //
    // 5a. AES decryption with your local private key
    let secp_private = secp256k1::SecretKey::from_slice(private_key.as_ref()).unwrap();
    let aes_key: &[u8; 32] = &secp_private.secret_bytes()[0..32].try_into().unwrap();
    let nonce: [u8; 12] = decoded.indexed[0].abi_encode_packed().try_into().unwrap();
    let decrypted_locally =
        aes_decrypt(aes_key.into(), &ciphertext, nonce).expect("AES decryption failed");
    assert_eq!(decrypted_locally, message);

    // 5b. Decrypt the "output" from the read call
    let result_bytes =
        PlaintextType::abi_decode(&Bytes::from(output)).expect("failed to decode the bytes");
    let final_string =
        String::from_utf8(result_bytes.to_vec()).expect("invalid utf8 in decrypted bytes");

    assert_eq!(final_string, "hello world");
}
