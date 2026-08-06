use alloy_consensus::TxEip1559;
use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::{TransactionBuilder, eip2718::Encodable2718};
use alloy_primitives::{
    Address, B256, Bytes, IntoLogData, TxKind, U256,
    aliases::{B96, U96},
    hex::{self, FromHex},
};
use alloy_provider::{Provider, SendableTx};
use alloy_rpc_types::{
    TransactionInput, TransactionRequest as AlloyTransactionRequest, state::EvmOverrides,
};
use alloy_serde::WithOtherFields;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolValue, sol};
use anvil::{NodeConfig, spawn};
use secp256k1::{PublicKey, SecretKey};
use seismic_crypto::{AesKeyDomain, aes_decrypt, ecdh_decrypt_aead};
use std::{fs, str::FromStr};

use seismic_prelude::foundry::{
    AnyNetwork, AnyTxEnvelope, EthereumWallet, SeismicCallExt, SeismicCallRequest,
    SeismicProviderBuilder, SeismicProviderExt, ShieldedCallExt, SignedProviderExt, SimBlock,
    SimulatePayload, TransactionRequest, TxLegacyFields, TxSeismic, TxSeismicElements,
    TxSeismicMetadata, TypedDataRequest, test_utils, tx_builder,
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

pub fn get_seismic_elements(signed_read: bool) -> TxSeismicElements {
    let encryption_sk = get_encryption_private_key();
    let encryption_pk = PublicKey::from_secret_key_global(&encryption_sk);
    let encryption_nonce = get_encryption_nonce();
    TxSeismicElements {
        encryption_pubkey: encryption_pk,
        encryption_nonce,
        message_version: 0,
        recent_block_hash: B256::ZERO,
        expires_at_block: u64::MAX,
        signed_read,
    }
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
    signed_read: bool,
) -> TransactionRequest {
    let sender = signer.address();
    let seismic_elements = get_seismic_elements(signed_read);
    let value = U256::from(0);

    // Create metadata for encryption
    let legacy_fields = TxLegacyFields { chain_id, nonce, to, value };
    let metadata =
        TxSeismicMetadata { sender, legacy_fields, seismic_elements: seismic_elements.clone() };

    let encrypted_input = seismic_elements
        .client_encrypt(&plaintext, &pk, &get_encryption_private_key(), &metadata)
        .unwrap();

    TransactionRequest {
        inner: AlloyTransactionRequest {
            from: Some(sender),
            nonce: Some(nonce),
            value: Some(value),
            to: Some(to),
            gas: Some(6000000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(Bytes::from(encrypted_input)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            ..Default::default()
        },
        seismic_elements: Some(seismic_elements),
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
    signed_read: bool,
) -> TypedDataRequest {
    let sender = signer.address();
    let mut seismic_elements = get_seismic_elements(signed_read);
    seismic_elements = seismic_elements.with_message_version(2);

    let gas_limit = 6000000;
    let gas_price = 20e9 as u128;
    let value = U256::from(0);

    // Create metadata for encryption with correct message_version
    let legacy_fields = TxLegacyFields { chain_id, nonce, to, value };
    let metadata =
        TxSeismicMetadata { sender, legacy_fields, seismic_elements: seismic_elements.clone() };

    let encrypted_input = seismic_elements
        .client_encrypt(&plaintext, &pk, &get_encryption_private_key(), &metadata)
        .unwrap();

    let tx = TransactionRequest {
        inner: AlloyTransactionRequest {
            from: Some(sender),
            nonce: Some(nonce),
            value: Some(value),
            to: Some(to),
            gas: Some(gas_limit),
            gas_price: Some(gas_price),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(Bytes::from(encrypted_input)), data: None },
            transaction_type: Some(TxSeismic::TX_TYPE),
            ..Default::default()
        },
        seismic_elements: Some(seismic_elements),
    };

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
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let url = handle.http_endpoint().as_str().parse().unwrap();
    let unsigned_provider = SeismicProviderBuilder::new().foundry().connect_http(url);
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

    let mut call_req = tx_builder()
        .with_from(deployer)
        .with_kind(TxKind::Create)
        .with_input(plaintext_bytecode.clone())
        .into();
    call_req.transaction_type = Some(TxEip1559::tx_type().into());
    println!("Call req: {:?}", call_req);
    // send a call bytes
    let res = provider.seismic_call_raw(SendableTx::Builder(call_req.into())).await.unwrap();
    assert_eq!(res, test_utils::ContractTestContext::get_code());

    // send a unsigned call
    let res = unsigned_provider
        .call(
            tx_builder()
                .with_kind(TxKind::Create)
                .with_input(plaintext_bytecode.clone())
                .into()
                .into(),
        )
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
                false,
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
                    true,
                )
                .await,
            ),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();

    // Create metadata for decryption (matching the encrypted call with message_version: 2)
    let seismic_elements = get_seismic_elements(true).with_message_version(2);
    let nonce = provider.get_transaction_count(deployer).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let legacy_fields = TxLegacyFields { chain_id, nonce, to: TxKind::Create, value: U256::ZERO };
    let metadata = TxSeismicMetadata {
        sender: deployer,
        legacy_fields,
        seismic_elements: seismic_elements.clone(),
    };

    let decrypted = seismic_elements
        .client_decrypt(&res, &network_pubkey, &get_encryption_private_key(), &metadata)
        .unwrap();
    assert_eq!(Bytes::from(decrypted), test_utils::ContractTestContext::get_code());
    assert!(
        ecdh_decrypt_aead(
            &network_pubkey,
            &get_encryption_private_key(),
            AesKeyDomain::TxRequest,
            &res,
            seismic_elements.get_enclave_nonce(),
            &metadata.encode_as_aad(),
        )
        .is_err(),
        "signed-read response must not decrypt with the request traffic key"
    );

    let chain_id = provider.get_chain_id().await.unwrap();

    // unsigned seismic estimate_gas should fail after sanitization because the
    // request no longer carries authenticated caller metadata.
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
                    true,
                )
                .await,
            )
            .into(),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap_err();
    // Sanitization cleared `from`, so the request should fail because the
    // sender is missing — confirming the attacker-supplied `from` was not used.
    let err_str = gas_estimate.to_string();
    assert!(
        err_str.contains("sender") || err_str.contains("from"),
        "expected sender-related error after sanitization, got: {err_str}"
    );

    let signed_call = sign_tx(
        signer.clone(),
        get_unsigned_seismic_tx_request(
            &signer,
            &network_pubkey,
            provider.get_transaction_count(deployer).await.unwrap(),
            TxKind::Call(contract_address),
            chain_id,
            test_utils::ContractTestContext::get_is_odd_input_plaintext(),
            true,
        )
        .await,
    )
    .await;
    let signed_gas_estimate = api
        .estimate_gas(
            SeismicCallRequest::Bytes(Bytes::from(signed_call.encoded_2718())),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();
    assert!(signed_gas_estimate > U256::ZERO);
}

/// Regression test for privacy-preserving unsigned call sanitization.
///
/// A transparent payable call depends on authenticated `from`/`value`
/// semantics. Unsigned `eth_call` and `eth_estimateGas` requests are sanitized
/// on Seismic, so they should fail against a contract that gates on `msg.value`.
/// The same request should succeed when submitted as signed raw transaction
/// bytes, because the node can recover the real sender and preserve the
/// original call context.
#[tokio::test(flavor = "multi_thread")]
async fn test_payable_call_and_estimate_gas_require_signed_request() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();

    // Minimal payable contract:
    // - any call with msg.value >= 1 ether succeeds
    // - any call with msg.value < 1 ether reverts
    //
    // Init code copies the runtime and returns it.
    let payable_gate_bytecode = Bytes::from(
        hex::decode("6015600c60003960156000f3670de0b6b3a76400003410600f57005b60006000fd").unwrap(),
    );
    let deploy_hash = provider
        .send_transaction(
            tx_builder()
                .with_from(deployer)
                .with_kind(TxKind::Create)
                .with_input(payable_gate_bytecode)
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .transaction_hash;
    let receipt = provider.get_transaction_receipt(deploy_hash).await.unwrap().unwrap();
    let contract_address = receipt.contract_address.unwrap();
    let calldata = Bytes::default();

    let chain_id = provider.get_chain_id().await.unwrap();
    let deposit_value = U256::from(32_000_000_000_000_000_000u128);
    let mut unsigned_request = TransactionRequest {
        inner: AlloyTransactionRequest {
            from: Some(signer.address()),
            nonce: Some(0),
            value: Some(deposit_value),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(6_000_000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(calldata.clone()), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };

    let unsigned_call_err = api
        .call(WithOtherFields::new(unsigned_request.clone()), None, EvmOverrides::default())
        .await
        .unwrap_err();
    let unsigned_call_err_str = unsigned_call_err.to_string();
    assert!(!unsigned_call_err_str.is_empty(), "expected unsigned eth_call to fail");

    let unsigned_err = api
        .estimate_gas(WithOtherFields::new(unsigned_request).into(), None, EvmOverrides::default())
        .await
        .unwrap_err();
    let err_str = unsigned_err.to_string();
    assert!(!err_str.is_empty(), "expected unsigned estimate_gas to fail");

    let signed_request = TransactionRequest {
        inner: AlloyTransactionRequest {
            from: Some(signer.address()),
            nonce: Some(provider.get_transaction_count(deployer).await.unwrap()),
            value: Some(deposit_value),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(6_000_000),
            gas_price: Some(20e9 as u128),
            chain_id: Some(chain_id),
            input: TransactionInput { input: Some(calldata), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };

    let signed_call = sign_tx(signer.clone(), signed_request).await;
    let signed_call_result = api
        .call(
            SeismicCallRequest::Bytes(Bytes::from(signed_call.encoded_2718())),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();
    assert_eq!(signed_call_result, Bytes::default());

    let signed_gas_estimate = api
        .estimate_gas(
            SeismicCallRequest::Bytes(Bytes::from(signed_call.encoded_2718())),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();
    assert!(signed_gas_estimate > U256::ZERO);
}

/// Tests that the RNG precompile produces different output for different transactions.
///
/// This is a regression test for a bug where `SeismicTransaction::new()` defaulted
/// `tx_hash` to `B256::ZERO`, causing the RNG precompile to use the same seed for
/// every transaction and produce identical "random" output.
///
/// The test deploys a minimal contract that calls the RNG precompile and stores the
/// result, then sends two separate transactions and verifies they get different values.
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_rng_different_per_transaction() {
    // Spin up node with auto-mine
    let (_api, handle) = spawn(NodeConfig::test()).await;
    let wallet = EthereumWallet::new(handle.dev_wallets().next().unwrap().clone());
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(wallet)
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();

    // Minimal contract: on any call, STATICCALLs the RNG precompile (0x64)
    // requesting 32 random bytes, stores the result in slot 0, increments a
    // call counter in slot 1, and returns the result.
    //
    // Solidity equivalent:
    //   contract RngCaller {
    //       bytes32 public lastRng;
    //       uint256 public callCount;
    //       fallback() external {
    //           (bool ok, bytes memory result) = address(0x64).staticcall(hex"00000020");
    //           require(ok);
    //           lastRng = bytes32(result);
    //           callCount++;
    //           assembly { return(add(result, 32), mload(result)) }
    //       }
    //   }
    //
    // Bytecode: 12-byte deploy prefix + 45-byte runtime.
    let deploy_code = hex::decode(
        "602d600c600039602d6000f3\
         6300000020600052602060006004601c60645afa50600051806000556001546001016001556000526020\
         6000f3",
    )
    .unwrap();
    let bytecode = Bytes::from(deploy_code);
    let tx_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(bytecode).into();
    let contract_addr = provider
        .send_transaction(tx_req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    // Deploy a second instance of the same contract (identical bytecode)
    let deploy_code_2 = hex::decode(
        "602d600c600039602d6000f3\
         6300000020600052602060006004601c60645afa50600051806000556001546001016001556000526020\
         6000f3",
    )
    .unwrap();
    let contract_addr_2 = provider
        .send_transaction(
            tx_builder()
                .with_from(deployer)
                .with_kind(TxKind::Create)
                .with_input(Bytes::from(deploy_code_2))
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    // Call contract 1 — triggers RNG precompile, stores result in slot 0
    let receipt_a = provider
        .send_transaction(
            tx_builder()
                .with_from(deployer)
                .with_to(contract_addr)
                .with_input(Bytes::new())
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt_a.inner.inner.status(), "Call A should succeed");

    // Call contract 2 — same code, different transaction
    let receipt_b = provider
        .send_transaction(
            tx_builder()
                .with_from(deployer)
                .with_to(contract_addr_2)
                .with_input(Bytes::new())
                .into()
                .into(),
        )
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt_b.inner.inner.status(), "Call B should succeed");

    // Read the stored RNG values from each contract's slot 0
    let rng_a = provider.get_storage_at(contract_addr, U256::from(0)).await.unwrap();
    let rng_b = provider.get_storage_at(contract_addr_2, U256::from(0)).await.unwrap();

    // Both should be non-zero
    assert_ne!(rng_a, U256::ZERO, "RNG output A should not be zero");
    assert_ne!(rng_b, U256::ZERO, "RNG output B should not be zero");

    // The key assertion: different transactions should produce different RNG output.
    // Before the fix, both would be identical because tx_hash was always B256::ZERO.
    assert_ne!(
        rng_a, rng_b,
        "RNG precompile should produce different output for different transactions. \
         If equal, tx_hash is likely not being propagated to the EVM."
    );
}

// Actual contract being tested:
// https://github.com/SeismicSystems/early-builds/blob/main/EIP7702_experiment/end-to-end-mvp/EncryptedLogs.sol
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_precompiles_end_to_end() {
    // Spin up node, get provider & deployer
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let wallet = EthereumWallet::new(handle.dev_wallets().next().unwrap().clone());
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(wallet)
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
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
        #[sol(rpc)]
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

    let encryption = Encryption::new(contract_addr, &provider);

    // .seismic().call() encrypts calldata, signs, decrypts response, and ABI-decodes
    let plaintext = encryption.decrypt(nonce, ciphertext.clone()).seismic().call().await.unwrap();

    // 5. Locally decrypt to cross-check
    // 5a. AES decryption with your local private key
    let secp_private = secp256k1::SecretKey::from_slice(private_key.as_ref()).unwrap();
    let aes_key: &[u8; 32] = &secp_private.secret_bytes()[0..32].try_into().unwrap();
    let nonce: [u8; 12] = decoded.indexed[0].abi_encode_packed().try_into().unwrap();
    let decrypted_locally =
        aes_decrypt(aes_key.into(), &ciphertext, nonce).expect("AES decryption failed");
    assert_eq!(decrypted_locally, message);

    // 5b. Verify the seismic_call result matches
    let final_string =
        String::from_utf8(plaintext.to_vec()).expect("invalid utf8 in decrypted bytes");

    assert_eq!(final_string, "hello world");
}

// Seismic fork tests
//
// Seismic equivalents of the upstream mainnet fork tests (which are
// #[ignore]'d because they need Ethereum mainnet RPCs). These fork the
// Seismic testnet instead, verifying that sanvil can fork a Seismic chain.

/// Seismic testnet RPC endpoint for fork tests.
const SEISMIC_TESTNET_RPC: &str = "https://testnet-1.seismictest.net/rpc";
/// Chain ID of the Seismic testnet.
const SEISMIC_TESTNET_CHAIN_ID: u64 = 5124;
/// Block number to fork from in fork tests (early block to minimize RPC data).
const SEISMIC_FORK_BLOCK_NUMBER: u64 = 1000;

fn seismic_fork_config() -> NodeConfig {
    NodeConfig::test()
        .with_eth_rpc_url(Some(SEISMIC_TESTNET_RPC.to_string()))
        .with_fork_block_number(Some(SEISMIC_FORK_BLOCK_NUMBER))
}

/// Tests that sanvil can fork the Seismic testnet and reports the correct chain ID.
/// Also verifies that --chain-id overrides the fork chain ID.
/// Seismic equivalent of: genesis::chain_id_precedence (fork scenarios)
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_fork_chain_id() {
    let (_api, handle) = spawn(seismic_fork_config()).await;
    let provider = handle.http_provider();
    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, SEISMIC_TESTNET_CHAIN_ID);

    let (_api, handle) = spawn(seismic_fork_config().with_chain_id(Some(99999u64))).await;
    let provider = handle.http_provider();
    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 99999u64);
}

/// Tests that sanvil forks at the correct block number and can read block data.
/// Seismic equivalent of: traces::test_trace_address_fork (basic fork state)
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_fork_block_number() {
    let (api, _handle) = spawn(seismic_fork_config()).await;
    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, U256::from(SEISMIC_FORK_BLOCK_NUMBER));

    let block = api
        .block_by_number(alloy_eips::BlockNumberOrTag::Number(SEISMIC_FORK_BLOCK_NUMBER))
        .await
        .unwrap();
    assert!(block.is_some());
}

/// Tests that sanvil can send transactions on a forked Seismic chain.
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_fork_send_tx() {
    let (_api, handle) = spawn(seismic_fork_config()).await;
    let provider = handle.http_provider();

    let from = handle.dev_wallets().next().unwrap().address();
    let to = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    let tx = AlloyTransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_value(U256::from(1e18 as u64));
    let tx = WithOtherFields::new(tx.into());

    let receipt = provider.send_transaction(tx).await.unwrap().get_receipt().await.unwrap();
    assert!(receipt.inner.inner.status());

    let balance = provider.get_balance(to).await.unwrap();
    assert_eq!(balance, U256::from(1e18 as u64));
}

// The probe bytecode below is stock-Solidity *source* (no ssolc builtin — only `staticcall(0x6A)`),
// compiled with the Seismic `solc` build. Sources + reproduce command: fixtures/TxTypeProbe.sol,
// fixtures/TxTypeWriteProbe.sol, fixtures/README.md.

// record() [266cf109] staticcalls 0x6A and stores the returned tx type into slot 0 (public
// `lastType`), so a mined transaction records the type it actually executed as.
// Source: fixtures/TxTypeWriteProbe.sol.
const TXTYPE_WRITE_PROBE_DEPLOY: &str = "6080604052348015600e575f5ffd5b506102da8061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c8063266cf109146100385780639f9a32b014610042575b5f5ffd5b610040610060565b005b61004a610132565b604051610057919061014f565b60405180910390f35b5f5f606a73ffffffffffffffffffffffffffffffffffffffff1660405161008690610195565b5f60405180830381855afa9150503d805f81146100be576040519150601f19603f3d011682016040523d82523d5f602084013e6100c3565b606091505b50915091508180156100d6575060208151145b610115576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161010c90610203565b60405180910390fd5b80806020019051810190610129919061024f565b5f819055505050565b5f5481565b5f819050919050565b61014981610137565b82525050565b5f6020820190506101625f830184610140565b92915050565b5f81905092915050565b50565b5f6101805f83610168565b915061018b82610172565b5f82019050919050565b5f61019f82610175565b9150819050919050565b5f82825260208201905092915050565b7f54585f494e464f000000000000000000000000000000000000000000000000005f82015250565b5f6101ed6007836101a9565b91506101f8826101b9565b602082019050919050565b5f6020820190508181035f83015261021a816101e1565b9050919050565b5f5ffd5b61022e81610137565b8114610238575f5ffd5b50565b5f8151905061024981610225565b92915050565b5f6020828403121561026457610263610221565b5b5f6102718482850161023b565b9150509291505056fea26469706673582212206e8df44b04233b7c69b57234ad9f2d6fa3f240f6512547ba3e690e90dec3bd4364736f6c63782c302e382e33312d646576656c6f702e323032362e372e32302b636f6d6d69742e66643566333839632e6d6f64005d";

// A probe that staticcalls the 0x6A tx-type precompile (source: fixtures/TxTypeProbe.sol):
//   isSeismic() [02ce8088]     -> txtype() == 0x4A
//   requireSeismic() [c6d819f6] -> reverts unless txtype() == 0x4A (74-specific, no decryption)
const TXTYPE_PROBE_DEPLOY: &str = "6080604052348015600e575f5ffd5b506103058061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c806302ce808814610038578063c6d819f614610056575b5f5ffd5b610040610060565b60405161004d9190610171565b60405180910390f35b61005e610071565b005b5f604a61006b610086565b14905090565b604a61007b610086565b14610084575f5ffd5b565b5f5f5f606a73ffffffffffffffffffffffffffffffffffffffff166040516100ad906101b7565b5f60405180830381855afa9150503d805f81146100e5576040519150601f19603f3d011682016040523d82523d5f602084013e6100ea565b606091505b50915091508180156100fd575060208151145b61013c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161013390610225565b60405180910390fd5b80806020019051810190610150919061027a565b9250505090565b5f8115159050919050565b61016b81610157565b82525050565b5f6020820190506101845f830184610162565b92915050565b5f81905092915050565b50565b5f6101a25f8361018a565b91506101ad82610194565b5f82019050919050565b5f6101c182610197565b9150819050919050565b5f82825260208201905092915050565b7f54585f494e464f000000000000000000000000000000000000000000000000005f82015250565b5f61020f6007836101cb565b915061021a826101db565b602082019050919050565b5f6020820190508181035f83015261023c81610203565b9050919050565b5f5ffd5b5f819050919050565b61025981610247565b8114610263575f5ffd5b50565b5f8151905061027481610250565b92915050565b5f6020828403121561028f5761028e610243565b5b5f61029c84828501610266565b9150509291505056fea26469706673582212204924f4189084c792361d86e18baf71dcadcfd5b6f8088b4caf833e2180d75aff64736f6c63782c302e382e33312d646576656c6f702e323032362e372e32302b636f6d6d69742e66643566333839632e6d6f64005d";

/// An unauthenticated eth_simulateV1 call carrying valid seismic ciphertext + elements but no
/// signature must NOT be classified as a Seismic tx. Otherwise txtype()/isSeismicTx() would
/// report an encrypted channel for a forged, unauthenticated read.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_unauthenticated_simulate_cannot_forge_seismic() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();
    let network_pubkey = provider.get_tee_pubkey().await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();

    let deploy_code = Bytes::from_hex(TXTYPE_PROBE_DEPLOY).unwrap();
    let deploy_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(deploy_code).into();
    let contract = provider
        .send_transaction(deploy_req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    // isSeismic() selector in a valid-but-unsigned seismic request (decryptable != authenticated).
    let is_seismic = Bytes::from_hex("02ce8088").unwrap();
    let forged = get_unsigned_seismic_tx_request(
        &signer,
        &network_pubkey,
        provider.get_transaction_count(deployer).await.unwrap(),
        TxKind::Call(contract),
        chain_id,
        is_seismic,
        true,
    )
    .await;

    let payload = SimulatePayload {
        block_state_calls: vec![SimBlock {
            block_overrides: None,
            state_overrides: None,
            calls: vec![forged.into()],
        }],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };
    let blocks = api.simulate_v1(payload, None).await.unwrap();
    let call = &blocks[0].calls[0];

    // Must actually execute (not a silent failure that would also decode to zero).
    assert!(call.status, "forged simulate call did not execute: {:?}", call.error);
    assert_eq!(call.return_data.len(), 32, "expected a 32-byte bool return");
    assert_eq!(
        U256::from_be_slice(call.return_data.as_ref()),
        U256::ZERO,
        "unauthenticated eth_simulateV1 forged txtype() == 74 (confidentiality bypass)"
    );
}

/// A signed estimate must run as a Seismic tx (`txtype() == 74`): `requireSeismic()` succeeds for
/// the signed read and reverts for the plain call. Regression test for the P2 estimator defect.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_signed_estimate_classifies_seismic() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();
    let network_pubkey = provider.get_tee_pubkey().await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();

    let deploy_code = Bytes::from_hex(TXTYPE_PROBE_DEPLOY).unwrap();
    let deploy_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(deploy_code).into();
    let contract = provider
        .send_transaction(deploy_req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    let require_seismic = Bytes::from_hex("c6d819f6").unwrap();
    let nonce = provider.get_transaction_count(deployer).await.unwrap();

    let signed = get_signed_seismic_tx_typed_data(
        &signer,
        &network_pubkey,
        nonce,
        TxKind::Call(contract),
        chain_id,
        require_seismic.clone(),
        true,
    )
    .await;
    let signed_res = api
        .estimate_gas(SeismicCallRequest::TypedData(signed), None, EvmOverrides::default())
        .await;
    assert!(
        signed_res.is_ok(),
        "signed estimate of requireSeismic() should succeed (txtype()==74), got {signed_res:?}"
    );

    let plain = TransactionRequest {
        inner: AlloyTransactionRequest {
            to: Some(TxKind::Call(contract)),
            input: TransactionInput { input: Some(require_seismic), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };
    let plain_res =
        api.estimate_gas(WithOtherFields::new(plain).into(), None, EvmOverrides::default()).await;
    assert!(
        plain_res.is_err(),
        "plain estimate of requireSeismic() should revert (txtype()!=74), but it succeeded"
    );
}

/// End-to-end through the real state-changing path (not eth_call/estimate): a mined type-74
/// transaction that executes a contract calling the 0x6A precompile records `txtype() == 74` into
/// storage; a mined standard (EIP-1559) transaction records its own type instead.
#[tokio::test(flavor = "multi_thread")]
async fn test_txtype_precompile_via_mined_write() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();
    let network_pubkey = provider.get_tee_pubkey().await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();

    // Deploy the write probe.
    let deploy_code = Bytes::from_hex(TXTYPE_WRITE_PROBE_DEPLOY).unwrap();
    let deploy_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(deploy_code).into();
    let contract = provider
        .send_transaction(deploy_req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    let record = Bytes::from_hex("266cf109").unwrap();

    // A real mined type-74 seismic WRITE calling record() (signed_read = false).
    let write = get_signed_seismic_tx_typed_data(
        &signer,
        &network_pubkey,
        provider.get_transaction_count(deployer).await.unwrap(),
        TxKind::Call(contract),
        chain_id,
        record.clone(),
        false,
    )
    .await;
    let tx_hash = api.send_signed_typed_data_tx(write).await.unwrap();
    api.mine_one().await;
    assert!(
        provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap().inner.inner.status(),
        "seismic write reverted"
    );
    let recorded_seismic = provider.get_storage_at(contract, U256::from(0)).await.unwrap();
    assert_eq!(
        recorded_seismic,
        U256::from(74),
        "a mined type-74 tx must record txtype() == 74, got {recorded_seismic}"
    );

    // A mined non-seismic WRITE calling record(): the node runs it as a legacy (type 0) tx, so the
    // precompile records 0 — the point is it is NOT classified as Seismic (74).
    let mut std_req = tx_builder()
        .with_from(deployer)
        .with_kind(TxKind::Call(contract))
        .with_input(record)
        .into();
    std_req.transaction_type = Some(TxEip1559::tx_type().into());
    assert!(
        provider
            .send_transaction(std_req.into())
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap()
            .inner
            .inner
            .status(),
        "standard write reverted"
    );
    let recorded_standard = provider.get_storage_at(contract, U256::from(0)).await.unwrap();
    assert_ne!(recorded_standard, U256::from(74), "a non-seismic tx must not record 74");
    assert_eq!(
        recorded_standard,
        U256::from(0),
        "a mined non-seismic tx records its executed (legacy) type 0, got {recorded_standard}"
    );
}

// A probe that staticcalls the 0x6A tx-context precompile with the 1-byte input `0x01`, which
// selects the `signed_read` flag rather than the tx type (source: fixtures/SignedReadProbe.sol):
//   requireSignedRead() [6cac1460] -> reverts unless signed_read == 1
//   flag()              [890eba68] -> returns signed_read
//   record()            [266cf109] -> stores signed_read into slot 0 (public `lastFlag`)
//   lastFlag()          [30b93e8a] -> getter for slot 0
const SIGNED_READ_PROBE_DEPLOY: &str = "6080604052348015600e575f5ffd5b506103708061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c8063266cf1091461004e57806330b93e8a146100585780636cac146014610076578063890eba6814610080575b5f5ffd5b61005661009e565b005b6100606100ad565b60405161006d91906101be565b60405180910390f35b61007e6100b2565b005b6100886100c7565b60405161009591906101be565b60405180910390f35b6100a66100d5565b5f81905550565b5f5481565b60016100bc6100d5565b146100c5575f5ffd5b565b5f6100d06100d5565b905090565b5f5f5f606a73ffffffffffffffffffffffffffffffffffffffff166040516100fc9061022b565b5f60405180830381855afa9150503d805f8114610134576040519150601f19603f3d011682016040523d82523d5f602084013e610139565b606091505b509150915081801561014c575060208151145b61018b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161018290610299565b60405180910390fd5b8080602001905181019061019f91906102e5565b9250505090565b5f819050919050565b6101b8816101a6565b82525050565b5f6020820190506101d15f8301846101af565b92915050565b5f81905092915050565b7f01000000000000000000000000000000000000000000000000000000000000005f82015250565b5f6102156001836101d7565b9150610220826101e1565b600182019050919050565b5f61023582610209565b9150819050919050565b5f82825260208201905092915050565b7f54585f434f4e54455854000000000000000000000000000000000000000000005f82015250565b5f610283600a8361023f565b915061028e8261024f565b602082019050919050565b5f6020820190508181035f8301526102b081610277565b9050919050565b5f5ffd5b6102c4816101a6565b81146102ce575f5ffd5b50565b5f815190506102df816102bb565b92915050565b5f602082840312156102fa576102f96102b7565b5b5f610307848285016102d1565b9150509291505056fea2646970667358221220101bd25bfa11faf3ccc49574e8137f87ec5a3b07ee24cd64928e43075479861364736f6c63782c302e382e33312d646576656c6f702e323032362e372e32302b636f6d6d69742e66643566333839632e6d6f64005d";

/// `signed_read` distinguishes an authenticated RPC read from a mined write — both are tx type 74,
/// so the type byte alone cannot tell them apart. Asserts the flag is true on the signed-read call
/// path and false everywhere else (mined type-74 write, plain unauthenticated call).
#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_signed_read_flag() {
    let (api, handle) = spawn(NodeConfig::test()).await;
    api.anvil_set_auto_mine(true).await.unwrap();
    let signer = handle.dev_wallets().next().unwrap();
    let provider = SeismicProviderBuilder::new()
        .foundry()
        .wallet(EthereumWallet::new(signer.clone()))
        .connect_http(reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap())
        .await
        .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();
    let network_pubkey = provider.get_tee_pubkey().await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();

    let deploy_code = Bytes::from_hex(SIGNED_READ_PROBE_DEPLOY).unwrap();
    let deploy_req =
        tx_builder().with_from(deployer).with_kind(TxKind::Create).with_input(deploy_code).into();
    let contract = provider
        .send_transaction(deploy_req.into())
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
        .contract_address
        .unwrap();

    let require_signed_read = Bytes::from_hex("6cac1460").unwrap();
    let flag = Bytes::from_hex("890eba68").unwrap();
    let record = Bytes::from_hex("266cf109").unwrap();

    // 1. An authenticated signed read must observe signed_read == 1.
    let signed = get_signed_seismic_tx_typed_data(
        &signer,
        &network_pubkey,
        provider.get_transaction_count(deployer).await.unwrap(),
        TxKind::Call(contract),
        chain_id,
        require_signed_read,
        true,
    )
    .await;
    let signed_res =
        api.call(SeismicCallRequest::TypedData(signed), None, EvmOverrides::default()).await;
    assert!(
        signed_res.is_ok(),
        "signed read of requireSignedRead() should succeed (signed_read == 1), got {signed_res:?}"
    );

    // 2. A plain unauthenticated eth_call is not a signed read. Its response comes back in
    //    plaintext, so assert the flag value directly rather than inferring it from a revert.
    let plain = TransactionRequest {
        inner: AlloyTransactionRequest {
            to: Some(TxKind::Call(contract)),
            input: TransactionInput { input: Some(flag), data: None },
            ..Default::default()
        },
        seismic_elements: None,
    };
    let plain_res = api
        .call(
            SeismicCallRequest::TransactionRequest(WithOtherFields::new(plain).into()),
            None,
            EvmOverrides::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        U256::from_be_slice(plain_res.as_ref()),
        U256::ZERO,
        "a plain unauthenticated eth_call must see signed_read == 0, got {plain_res}"
    );

    // 3. A mined type-74 WRITE is not a read: it must record signed_read == 0. This is the case the
    //    tx type byte cannot distinguish, since the write is also type 74.
    let write = get_signed_seismic_tx_typed_data(
        &signer,
        &network_pubkey,
        provider.get_transaction_count(deployer).await.unwrap(),
        TxKind::Call(contract),
        chain_id,
        record,
        false,
    )
    .await;
    let tx_hash = api.send_signed_typed_data_tx(write).await.unwrap();
    api.mine_one().await;
    assert!(
        provider.get_transaction_receipt(tx_hash).await.unwrap().unwrap().inner.inner.status(),
        "seismic write reverted"
    );
    let recorded = provider.get_storage_at(contract, U256::from(0)).await.unwrap();
    assert_eq!(
        recorded,
        U256::ZERO,
        "a mined type-74 write must record signed_read == 0, got {recorded}"
    );
}
