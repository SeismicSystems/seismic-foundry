use alloy_consensus::TxEip1559;
use alloy_dyn_abi::EventExt;
use alloy_json_abi::{Event, EventParam};
use alloy_network::TransactionBuilder;
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
use alloy_sol_types::{SolCall, SolValue, sol};
use anvil::{NodeConfig, spawn};
use secp256k1::{PublicKey, SecretKey};
use seismic_enclave::aes_decrypt;
use std::{fs, str::FromStr};

use seismic_prelude::foundry::{
    AnyNetwork, AnyTxEnvelope, EthereumWallet, SeismicCallRequest, SeismicProviderExt,
    SeismicSignedProvider, SeismicUnsignedProvider, TransactionRequest, TxLegacyFields, TxSeismic,
    TxSeismicElements, TxSeismicMetadata, TypedDataRequest, test_utils, tx_builder,
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
    let provider = SeismicSignedProvider::new(
        EthereumWallet::new(signer.clone()),
        reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap(),
    )
    .await
    .unwrap();
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

    let mut call_req = tx_builder()
        .with_from(deployer)
        .with_kind(TxKind::Create)
        .with_input(plaintext_bytecode.clone())
        .into();
    call_req.transaction_type = Some(TxEip1559::tx_type().into());
    println!("Call req: {:?}", call_req);
    // send a call bytes
    let res = provider.seismic_call(SendableTx::Builder(call_req.into())).await.unwrap();
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
                    true,
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
    let provider = SeismicSignedProvider::new(
        wallet,
        reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap(),
    )
    .await
    .unwrap();
    let deployer = handle.dev_accounts().next().unwrap();

    // Deploy a minimal contract that:
    //   - On any call: STATICCALL the RNG precompile (0x64) requesting 32 bytes
    //   - Stores the result in storage slot 0
    //   - Increments a call counter in storage slot 1
    //   - Returns the RNG result
    //
    // Solidity equivalent:
    //   contract RngCaller {
    //       bytes32 public lastRng;
    //       uint256 public callCount;
    //       fallback() external {
    //           // Prepare input: 0x00000020 (32 bytes)
    //           bytes memory input = hex"00000020";
    //           (bool ok, bytes memory result) = address(0x64).staticcall(input);
    //           require(ok);
    //           lastRng = bytes32(result);
    //           callCount++;
    //           // Return the result
    //           assembly { return(add(result, 32), mload(result)) }
    //       }
    //   }
    //
    // Hand-assembled EVM bytecode for the runtime code:
    //   PUSH4 0x00000020  ; numBytes = 32
    //   PUSH0             ; memory offset 0
    //   MSTORE            ; mem[0..32] = 0x00000020 (right-padded)
    //   PUSH1 0x20        ; retSize = 32
    //   PUSH1 0x00        ; retOffset = 0
    //   PUSH1 0x04        ; argSize = 4 (first 4 bytes of memory = 00000020)
    //   PUSH1 0x1c        ; argOffset = 28 (bytes 28..32 of the word contain 00000020)
    //   PUSH1 0x64        ; address = 0x64 (RNG precompile)
    //   GAS               ; forward all gas
    //   STATICCALL         ; staticcall(gas, 0x64, 28, 4, 0, 32)
    //   POP               ; discard success flag
    //   PUSH0             ; offset 0
    //   MLOAD             ; load result from memory
    //   DUP1              ; duplicate for storage
    //   PUSH0             ; slot 0
    //   SSTORE            ; store lastRng
    //   PUSH1 0x01        ; slot 1
    //   SLOAD             ; load callCount
    //   PUSH1 0x01        ; increment
    //   ADD
    //   PUSH1 0x01        ; slot 1
    //   SSTORE            ; store callCount
    //   PUSH0             ; memory offset 0
    //   MSTORE            ; store result in memory for return
    //   PUSH1 0x20        ; return 32 bytes
    //   PUSH0             ; from offset 0
    //   RETURN
    // Runtime bytecodes concatenated into one hex string.
    // See comments above for opcode breakdown.
    // Uses PUSH1 0x00 instead of PUSH0 (0x5f) for compatibility.
    let runtime_code = hex::decode(concat!(
        "6300000020", // PUSH4 0x00000020
        "6000",       // PUSH1 0x00
        "52",         // MSTORE
        "6020",       // PUSH1 0x20 (retSize)
        "6000",       // PUSH1 0x00 (retOffset)
        "6004",       // PUSH1 0x04 (argSize)
        "601c",       // PUSH1 0x1c (argOffset = 28)
        "6064",       // PUSH1 0x64 (RNG precompile address)
        "5a",         // GAS
        "fa",         // STATICCALL
        "50",         // POP (discard success)
        "6000",       // PUSH1 0x00
        "51",         // MLOAD (load RNG result)
        "80",         // DUP1
        "6000",       // PUSH1 0x00
        "55",         // SSTORE (slot 0 = result)
        "6001",       // PUSH1 0x01
        "54",         // SLOAD (load counter)
        "6001",       // PUSH1 0x01
        "01",         // ADD
        "6001",       // PUSH1 0x01
        "55",         // SSTORE (slot 1 = counter)
        "6000",       // PUSH1 0x00
        "52",         // MSTORE
        "6020",       // PUSH1 0x20
        "6000",       // PUSH1 0x00
        "f3",         // RETURN
    ))
    .unwrap();

    // Deploy prefix: CODECOPY runtime to memory, then RETURN it.
    // The prefix is exactly 12 bytes, so runtime starts at offset 12.
    // CODECOPY pops (destOffset, offset, size) — push in reverse order.
    // RETURN pops (offset, size) — push in reverse order.
    let runtime_len = runtime_code.len() as u8;
    let mut deploy_code: Vec<u8> = vec![
        0x60,
        runtime_len, // PUSH1 <size>
        0x60,
        0x0c, // PUSH1 0x0c (offset = 12, where runtime starts in deploy code)
        0x60,
        0x00, // PUSH1 0x00 (destOffset in memory)
        0x39, // CODECOPY(destOffset=0, offset=12, size=runtime_len)
        0x60,
        runtime_len, // PUSH1 <size>
        0x60,
        0x00, // PUSH1 0x00 (offset)
        0xf3, // RETURN(offset=0, size=runtime_len)
    ];
    assert_eq!(deploy_code.len(), 12, "deploy prefix must be exactly 12 bytes");
    deploy_code.extend_from_slice(&runtime_code);

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

    // Deploy a second instance of the same contract
    let mut deploy_code_2 = vec![
        0x60,
        runtime_len, // PUSH1 size
        0x60,
        0x0c, // PUSH1 offset (12 = deploy prefix length)
        0x60,
        0x00, // PUSH1 destOffset
        0x39, // CODECOPY
        0x60,
        runtime_len, // PUSH1 size
        0x60,
        0x00, // PUSH1 offset
        0xf3, // RETURN
    ];
    deploy_code_2.extend_from_slice(&runtime_code);
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
    let provider = SeismicSignedProvider::new(
        wallet,
        reqwest::Url::parse(handle.http_endpoint().as_str()).unwrap(),
    )
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
    let unencrypted_decrypt_call = Bytes::from(call.abi_encode());

    // Create a seismic read call - provider will handle seismic_elements and metadata
    let tx_req = tx_builder()
        .with_from(from)
        .with_to(contract_addr)
        .with_input(unencrypted_decrypt_call)
        .into()
        .seismic();

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

// Seismic fork tests
//
// Seismic equivalents of the upstream mainnet fork tests (which are
// #[ignore]'d because they need Ethereum mainnet RPCs). These fork the
// Seismic testnet instead, verifying that sanvil can fork a Seismic chain.

/// Seismic testnet RPC endpoint for fork tests.
const SEISMIC_TESTNET_RPC: &str = "https://gcp-0.seismictest.net/rpc";
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
