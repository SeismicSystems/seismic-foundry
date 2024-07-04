use crate::utils::http_provider_with_signer;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{b256, hex::FromHex, Bytes, U128, U256};
use alloy_provider::Provider;
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use anvil::{spawn, NodeConfig};
use alloy_rlp::{Decodable, Encodable, Header, EMPTY_STRING_CODE};
use seismic_preimages::PreImageValue;
use anvil_core::eth::transaction::seismic::{SeismicTransactionFields, SecretData};

#[tokio::test(flavor = "multi_thread")]
async fn test_seismic_transaction_encoding() {
    let (_api, handle) = spawn(NodeConfig::test()).await;
    let provider = handle.http_provider();
    let accounts: Vec<_> = handle.dev_wallets().collect();
    let from = accounts[0].address();
    let to = accounts[1].address(); // should be a deployed contract address

    let tx = TransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_value(U256::from(1234))
        .with_gas_limit(21000);
    let tx = WithOtherFields {
        inner: tx,
        other: SeismicTransactionFields {
            secret_data: Some(vec![SecretData {
                index: 0,
                preimage: PreImageValue::Uint(1234),
                preimage_type: "uint16".to_string(),
                salt: Bytes::from_hex("0x0").unwrap(),
            }]),
        }
        .into(),
    };


    // mine block
    _api.evm_mine(None).await.unwrap();

    let receipt = provider.get_transaction_receipt(pending.tx_hash().to_owned()).await.unwrap().unwrap();
    assert_eq!(receipt.from, from);
    assert_eq!(receipt.to, Some(to));
}

