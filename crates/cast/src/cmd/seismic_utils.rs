//! Shared utilities for seismic transaction encryption in scast commands.

use alloy_consensus::BlockHeader;
use alloy_network::{TransactionBuilder, eip2718::Encodable2718};
use alloy_primitives::{Bytes, U256, aliases::U96};
use alloy_provider::Provider;
use alloy_rpc_types::BlockNumberOrTag;
use alloy_serde::WithOtherFields;
use eyre::Result;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use seismic_prelude::foundry::{
    AnyNetwork, EthereumWallet, InputDecryptionElements, TransactionRequest, TxSeismicElements,
};
use std::str::FromStr;

/// Fetch the latest block and create seismic elements with a real block hash.
/// Returns both the elements and the block gas limit (to avoid a duplicate RPC
/// call if gas estimation is needed later).
pub async fn create_seismic_elements<P: Provider<AnyNetwork>>(
    provider: &P,
    encryption_sk: &SecretKey,
    signed_read: bool,
) -> Result<(TxSeismicElements, u64)> {
    let secp = Secp256k1::new();
    let encryption_pk = PublicKey::from_secret_key(&secp, encryption_sk);
    let encryption_nonce = U96::random();

    let block = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .ok_or_else(|| eyre::eyre!("Failed to fetch latest block"))?;
    let header = &block.header;

    let elements = TxSeismicElements {
        encryption_pubkey: encryption_pk,
        encryption_nonce,
        message_version: 0,
        recent_block_hash: header.hash,
        expires_at_block: header.number() + 100,
        signed_read,
    };

    Ok((elements, header.gas_limit()))
}

/// Parse a hex-encoded private key or generate a random one.
pub fn get_or_generate_encryption_key(provided_key: Option<String>) -> Result<SecretKey> {
    match provided_key {
        Some(key_str) => {
            SecretKey::from_str(&key_str).map_err(|e| eyre::eyre!("Invalid private key: {e}"))
        }
        None => {
            let mut rng = rand::rng();
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            SecretKey::from_slice(&key_bytes)
                .map_err(|e| eyre::eyre!("Failed to generate random private key: {e}"))
        }
    }
}

/// Set seismic tx fields and convert EIP-1559 fees to legacy gas_price.
pub fn prepare_seismic_fields(
    tx: &mut WithOtherFields<TransactionRequest>,
    seismic_elements: TxSeismicElements,
) {
    tx.inner.transaction_type = Some(seismic_prelude::foundry::TxSeismic::TX_TYPE);
    tx.seismic_elements = Some(seismic_elements);

    if tx.inner.gas_price.is_none() {
        if let Some(max_fee) = tx.inner.max_fee_per_gas {
            tx.inner.gas_price = Some(max_fee);
        }
    }
    tx.inner.max_fee_per_gas = None;
    tx.inner.max_priority_fee_per_gas = None;
}

/// Encrypt the tx input using the same metadata() the server uses for decryption.
pub fn encrypt_tx_input(
    tx: &mut WithOtherFields<TransactionRequest>,
    original_input: &Bytes,
    network_pubkey: &PublicKey,
    encryption_sk: &SecretKey,
    sender: alloy_primitives::Address,
) -> Result<()> {
    let metadata = tx
        .metadata(sender)
        .map_err(|e| eyre::eyre!("Failed to create encryption metadata: {e}"))?;

    let encrypted_input = metadata
        .client_encrypt(original_input, network_pubkey, encryption_sk)
        .map_err(|e| eyre::eyre!("Failed to encrypt input data: {e}"))?;

    tx.inner.input = alloy_rpc_types::TransactionInput { input: Some(encrypted_input), data: None };
    Ok(())
}

/// Sign the tx and send raw bytes to eth_estimateGas.
/// Falls back to `block_gas_limit` if estimation fails.
pub async fn estimate_gas_signed<P: Provider<AnyNetwork>>(
    provider: &P,
    tx: &mut WithOtherFields<TransactionRequest>,
    wallet: &EthereumWallet,
    block_gas_limit: u64,
) -> Result<()> {
    let mut tx_for_estimate = tx.clone();
    tx_for_estimate.set_gas_limit(block_gas_limit);

    let signed = tx_for_estimate
        .build(wallet)
        .await
        .map_err(|e| eyre::eyre!("Failed to sign tx for gas estimation: {e:?}"))?;
    let encoded = Bytes::from(signed.encoded_2718());

    match provider.client().request::<_, U256>("eth_estimateGas", (encoded,)).await {
        Ok(gas) => {
            let gas_limit: u64 =
                gas.try_into().map_err(|_| eyre::eyre!("Gas estimate exceeds u64::MAX"))?;
            tx.set_gas_limit(gas_limit);
        }
        Err(e) => {
            sh_warn!(
                "Signed gas estimation failed ({e}), using block gas limit ({block_gas_limit}). \
                 Use --gas-limit for precise control."
            )?;
            tx.set_gas_limit(block_gas_limit);
        }
    }
    Ok(())
}
