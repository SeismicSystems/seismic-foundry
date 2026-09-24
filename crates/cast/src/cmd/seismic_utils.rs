//! Shared utilities for seismic transaction encryption in scast commands.

use alloy_consensus::BlockHeader;
use alloy_network::TransactionBuilder;
use alloy_primitives::{Bytes, aliases::U96};
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
/// Skips encryption if the input is empty (e.g. plain ETH transfers).
pub fn encrypt_tx_input(
    tx: &mut WithOtherFields<TransactionRequest>,
    original_input: &Bytes,
    network_pubkey: &PublicKey,
    encryption_sk: &SecretKey,
    sender: alloy_primitives::Address,
) -> Result<()> {
    if original_input.is_empty() {
        return Ok(());
    }

    let metadata = tx
        .metadata(sender)
        .map_err(|e| eyre::eyre!("Failed to create encryption metadata: {e}"))?;

    let encrypted_input = metadata
        .client_encrypt(original_input, network_pubkey, encryption_sk)
        .map_err(|e| eyre::eyre!("Failed to encrypt input data: {e}"))?;

    tx.inner.input = alloy_rpc_types::TransactionInput { input: Some(encrypted_input), data: None };
    Ok(())
}

pub use foundry_common::seismic::request_signed_gas_estimate;

/// Build a separately encrypted, call-only estimate from a plaintext write request.
fn prepare_signed_gas_estimate(
    tx: &WithOtherFields<TransactionRequest>,
    block_gas_limit: u64,
    network_pubkey: &PublicKey,
    encryption_sk: &SecretKey,
) -> Result<WithOtherFields<TransactionRequest>> {
    let mut estimate = tx.clone();
    let elements = estimate
        .seismic_elements
        .as_mut()
        .ok_or_else(|| eyre::eyre!("Missing seismic elements for gas estimation"))?;
    elements.signed_read = true;
    // signed_read is authenticated metadata. Encrypt again with a fresh nonce:
    // reusing the write's AES-GCM key/nonce with different AAD is unsafe.
    elements.encryption_nonce = U96::random();
    estimate.set_gas_limit(block_gas_limit);
    let sender = tx.from.ok_or_else(|| eyre::eyre!("Missing sender for gas estimation"))?;
    let input = tx.inner.input.input().unwrap_or_default();
    encrypt_tx_input(&mut estimate, input, network_pubkey, encryption_sk, sender)?;
    Ok(estimate)
}

/// Estimate a plaintext seismic write using a separate signed-read payload.
/// Only the gas limit is updated; the caller must encrypt the write afterward.
/// Falls back to `block_gas_limit` if estimation fails.
pub async fn estimate_gas_signed<P: Provider<AnyNetwork>>(
    provider: &P,
    tx: &mut WithOtherFields<TransactionRequest>,
    wallet: &EthereumWallet,
    block_gas_limit: u64,
    network_pubkey: &PublicKey,
    encryption_sk: &SecretKey,
) -> Result<()> {
    let tx_for_estimate =
        prepare_signed_gas_estimate(tx, block_gas_limit, network_pubkey, encryption_sk)?;

    match request_signed_gas_estimate(provider, &tx_for_estimate, wallet).await {
        Ok(gas_limit) => tx.set_gas_limit(gas_limit),
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, TxKind, U256};
    use alloy_provider::ProviderBuilder;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_transport::mock::Asserter;

    const BLOCK_GAS_LIMIT: u64 = 30_000_000;

    fn plaintext_write(sender: Address, input: Bytes) -> WithOtherFields<TransactionRequest> {
        let mut tx = WithOtherFields::<TransactionRequest>::default();
        tx.set_from(sender);
        tx.set_chain_id(5124);
        tx.set_nonce(7);
        tx.set_to(Address::repeat_byte(0x22));
        tx.set_value(U256::from(123));
        tx.set_gas_price(1_000_000_000);
        TransactionBuilder::set_input(&mut tx, input);
        let encryption_sk = SecretKey::from_slice(&[1; 32]).unwrap();
        prepare_seismic_fields(
            &mut tx,
            TxSeismicElements {
                encryption_pubkey: PublicKey::from_secret_key(&Secp256k1::new(), &encryption_sk),
                encryption_nonce: U96::from(42),
                recent_block_hash: B256::repeat_byte(0x33),
                expires_at_block: 100,
                signed_read: false,
                ..Default::default()
            },
        );
        tx
    }

    #[test]
    fn test_seismic_gas_estimate_separates_read_and_write_encryption() {
        let encryption_sk = SecretKey::from_slice(&[1; 32]).unwrap();
        let network_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let network_pk = PublicKey::from_secret_key(&Secp256k1::new(), &network_sk);
        let sender = Address::repeat_byte(0x11);

        // Cover ordinary calls, contract creation, and empty-calldata transfers.
        for to in [TxKind::Call(Address::repeat_byte(0x22)), TxKind::Create] {
            for input in [Bytes::from_static(b"calldata"), Bytes::new()] {
                let mut write = plaintext_write(sender, input.clone());
                write.set_kind(to);
                let original = write.clone();
                let estimate = prepare_signed_gas_estimate(
                    &write,
                    BLOCK_GAS_LIMIT,
                    &network_pk,
                    &encryption_sk,
                )
                .unwrap();

                assert_eq!(write, original);
                assert_eq!(estimate.gas_limit(), Some(BLOCK_GAS_LIMIT));
                let read_metadata = estimate.metadata(sender).unwrap();
                let write_metadata = write.metadata(sender).unwrap();
                assert!(read_metadata.seismic_elements.signed_read);
                assert!(!write_metadata.seismic_elements.signed_read);
                assert_ne!(
                    read_metadata.seismic_elements.encryption_nonce,
                    write_metadata.seismic_elements.encryption_nonce,
                );
                let mut expected_metadata = write_metadata.clone();
                expected_metadata.seismic_elements.signed_read = true;
                expected_metadata.seismic_elements.encryption_nonce =
                    read_metadata.seismic_elements.encryption_nonce;
                assert_eq!(read_metadata, expected_metadata);

                let read_input = estimate.inner.input.input().unwrap();
                assert_eq!(
                    read_metadata.decrypt_request(&network_sk, read_input).unwrap(),
                    input.as_ref(),
                );

                // This is the send path: only after estimation do we encrypt the write.
                write.set_gas_limit(50_000);
                encrypt_tx_input(&mut write, &input, &network_pk, &encryption_sk, sender).unwrap();
                assert_eq!(write.metadata(sender).unwrap(), write_metadata);
                let write_input = write.inner.input.input().unwrap();
                assert_eq!(
                    write_metadata.decrypt_request(&network_sk, write_input).unwrap(),
                    input.as_ref(),
                );
                if !input.is_empty() {
                    assert_ne!(read_input, write_input);
                    // Merely flipping the flag after encryption must not authenticate.
                    let mut wrong_metadata = read_metadata;
                    wrong_metadata.seismic_elements.signed_read = false;
                    assert!(wrong_metadata.decrypt_request(&network_sk, read_input).is_err());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_seismic_gas_estimate_only_updates_write_gas() {
        let encryption_sk = SecretKey::from_slice(&[1; 32]).unwrap();
        let network_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let network_pk = PublicKey::from_secret_key(&Secp256k1::new(), &network_sk);
        let signer = PrivateKeySigner::random();
        let sender = signer.address();
        let wallet = EthereumWallet::from(signer);

        for succeeds in [true, false] {
            let asserter = Asserter::new();
            if succeeds {
                asserter.push_success(&U256::from(50_000));
            } else {
                asserter.push_failure_msg("estimation unavailable");
            }
            let provider = ProviderBuilder::<_, _, AnyNetwork>::default()
                .connect_mocked_client(asserter.clone());
            let mut tx = plaintext_write(sender, Bytes::from_static(b"calldata"));
            let mut expected = tx.clone();
            expected.set_gas_limit(if succeeds { 50_000 } else { BLOCK_GAS_LIMIT });

            estimate_gas_signed(
                &provider,
                &mut tx,
                &wallet,
                BLOCK_GAS_LIMIT,
                &network_pk,
                &encryption_sk,
            )
            .await
            .unwrap();

            assert_eq!(tx, expected);
            assert!(asserter.read_q().is_empty(), "estimate must reach the RPC transport");
        }
    }
}
