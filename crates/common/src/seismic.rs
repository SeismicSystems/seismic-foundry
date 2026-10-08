//! Seismic-specific helpers shared across foundry tools.

use alloy_network::{TransactionBuilder, eip2718::Encodable2718};
use alloy_primitives::{Bytes, U256};
use alloy_provider::Provider;
use alloy_serde::WithOtherFields;
use eyre::Result;
use seismic_prelude::foundry::{AnyNetwork, EthereumWallet, TransactionRequest};

/// Sign the tx and send raw bytes to eth_estimateGas, returning the estimate.
///
/// The node sanitizes unsigned `eth_estimateGas` requests (clearing `from` to
/// prevent sender spoofing), which underprices any tx whose gas depends on
/// `msg.sender`. Raw signed bytes authenticate the sender cryptographically,
/// so the estimate runs against the real sender. Works for all tx types, not
/// just seismic ones.
///
/// The tx's gas limit should already be set (signing requires a fully formed
/// tx, so estimation itself needs a placeholder gas limit to sign with).
pub async fn request_signed_gas_estimate<P: Provider<AnyNetwork>>(
    provider: &P,
    tx: &WithOtherFields<TransactionRequest>,
    wallet: &EthereumWallet,
) -> Result<u64> {
    let signed = tx
        .clone()
        .build(wallet)
        .await
        .map_err(|e| eyre::eyre!("Failed to sign tx for gas estimation: {e:?}"))?;
    let encoded = Bytes::from(signed.encoded_2718());

    let gas = provider.client().request::<_, U256>("eth_estimateGas", (encoded,)).await?;
    gas.try_into().map_err(|_| eyre::eyre!("Gas estimate exceeds u64::MAX"))
}
