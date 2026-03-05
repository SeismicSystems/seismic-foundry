use crate::{
    ScriptArgs, ScriptConfig, build::LinkedBuildData, progress::ScriptProgress,
    sequence::ScriptSequenceKind, verify::BroadcastedState,
};
use alloy_chains::{Chain, NamedChain};
use alloy_consensus::TxEnvelope;
use alloy_eips::{BlockId, eip2718::Encodable2718};
use alloy_network::TransactionBuilder;
use alloy_primitives::{
    Address, TxHash,
    aliases::U96,
    map::{AddressHashMap, AddressHashSet},
    utils::format_units,
};
use alloy_provider::{Provider, utils::Eip1559Estimation};
use alloy_serde::WithOtherFields;
use eyre::{Context, Result, bail};
use forge_verify::provider::VerificationProviderType;
use foundry_cheatcodes::Wallets;
use foundry_cli::utils::{has_batch_support, has_different_gas_calc};
use foundry_common::{
    TransactionMaybeSigned,
    provider::{RetryProvider, get_http_provider, try_get_http_provider},
    shell,
};
use foundry_config::Config;
use futures::{StreamExt, future::join_all};
use itertools::Itertools;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::{cmp::Ordering, sync::Arc};

use seismic_prelude::foundry::{
    AnyNetwork, EthereumWallet, SeismicProviderExt, TransactionRequest, TxLegacyFields, TxSeismic,
    TxSeismicElements, TxSeismicMetadata,
};

/// Encrypts the calldata of a transaction and converts it to a TxSeismic (type 0x4a).
///
/// This is used when a transaction targets a function with shielded type parameters.
/// The calldata is encrypted using ECDH with the network's TEE public key.
fn encrypt_transaction_for_seismic(
    tx: &mut WithOtherFields<TransactionRequest>,
    network_pubkey: &PublicKey,
    recent_block_hash: alloy_primitives::B256,
    recent_block_number: u64,
) -> Result<()> {
    // Generate a random ephemeral encryption keypair
    let secp = Secp256k1::new();
    let encryption_sk = {
        let mut rng = rand::rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        SecretKey::from_slice(&key_bytes)
            .map_err(|e| eyre::eyre!("Failed to generate encryption key: {}", e))?
    };
    let encryption_pk = PublicKey::from_secret_key(&secp, &encryption_sk);
    let encryption_nonce = U96::random();

    let seismic_elements = TxSeismicElements {
        encryption_pubkey: encryption_pk,
        encryption_nonce,
        message_version: 0,
        recent_block_hash,
        expires_at_block: recent_block_number + 100,
        signed_read: false,
    };

    // Get the original calldata
    let original_input = tx.inner.inner.input.input().cloned().unwrap_or_default();

    // Build metadata for AEAD
    let from = tx.inner.inner.from.unwrap_or_default();
    let legacy_fields = TxLegacyFields {
        chain_id: tx.inner.inner.chain_id.unwrap_or_default(),
        nonce: tx.inner.inner.nonce.unwrap_or_default(),
        to: tx.inner.inner.to.unwrap_or_default(),
        value: tx.inner.inner.value.unwrap_or_default(),
    };
    let metadata = TxSeismicMetadata {
        sender: from,
        legacy_fields,
        seismic_elements: seismic_elements.clone(),
    };

    // Encrypt the calldata
    let encrypted_input = seismic_elements
        .client_encrypt(&original_input, network_pubkey, &encryption_sk, &metadata)
        .map_err(|e| eyre::eyre!("Failed to encrypt calldata for seismic tx: {}", e))?;

    // Set encrypted input
    tx.inner.inner.input =
        alloy_rpc_types::TransactionInput { input: Some(encrypted_input), data: None };

    // Set transaction type to TxSeismic (0x4a)
    tx.inner.inner.transaction_type = Some(TxSeismic::TX_TYPE);
    tx.inner.seismic_elements = Some(seismic_elements);

    // Convert EIP-1559 gas fields to legacy gas_price (TxSeismic uses legacy format)
    if let Some(max_fee) = tx.inner.inner.max_fee_per_gas {
        tx.inner.inner.gas_price = Some(max_fee);
        tx.inner.inner.max_fee_per_gas = None;
        tx.inner.inner.max_priority_fee_per_gas = None;
    }

    Ok(())
}

pub async fn estimate_gas<P: Provider<AnyNetwork>>(
    tx: &mut WithOtherFields<TransactionRequest>,
    provider: &P,
    estimate_multiplier: u64,
) -> Result<()> {
    // if already set, some RPC endpoints might simply return the gas value that is already
    // set in the request and omit the estimate altogether, so we remove it here
    tx.inner.inner.gas = None;

    tx.set_gas_limit(
        provider.estimate_gas(tx.clone()).await.wrap_err("Failed to estimate gas for tx")?
            * estimate_multiplier
            / 100,
    );
    Ok(())
}

pub async fn next_nonce(
    caller: Address,
    provider_url: &str,
    block_number: Option<u64>,
) -> eyre::Result<u64> {
    let provider = try_get_http_provider(provider_url)
        .wrap_err_with(|| format!("bad fork_url provider: {provider_url}"))?;

    let block_id = block_number.map_or(BlockId::latest(), BlockId::number);
    Ok(provider.get_transaction_count(caller).block_id(block_id).await?)
}

pub async fn send_transaction(
    provider: Arc<RetryProvider>,
    mut kind: SendTransactionKind<'_>,
    sequential_broadcast: bool,
    is_fixed_gas_limit: bool,
    estimate_via_rpc: bool,
    estimate_multiplier: u64,
) -> Result<TxHash> {
    if let SendTransactionKind::Raw(tx, _) | SendTransactionKind::Unlocked(tx) = &mut kind {
        if sequential_broadcast {
            let from = tx.inner.inner.from.expect("no sender");

            let tx_nonce = tx.inner.inner.nonce.expect("no nonce");
            for attempt in 0..5 {
                let nonce = provider.get_transaction_count(from).await?;
                match nonce.cmp(&tx_nonce) {
                    Ordering::Greater => {
                        bail!(
                            "EOA nonce changed unexpectedly while sending transactions. Expected {tx_nonce} got {nonce} from provider."
                        )
                    }
                    Ordering::Less => {
                        if attempt == 4 {
                            bail!(
                                "After 5 attempts, provider nonce ({nonce}) is still behind expected nonce ({tx_nonce})."
                            )
                        }
                        warn!(
                            "Expected nonce ({tx_nonce}) is ahead of provider nonce ({nonce}). Retrying in 1 second..."
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                    }
                    Ordering::Equal => {
                        // Nonces are equal, we can proceed
                        break;
                    }
                }
            }
        }

        // Chains which use `eth_estimateGas` are being sent sequentially and require their
        // gas to be re-estimated right before broadcasting.
        if !is_fixed_gas_limit && estimate_via_rpc {
            estimate_gas(tx, &provider, estimate_multiplier).await?;
        }
    }

    let pending = match kind {
        SendTransactionKind::Unlocked(tx) => {
            debug!("sending transaction from unlocked account {:?}", tx);

            // Submit the transaction
            provider.send_transaction(tx).await?
        }
        SendTransactionKind::Raw(tx, signer) => {
            debug!("sending transaction: {:?}", tx);
            let signed = tx.build(signer).await?;

            // Submit the raw transaction
            provider.send_raw_transaction(signed.encoded_2718().as_ref()).await?
        }
        SendTransactionKind::Signed(tx) => {
            debug!("sending transaction: {:?}", tx);
            provider.send_raw_transaction(tx.encoded_2718().as_ref()).await?
        }
    };

    Ok(*pending.tx_hash())
}

/// How to send a single transaction
#[derive(Clone)]
pub enum SendTransactionKind<'a> {
    Unlocked(WithOtherFields<TransactionRequest>),
    Raw(WithOtherFields<TransactionRequest>, &'a EthereumWallet),
    Signed(TxEnvelope),
}

/// Represents how to send _all_ transactions
pub enum SendTransactionsKind {
    /// Send via `eth_sendTransaction` and rely on the  `from` address being unlocked.
    Unlocked(AddressHashSet),
    /// Send a signed transaction via `eth_sendRawTransaction`
    Raw(AddressHashMap<EthereumWallet>),
}

impl SendTransactionsKind {
    /// Returns the [`SendTransactionKind`] for the given address
    ///
    /// Returns an error if no matching signer is found or the address is not unlocked
    pub fn for_sender(
        &self,
        addr: &Address,
        tx: WithOtherFields<TransactionRequest>,
    ) -> Result<SendTransactionKind<'_>> {
        match self {
            Self::Unlocked(unlocked) => {
                if !unlocked.contains(addr) {
                    bail!("Sender address {:?} is not unlocked", addr)
                }
                Ok(SendTransactionKind::Unlocked(tx))
            }
            Self::Raw(wallets) => {
                if let Some(wallet) = wallets.get(addr) {
                    Ok(SendTransactionKind::Raw(tx, wallet))
                } else {
                    bail!("No matching signer for {:?} found", addr)
                }
            }
        }
    }
}

/// State after we have bundled all
/// [`TransactionWithMetadata`](forge_script_sequence::TransactionWithMetadata) objects into a
/// single [`ScriptSequenceKind`] object containing one or more script sequences.
pub struct BundledState {
    pub args: ScriptArgs,
    pub script_config: ScriptConfig,
    pub script_wallets: Wallets,
    pub build_data: LinkedBuildData,
    pub sequence: ScriptSequenceKind,
}

impl BundledState {
    pub async fn wait_for_pending(mut self) -> Result<Self> {
        let progress = ScriptProgress::default();
        let progress_ref = &progress;
        let futs = self
            .sequence
            .sequences_mut()
            .iter_mut()
            .enumerate()
            .map(|(sequence_idx, sequence)| async move {
                let rpc_url = sequence.rpc_url();
                let provider = Arc::new(get_http_provider(rpc_url));
                progress_ref
                    .wait_for_pending(
                        sequence_idx,
                        sequence,
                        &provider,
                        self.script_config.config.transaction_timeout,
                    )
                    .await
            })
            .collect::<Vec<_>>();

        let errors = join_all(futs).await.into_iter().filter_map(Result::err).collect::<Vec<_>>();

        self.sequence.save(true, false)?;

        if !errors.is_empty() {
            return Err(eyre::eyre!("{}", errors.iter().format("\n")));
        }

        Ok(self)
    }

    /// Broadcasts transactions from all sequences.
    pub async fn broadcast(mut self) -> Result<BroadcastedState> {
        let required_addresses = self
            .sequence
            .sequences()
            .iter()
            .flat_map(|sequence| {
                sequence
                    .transactions()
                    .filter(|tx| tx.is_unsigned())
                    .map(|tx| tx.from().expect("missing from"))
            })
            .collect::<AddressHashSet>();

        if required_addresses.contains(&Config::DEFAULT_SENDER) {
            eyre::bail!(
                "You seem to be using Foundry's default sender. Be sure to set your own --sender."
            );
        }

        let send_kind = if self.args.unlocked {
            SendTransactionsKind::Unlocked(required_addresses.clone())
        } else {
            let signers = self.script_wallets.into_multi_wallet().into_signers()?;
            let mut missing_addresses = Vec::new();

            for addr in &required_addresses {
                if !signers.contains_key(addr) {
                    missing_addresses.push(addr);
                }
            }

            if !missing_addresses.is_empty() {
                eyre::bail!(
                    "No associated wallet for addresses: {:?}. Unlocked wallets: {:?}",
                    missing_addresses,
                    signers.keys().collect::<Vec<_>>()
                );
            }

            let signers = signers
                .into_iter()
                .map(|(addr, signer)| (addr, EthereumWallet::new(signer)))
                .collect();

            SendTransactionsKind::Raw(signers)
        };

        let progress = ScriptProgress::default();

        for i in 0..self.sequence.sequences().len() {
            let mut sequence = self.sequence.sequences_mut().get_mut(i).unwrap();

            let provider = Arc::new(try_get_http_provider(sequence.rpc_url())?);
            let already_broadcasted = sequence.receipts.len();

            let seq_progress = progress.get_sequence_progress(i, sequence);

            if already_broadcasted < sequence.transactions.len() {
                // Check if any transactions in this sequence need seismic encryption
                let has_any_shielded = sequence
                    .transactions
                    .iter()
                    .skip(already_broadcasted)
                    .any(|tx| tx.has_shielded_args);

                // Fetch TEE public key and recent block once if any transaction needs encryption
                let seismic_info = if has_any_shielded {
                    let pk = provider
                        .get_tee_pubkey()
                        .await
                        .wrap_err("Failed to fetch TEE public key for seismic transaction encryption. Is the RPC endpoint a Seismic node?")?;
                    let block = provider
                        .get_block_number()
                        .await
                        .wrap_err("Failed to fetch latest block number for seismic transaction")?;
                    let block_info = provider
                        .get_block_by_number(block.into())
                        .await
                        .wrap_err("Failed to fetch latest block for seismic transaction")?
                        .ok_or_else(|| eyre::eyre!("Latest block not found"))?;
                    let block_hash = block_info.header.hash;
                    Some((pk, block_hash, block))
                } else {
                    None
                };

                let is_legacy = Chain::from(sequence.chain).is_legacy() || self.args.legacy;
                // Make a one-time gas price estimation
                let (gas_price, eip1559_fees) = match (
                    is_legacy,
                    self.args.with_gas_price,
                    self.args.priority_gas_price,
                ) {
                    (true, Some(gas_price), _) => (Some(gas_price.to()), None),
                    (true, None, _) => (Some(provider.get_gas_price().await?), None),
                    (false, Some(max_fee_per_gas), Some(max_priority_fee_per_gas)) => (
                        None,
                        Some(Eip1559Estimation {
                            max_fee_per_gas: max_fee_per_gas.to(),
                            max_priority_fee_per_gas: max_priority_fee_per_gas.to(),
                        }),
                    ),
                    (false, _, _) => {
                        let mut fees = provider.estimate_eip1559_fees().await.wrap_err("Failed to estimate EIP1559 fees. This chain might not support EIP1559, try adding --legacy to your command.")?;

                        if let Some(gas_price) = self.args.with_gas_price {
                            fees.max_fee_per_gas = gas_price.to();
                        }

                        if let Some(priority_gas_price) = self.args.priority_gas_price {
                            fees.max_priority_fee_per_gas = priority_gas_price.to();
                        }

                        (None, Some(fees))
                    }
                };

                // Iterate through transactions, matching the `from` field with the associated
                // wallet. Then send the transaction. Panics if we find a unknown `from`
                let transactions = sequence
                    .transactions
                    .iter()
                    .skip(already_broadcasted)
                    .map(|tx_with_metadata| {
                        let is_fixed_gas_limit = tx_with_metadata.is_fixed_gas_limit;
                        let needs_encryption = tx_with_metadata.has_shielded_args;

                        let kind = match tx_with_metadata.tx().clone() {
                            TransactionMaybeSigned::Signed { tx, .. } => {
                                SendTransactionKind::Signed(tx)
                            }
                            TransactionMaybeSigned::Unsigned(mut tx) => {
                                let from = tx
                                    .inner
                                    .inner
                                    .from
                                    .expect("No sender for onchain transaction!");

                                tx.set_chain_id(sequence.chain);

                                // Set TxKind::Create explicitly to satisfy `check_reqd_fields` in
                                // alloy
                                if tx.inner.inner.to.is_none() {
                                    tx.set_create();
                                }

                                if needs_encryption {
                                    // For seismic transactions, use legacy gas pricing
                                    let legacy_gas_price = gas_price.unwrap_or_else(|| {
                                        let fees = eip1559_fees.expect("was set above");
                                        fees.max_fee_per_gas
                                    });
                                    tx.set_gas_price(legacy_gas_price);
                                } else if let Some(gas_price) = gas_price {
                                    tx.set_gas_price(gas_price);
                                } else {
                                    let eip1559_fees = eip1559_fees.expect("was set above");
                                    tx.set_max_priority_fee_per_gas(
                                        eip1559_fees.max_priority_fee_per_gas,
                                    );
                                    tx.set_max_fee_per_gas(eip1559_fees.max_fee_per_gas);
                                }

                                // Encrypt calldata for transactions with shielded parameters
                                if needs_encryption {
                                    let (network_pk, block_hash, block_number) =
                                        seismic_info.as_ref().expect(
                                            "seismic info should be fetched when shielded txs exist",
                                        );
                                    encrypt_transaction_for_seismic(
                                        &mut tx,
                                        network_pk,
                                        *block_hash,
                                        *block_number,
                                    )?;
                                }

                                send_kind.for_sender(&from, tx)?
                            }
                        };

                        Ok((kind, is_fixed_gas_limit))
                    })
                    .collect::<Result<Vec<_>>>()?;

                let estimate_via_rpc =
                    has_different_gas_calc(sequence.chain) || self.args.skip_simulation;

                // We only wait for a transaction receipt before sending the next transaction, if
                // there is more than one signer. There would be no way of assuring
                // their order otherwise.
                // Or if the chain does not support batched transactions (eg. Arbitrum).
                // Or if we need to invoke eth_estimateGas before sending transactions.
                let sequential_broadcast = estimate_via_rpc
                    || self.args.slow
                    || required_addresses.len() != 1
                    || !has_batch_support(sequence.chain);

                // We send transactions and wait for receipts in batches.
                let batch_size = if sequential_broadcast { 1 } else { self.args.batch_size };
                let mut index = already_broadcasted;

                for (batch_number, batch) in transactions.chunks(batch_size).enumerate() {
                    let mut pending_transactions = vec![];

                    seq_progress.inner.write().set_status(&format!(
                        "Sending transactions [{} - {}]",
                        batch_number * batch_size,
                        batch_number * batch_size + std::cmp::min(batch_size, batch.len()) - 1
                    ));
                    for (kind, is_fixed_gas_limit) in batch {
                        let fut = send_transaction(
                            provider.clone(),
                            kind.clone(),
                            sequential_broadcast,
                            *is_fixed_gas_limit,
                            estimate_via_rpc,
                            self.args.gas_estimate_multiplier,
                        );
                        pending_transactions.push(fut);
                    }

                    if !pending_transactions.is_empty() {
                        let mut buffer = futures::stream::iter(pending_transactions).buffered(7);

                        while let Some(tx_hash) = buffer.next().await {
                            let tx_hash = tx_hash.wrap_err("Failed to send transaction")?;
                            sequence.add_pending(index, tx_hash);

                            // Checkpoint save
                            self.sequence.save(true, false)?;
                            sequence = self.sequence.sequences_mut().get_mut(i).unwrap();

                            seq_progress.inner.write().tx_sent(tx_hash);
                            index += 1;
                        }

                        // Checkpoint save
                        self.sequence.save(true, false)?;
                        sequence = self.sequence.sequences_mut().get_mut(i).unwrap();

                        progress
                            .wait_for_pending(
                                i,
                                sequence,
                                &provider,
                                self.script_config.config.transaction_timeout,
                            )
                            .await?
                    }
                    // Checkpoint save
                    self.sequence.save(true, false)?;
                    sequence = self.sequence.sequences_mut().get_mut(i).unwrap();
                }
            }

            let (total_gas, total_gas_price, total_paid) =
                sequence.receipts.iter().fold((0, 0, 0), |acc, receipt| {
                    let gas_used = receipt.gas_used;
                    let gas_price = receipt.effective_gas_price as u64;
                    (acc.0 + gas_used, acc.1 + gas_price, acc.2 + gas_used * gas_price)
                });
            let paid = format_units(total_paid, 18).unwrap_or_else(|_| "N/A".to_string());
            let avg_gas_price = format_units(total_gas_price / sequence.receipts.len() as u64, 9)
                .unwrap_or_else(|_| "N/A".to_string());

            let token_symbol = NamedChain::try_from(sequence.chain)
                .unwrap_or_default()
                .native_currency_symbol()
                .unwrap_or("ETH");
            seq_progress.inner.write().set_status(&format!(
                "Total Paid: {} {} ({} gas * avg {} gwei)\n",
                paid.trim_end_matches('0'),
                token_symbol,
                total_gas,
                avg_gas_price.trim_end_matches('0').trim_end_matches('.')
            ));
            seq_progress.inner.write().finish();
        }

        if !shell::is_json() {
            sh_println!("\n\n==========================")?;
            sh_println!("\nONCHAIN EXECUTION COMPLETE & SUCCESSFUL.")?;
        }

        Ok(BroadcastedState {
            args: self.args,
            script_config: self.script_config,
            build_data: self.build_data,
            sequence: self.sequence,
        })
    }

    pub fn verify_preflight_check(&self) -> Result<()> {
        for sequence in self.sequence.sequences() {
            if self.args.verifier.verifier == VerificationProviderType::Etherscan
                && self
                    .script_config
                    .config
                    .get_etherscan_api_key(Some(sequence.chain.into()))
                    .is_none()
            {
                eyre::bail!("Missing etherscan key for chain {}", sequence.chain);
            }
        }

        Ok(())
    }
}
