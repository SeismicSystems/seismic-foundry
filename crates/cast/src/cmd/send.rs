use crate::tx::{self, CastTxBuilder};
use alloy_ens::NameOrAddress;
use alloy_network::{TransactionBuilder, eip2718::Encodable2718};
use alloy_primitives::Bytes;
use alloy_provider::Provider;
use alloy_signer::Signer;
use clap::Parser;
use eyre::{Result, eyre};
use foundry_cli::{
    opts::{EthereumOpts, TransactionOpts},
    utils,
    utils::LoadConfig,
};
use seismic_prelude::foundry::{AnyNetwork, EthereumWallet, SeismicProviderExt};
use std::{path::PathBuf, str::FromStr};

use super::seismic_utils;

/// CLI arguments for `cast send`.
#[derive(Debug, Parser)]
pub struct SendTxArgs {
    /// The destination of the transaction.
    ///
    /// If not provided, you must use cast send --create.
    #[arg(value_parser = NameOrAddress::from_str)]
    to: Option<NameOrAddress>,

    /// The signature of the function to call.
    sig: Option<String>,

    /// The arguments of the function to call.
    #[arg(allow_negative_numbers = true)]
    args: Vec<String>,

    /// Only print the transaction hash and exit immediately.
    #[arg(id = "async", long = "async", alias = "cast-async", env = "CAST_ASYNC")]
    cast_async: bool,

    /// The number of confirmations until the receipt is fetched.
    #[arg(long, default_value = "1")]
    confirmations: u64,

    /// Encrypt calldata via ECDH and send as a Seismic transaction (type 74).
    ///
    /// --seismic <SK>: use this hex-encoded private key for encryption
    ///
    /// --seismic: generate a random ephemeral key
    ///
    /// (omit flag): send a standard transaction
    #[arg(long, value_name = "ENCRYPTION_PRIVATE_KEY")]
    pub seismic: Option<Option<String>>,

    #[command(subcommand)]
    command: Option<SendTxSubcommands>,

    /// Send via `eth_sendTransaction` using the `--from` argument or $ETH_FROM as sender
    #[arg(long, requires = "from")]
    unlocked: bool,

    /// Timeout for sending the transaction.
    #[arg(long, env = "ETH_TIMEOUT")]
    pub timeout: Option<u64>,

    #[command(flatten)]
    tx: TransactionOpts,

    #[command(flatten)]
    eth: EthereumOpts,

    /// The path of blob data to be sent.
    #[arg(
        long,
        value_name = "BLOB_DATA_PATH",
        conflicts_with = "legacy",
        requires = "blob",
        help_heading = "Transaction options"
    )]
    path: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub enum SendTxSubcommands {
    /// Use to deploy raw contract bytecode.
    #[command(name = "--create")]
    Create {
        /// The bytecode of the contract to deploy.
        code: String,

        /// The signature of the function to call.
        sig: Option<String>,

        /// The arguments of the function to call.
        #[arg(allow_negative_numbers = true)]
        args: Vec<String>,
    },
}

impl SendTxArgs {
    pub async fn run(self) -> eyre::Result<()> {
        let Self {
            eth,
            to,
            mut sig,
            cast_async,
            mut args,
            tx,
            confirmations: _,
            command,
            unlocked,
            path,
            timeout,
            seismic,
        } = self;

        let blob_data = if let Some(path) = path { Some(std::fs::read(path)?) } else { None };

        let code = if let Some(SendTxSubcommands::Create {
            code,
            sig: constructor_sig,
            args: constructor_args,
        }) = command
        {
            if to.is_none() && tx.auth.is_some() {
                return Err(eyre!(
                    "EIP-7702 transactions can't be CREATE transactions and require a destination address"
                ));
            }
            if to.is_none() && blob_data.is_some() {
                return Err(eyre!(
                    "EIP-4844 transactions can't be CREATE transactions and require a destination address"
                ));
            }

            sig = constructor_sig;
            args = constructor_args;
            Some(code)
        } else {
            None
        };

        let config = eth.load_config()?;
        let provider = utils::get_provider(&config)?;

        let builder = CastTxBuilder::new(&provider, tx, &config)
            .await?
            .with_to(to)
            .await?
            .with_code_sig_and_args(code, sig, args)
            .await?
            .with_blob_data(blob_data)?;

        let timeout = timeout.unwrap_or(config.transaction_timeout);

        if seismic.is_some() {
            let signer = eth.wallet.signer().await?;
            let from = signer.address();
            tx::validate_from_address(eth.wallet.from, from)?;

            let encryption_sk = seismic_utils::get_or_generate_encryption_key(seismic.unwrap())?;

            // build_raw avoids unsigned gas estimation (the node sanitizes `from`
            // on unsigned eth_estimateGas, breaking msg.sender-gated contracts).
            let (mut tx, _) = builder.build_raw(&signer).await?;

            if tx.nonce.is_none() {
                tx.set_nonce(provider.get_transaction_count(from).await?);
            }
            if tx.inner.gas_price.is_none() {
                tx.inner.gas_price = Some(provider.get_gas_price().await?);
            }

            let (seismic_elements, block_gas_limit) =
                seismic_utils::create_seismic_elements(&provider, &encryption_sk, false).await?;
            let network_pubkey = provider.get_tee_pubkey().await?;
            let original_input = tx.inner.input.input().unwrap_or_default().clone();

            seismic_utils::prepare_seismic_fields(&mut tx, seismic_elements);
            seismic_utils::encrypt_tx_input(
                &mut tx,
                &original_input,
                &network_pubkey,
                &encryption_sk,
                from,
            )?;

            let wallet = EthereumWallet::from(signer);
            if tx.inner.gas.is_none() {
                seismic_utils::estimate_gas_signed(&provider, &mut tx, &wallet, block_gas_limit)
                    .await?;
            }

            let signed = tx
                .build(&wallet)
                .await
                .map_err(|e| eyre::eyre!("Failed to sign seismic transaction: {e:?}"))?;
            let encoded = Bytes::from(signed.encoded_2718());
            let tx_hash: alloy_primitives::B256 = provider
                .client()
                .request("eth_sendRawTransaction", (encoded,))
                .await
                .map_err(|e| eyre::eyre!("Failed to send seismic transaction: {e}"))?;

            return cast_send(&provider, tx_hash, cast_async, timeout).await;
        }

        if unlocked {
            if let Some(config_chain) = config.chain {
                let current_chain_id = provider.get_chain_id().await?;
                let config_chain_id = config_chain.id();
                if config_chain_id != current_chain_id {
                    sh_warn!("Switching to chain {}", config_chain)?;
                    provider
                        .raw_request::<_, ()>(
                            "wallet_switchEthereumChain".into(),
                            [serde_json::json!({
                                "chainId": format!("0x{:x}", config_chain_id),
                            })],
                        )
                        .await?;
                }
            }

            let (tx, _) = builder.build(config.sender).await?;

            // Unlocked accounts use eth_sendTransaction (node signs)
            let tx_hash: alloy_primitives::B256 =
                provider.client().request("eth_sendTransaction", (tx,)).await?;
            cast_send(&provider, tx_hash, cast_async, timeout).await
        } else {
            let signer = eth.wallet.signer().await?;
            let from = signer.address();

            tx::validate_from_address(eth.wallet.from, from)?;

            let (tx, _) = builder.build(&signer).await?;

            // Sign and send via eth_sendRawTransaction directly.
            // provider.send_transaction() stack overflows on the SeismicFoundry
            // network due to a recursive build() in the filler chain.
            let wallet = EthereumWallet::from(signer);
            let signed = tx
                .build(&wallet)
                .await
                .map_err(|e| eyre::eyre!("Failed to sign transaction: {e:?}"))?;
            let encoded = Bytes::from(signed.encoded_2718());
            let tx_hash: alloy_primitives::B256 =
                provider.client().request("eth_sendRawTransaction", (encoded,)).await?;

            cast_send(&provider, tx_hash, cast_async, timeout).await
        }
    }
}

async fn cast_send<P: Provider<AnyNetwork>>(
    provider: &P,
    tx_hash: alloy_primitives::B256,
    cast_async: bool,
    timeout: u64,
) -> Result<()> {
    sh_println!("{tx_hash:#x}")?;
    if !cast_async {
        let start = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_secs(timeout);
        loop {
            if let Some(receipt) = provider.get_transaction_receipt(tx_hash).await? {
                sh_println!("{}", serde_json::to_string_pretty(&receipt)?)?;
                break;
            }
            if start.elapsed() > timeout_dur {
                eyre::bail!("Timed out waiting for transaction receipt");
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    Ok(())
}
