use super::seismic_utils;
use crate::tx::{CastTxBuilder, SenderKind};
use alloy_ens::NameOrAddress;
use alloy_network::TransactionBuilder;
use alloy_primitives::U256;
use alloy_provider::Provider;
use alloy_rpc_types::BlockId;
use clap::Parser;
use eyre::Result;
use foundry_cli::{
    opts::{EthereumOpts, TransactionOpts},
    utils::{self, LoadConfig, parse_ether_value},
};
use seismic_prelude::foundry::{EthereumWallet, SeismicProviderExt};
use std::str::FromStr;

/// CLI arguments for `cast estimate`.
#[derive(Debug, Parser)]
pub struct EstimateArgs {
    /// The destination of the transaction.
    #[arg(value_parser = NameOrAddress::from_str)]
    to: Option<NameOrAddress>,

    /// The signature of the function to call.
    sig: Option<String>,

    /// The arguments of the function to call.
    #[arg(allow_negative_numbers = true)]
    args: Vec<String>,

    /// The block height to query at.
    ///
    /// Can also be the tags earliest, finalized, safe, latest, or pending.
    #[arg(long, short = 'B')]
    block: Option<BlockId>,

    /// Calculate the cost of a transaction using the network gas price.
    ///
    /// If not specified the amount of gas will be estimated.
    #[arg(long)]
    cost: bool,

    /// Encrypt calldata and estimate via a signed read (raw signed tx bytes).
    ///
    /// --seismic <SK>: use this hex-encoded private key for encryption
    ///
    /// --seismic: generate a random ephemeral key
    ///
    /// (omit flag): perform a standard `eth_estimateGas`
    ///
    /// The seismic path estimates against the latest block; `--block` is ignored.
    #[arg(long, value_name = "ENCRYPTION_PRIVATE_KEY")]
    pub seismic: Option<Option<String>>,

    #[command(subcommand)]
    command: Option<EstimateSubcommands>,

    #[command(flatten)]
    tx: TransactionOpts,

    #[command(flatten)]
    eth: EthereumOpts,
}

#[derive(Debug, Parser)]
pub enum EstimateSubcommands {
    /// Estimate gas cost to deploy a smart contract
    #[command(name = "--create")]
    Create {
        /// The bytecode of contract
        code: String,

        /// The signature of the constructor
        sig: Option<String>,

        /// Constructor arguments
        #[arg(allow_negative_numbers = true)]
        args: Vec<String>,

        /// Ether to send in the transaction
        ///
        /// Either specified in wei, or as a string with a unit type:
        ///
        /// Examples: 1ether, 10gwei, 0.01ether
        #[arg(long, value_parser = parse_ether_value)]
        value: Option<U256>,
    },
}

impl EstimateArgs {
    pub async fn run(self) -> Result<()> {
        let Self { to, mut sig, mut args, mut tx, block, cost, eth, command, seismic } = self;

        let config = eth.load_config()?;
        let provider = utils::get_provider(&config)?;
        let is_seismic = seismic.is_some();

        let sender = SenderKind::from_wallet_opts(eth.wallet.clone()).await?;
        let from = sender.address();

        let code = if let Some(EstimateSubcommands::Create {
            code,
            sig: create_sig,
            args: create_args,
            value,
        }) = command
        {
            sig = create_sig;
            args = create_args;
            if let Some(value) = value {
                tx.value = Some(value);
            }
            Some(code)
        } else {
            None
        };

        // For seismic estimates, pre-set a gas limit to skip unsigned gas estimation
        // in build() — it would run against plaintext calldata. The real (signed)
        // estimate replaces it below.
        let user_gas_limit = tx.gas_limit;
        if is_seismic && tx.gas_limit.is_none() {
            tx.gas_limit = Some(U256::from(30_000_000));
        }

        let builder = CastTxBuilder::new(&provider, tx, &config)
            .await?
            .with_to(to)
            .await?
            .with_code_sig_and_args(code, sig, args)
            .await?;

        let gas = if is_seismic {
            let signer = eth.wallet.signer().await?;

            // Seismic path uses build() to fill nonce/chainId (needed for signing and
            // the encryption AAD). Non-seismic uses build_raw() (upstream behavior:
            // eth_estimateGas doesn't need gas/nonce).
            let (mut tx, _) = builder.build(sender).await?;

            let encryption_sk = seismic_utils::get_or_generate_encryption_key(seismic.unwrap())?;
            let (seismic_elements, block_gas_limit) =
                seismic_utils::create_seismic_elements(&provider, &encryption_sk, true).await?;
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

            // Signed reads require a fully formed tx: sign with the block gas limit
            // unless the user provided one.
            if user_gas_limit.is_none() {
                tx.set_gas_limit(block_gas_limit);
            }

            let wallet = EthereumWallet::from(signer);
            seismic_utils::request_signed_gas_estimate(&provider, &tx, &wallet).await?
        } else {
            let (tx, _) = builder.build_raw(sender).await?;
            provider.estimate_gas(tx).block(block.unwrap_or_default()).await?
        };
        if cost {
            let gas_price_wei = provider.get_gas_price().await?;
            let cost = gas_price_wei * gas as u128;
            let cost_eth = cost as f64 / 1e18;
            sh_println!("{cost_eth}")?;
        } else {
            sh_println!("{gas}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_estimate_value() {
        let args: EstimateArgs = EstimateArgs::parse_from(["foundry-cli", "--value", "100"]);
        assert!(args.tx.value.is_some());
    }
}
