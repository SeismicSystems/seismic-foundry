use crate::{
    Cast,
    tx::{self, CastTxBuilder},
};
use alloy_ens::NameOrAddress;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_serde::WithOtherFields;
use alloy_signer::Signer;
use clap::Parser;
use eyre::{Result, eyre};
use foundry_cli::{
    opts::{EthereumOpts, TransactionOpts},
    utils,
    utils::LoadConfig,
};
use std::{path::PathBuf, str::FromStr};

// Seismic imports for encryption/decryption
use alloy_primitives::{B256, Bytes, aliases::U96};
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use seismic_prelude::foundry::{
    AnyNetwork, EthereumWallet, SeismicProviderExt, TransactionRequest, TxLegacyFields,
    TxSeismicElements, TxSeismicMetadata,
};

/// Helper function to create seismic elements from private key
fn create_seismic_elements(encryption_sk: &SecretKey) -> TxSeismicElements {
    let secp = Secp256k1::new();
    let encryption_pk = PublicKey::from_secret_key(&secp, encryption_sk);
    // randomly generate a nonce
    let encryption_nonce = U96::random();
    TxSeismicElements {
        encryption_pubkey: encryption_pk,
        encryption_nonce,
        message_version: 0,
        recent_block_hash: B256::ZERO,
        expires_at_block: u64::MAX,
        signed_read: false,
    }
}

/// Helper function to get or generate encryption private key
fn get_or_generate_encryption_key(provided_key: Option<String>) -> Result<SecretKey> {
    match provided_key {
        Some(key_str) => {
            SecretKey::from_str(&key_str).map_err(|e| eyre::eyre!("Invalid private key: {}", e))
        }
        None => {
            // Generate a truly random private key on the fly
            let mut rng = rand::rng();
            let mut key_bytes = [0u8; 32];
            rng.fill_bytes(&mut key_bytes);
            SecretKey::from_slice(&key_bytes)
                .map_err(|e| eyre::eyre!("Failed to generate random private key: {}", e))
        }
    }
}

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

    /// Use seismic transaction with optional encryption private key
    #[arg(long, value_name = "ENCRYPTION_PRIVATE_KEY")]
    pub seismic: Option<Option<String>>,
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
            confirmations,
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
            // ensure we don't violate settings for transactions that can't be CREATE: 7702 and 4844
            // which require mandatory target
            if to.is_none() && tx.auth.is_some() {
                return Err(eyre!(
                    "EIP-7702 transactions can't be CREATE transactions and require a destination address"
                ));
            }
            // ensure we don't violate settings for transactions that can't be CREATE: 7702 and 4844
            // which require mandatory target
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

        let is_seismic = seismic.is_some();

        if is_seismic {
            // Get wallet signer directly for seismic transactions
            let signer = eth.wallet.signer().await?;
            let from = signer.address();

            tx::validate_from_address(eth.wallet.from, from)?;

            let (tx, _) = builder.build(&signer).await?;

            // Handle seismic transaction
            let encryption_sk = get_or_generate_encryption_key(seismic.unwrap())?;

            // Create seismic elements
            let seismic_elements = create_seismic_elements(&encryption_sk);

            // Get the network's TEE public key
            let network_pubkey = provider.get_tee_pubkey().await?;

            // Get the original transaction input data
            let original_input = tx.inner.input.input().unwrap_or_default().clone();

            // Create metadata for encryption
            let legacy_fields = TxLegacyFields {
                chain_id: tx.chain_id.unwrap_or_default(),
                nonce: tx.nonce.unwrap_or_default(),
                to: tx.to.unwrap_or_default(),
                value: tx.value.unwrap_or_default(),
            };
            let metadata =
                TxSeismicMetadata { sender: from, legacy_fields, seismic_elements: seismic_elements.clone() };

            // Encrypt the input data
            let encrypted_input = seismic_elements
                .client_encrypt(&original_input, &network_pubkey, &encryption_sk, &metadata)
                .map_err(|e| eyre::eyre!("Failed to encrypt input data: {}", e))?;

            // Create encrypted transaction
            let mut encrypted_tx = tx.clone();
            encrypted_tx.inner.input = alloy_rpc_types::TransactionInput {
                input: Some(Bytes::from(encrypted_input)),
                data: None,
            };
            encrypted_tx.inner.transaction_type =
                Some(seismic_prelude::foundry::TxSeismic::TX_TYPE);
            encrypted_tx.seismic_elements = Some(seismic_elements.clone());

            // Convert EIP-1559 fields back to legacy gas_price for seismic transactions
            if let Some(max_fee) = encrypted_tx.inner.max_fee_per_gas {
                encrypted_tx.inner.gas_price = Some(max_fee);
                encrypted_tx.inner.max_fee_per_gas = None;
                encrypted_tx.inner.max_priority_fee_per_gas = None;
            }

            // Sign the transaction to create a raw signed seismic tx
            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::<_, _, AnyNetwork>::default()
                .wallet(wallet)
                .connect_provider(&provider);

            return cast_send(provider, encrypted_tx, cast_async, confirmations, timeout).await;
        }
        // Case 1:
        // Default to sending via eth_sendTransaction if the --unlocked flag is passed.
        // This should be the only way this RPC method is used as it requires a local node
        // or remote RPC with unlocked accounts.
        if unlocked {
            // only check current chain id if it was specified in the config
            if let Some(config_chain) = config.chain {
                let current_chain_id = provider.get_chain_id().await?;
                let config_chain_id = config_chain.id();
                // switch chain if current chain id is not the same as the one specified in the
                // config
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

            cast_send(provider, tx, cast_async, confirmations, timeout).await
        // Case 2:
        // An option to use a local signer was provided.
        // If we cannot successfully instantiate a local signer, then we will assume we don't
        // have enough information to sign and we must bail.
        } else {
            // Retrieve the signer, and bail if it can't be constructed.
            let signer = eth.wallet.signer().await?;
            let from = signer.address();

            tx::validate_from_address(eth.wallet.from, from)?;

            let (tx, _) = builder.build(&signer).await?;

            let wallet = EthereumWallet::from(signer);
            let provider = ProviderBuilder::<_, _, AnyNetwork>::default()
                .wallet(wallet)
                .connect_provider(&provider);

            cast_send(provider, tx, cast_async, confirmations, timeout).await
        }
    }
}

async fn cast_send<P: Provider<AnyNetwork>>(
    provider: P,
    tx: WithOtherFields<TransactionRequest>,
    cast_async: bool,
    confs: u64,
    timeout: u64,
) -> Result<()> {
    let cast = Cast::new(provider);
    let pending_tx = cast.send(tx).await?;

    let tx_hash = pending_tx.inner().tx_hash();

    if cast_async {
        sh_println!("{tx_hash:#x}")?;
    } else {
        let receipt =
            cast.receipt(format!("{tx_hash:#x}"), None, confs, Some(timeout), false).await?;
        sh_println!("{receipt}")?;
    }

    Ok(())
}
