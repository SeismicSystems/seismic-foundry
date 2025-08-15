use crate::{
    traces::TraceKind,
    tx::{CastTxBuilder, SenderKind},
    Cast,
};
use alloy_ens::NameOrAddress;
use alloy_network::{TransactionBuilder};
use alloy_provider::{Provider, SendableTx};
use alloy_signer::Signer;
use alloy_primitives::{hex, Address, Bytes, TxKind, U256};
use alloy_rpc_types::{
    state::{StateOverride, StateOverridesBuilder},
    BlockId, BlockNumberOrTag,
};
use clap::Parser;
use eyre::Result;
use foundry_cli::{
    opts::{EthereumOpts, TransactionOpts},
    utils::{self, handle_traces, parse_ether_value, TraceResult},
};
use foundry_common::shell;
use foundry_compilers::artifacts::EvmVersion;
use foundry_config::{
    figment::{
        self,
        value::{Dict, Map},
        Figment, Metadata, Profile,
    },
    Config,
};
use foundry_evm::{
    executors::TracingExecutor,
    opts::EvmOpts,
    traces::{InternalTraceMode, TraceMode},
};
use regex::Regex;
use revm::context::TransactionType;
use std::{str::FromStr, sync::LazyLock};

// Seismic imports for encryption/decryption
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use rand::RngCore;
use seismic_prelude::foundry::{TxSeismicElements, SeismicProviderExt, EthereumWallet};
use alloy_primitives::aliases::U96;


// matches override pattern <address>:<slot>:<value>
// e.g. 0x123:0x1:0x1234
static OVERRIDE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([^:]+):([^:]+):([^:]+)$").unwrap());

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
    }
}

/// CLI arguments for `cast call`.
///
/// ## State Override Flags
///
/// The following flags can be used to override the state for the call:
///
/// * `--override-balance <address>:<balance>` - Override the balance of an account
/// * `--override-nonce <address>:<nonce>` - Override the nonce of an account
/// * `--override-code <address>:<code>` - Override the code of an account
/// * `--override-state <address>:<slot>:<value>` - Override a storage slot of an account
///
/// Multiple overrides can be specified for the same account. For example:
///
/// ```bash
/// cast call 0x... "transfer(address,uint256)" 0x... 100 \
///   --override-balance 0x123:0x1234 \
///   --override-nonce 0x123:1 \
///   --override-code 0x123:0x1234 \
///   --override-state 0x123:0x1:0x1234
///   --override-state-diff 0x123:0x1:0x1234
/// ```
#[derive(Debug, Parser)]
pub struct CallArgs {
    /// The destination of the transaction.
    #[arg(value_parser = NameOrAddress::from_str)]
    to: Option<NameOrAddress>,

    /// The signature of the function to call.
    sig: Option<String>,

    /// The arguments of the function to call.
    args: Vec<String>,

    /// Raw hex-encoded data for the transaction. Used instead of \[SIG\] and \[ARGS\].
    #[arg(
        long,
        conflicts_with_all = &["sig", "args"]
    )]
    data: Option<String>,

    /// Forks the remote rpc, executes the transaction locally and prints a trace
    #[arg(long, default_value_t = false)]
    trace: bool,

    /// Opens an interactive debugger.
    /// Can only be used with `--trace`.
    #[arg(long, requires = "trace")]
    debug: bool,

    #[arg(long, requires = "trace")]
    decode_internal: bool,

    /// Labels to apply to the traces; format: `address:label`.
    /// Can only be used with `--trace`.
    #[arg(long, requires = "trace")]
    labels: Vec<String>,

    /// The EVM Version to use.
    /// Can only be used with `--trace`.
    #[arg(long, requires = "trace")]
    evm_version: Option<EvmVersion>,

    /// The block height to query at.
    ///
    /// Can also be the tags earliest, finalized, safe, latest, or pending.
    #[arg(long, short)]
    block: Option<BlockId>,

    /// Enable Odyssey features.
    #[arg(long, alias = "alphanet")]
    pub odyssey: bool,

    #[command(subcommand)]
    command: Option<CallSubcommands>,

    #[command(flatten)]
    tx: TransactionOpts,

    #[command(flatten)]
    eth: EthereumOpts,

    /// Use current project artifacts for trace decoding.
    #[arg(long, visible_alias = "la")]
    pub with_local_artifacts: bool,

    /// Override the balance of an account.
    /// Format: address:balance
    #[arg(long = "override-balance", value_name = "ADDRESS:BALANCE")]
    pub balance_overrides: Option<Vec<String>>,

    /// Override the nonce of an account.
    /// Format: address:nonce
    #[arg(long = "override-nonce", value_name = "ADDRESS:NONCE")]
    pub nonce_overrides: Option<Vec<String>>,

    /// Override the code of an account.
    /// Format: address:code
    #[arg(long = "override-code", value_name = "ADDRESS:CODE")]
    pub code_overrides: Option<Vec<String>>,

    /// Override the state of an account.
    /// Format: address:slot:value
    #[arg(long = "override-state", value_name = "ADDRESS:SLOT:VALUE")]
    pub state_overrides: Option<Vec<String>>,

    /// Override the state diff of an account.
    /// Format: address:slot:value
    #[arg(long = "override-state-diff", value_name = "ADDRESS:SLOT:VALUE")]
    pub state_diff_overrides: Option<Vec<String>>,

    /// Optional private key for encrypting seismic transaction
    #[arg(long, help = "Private key for encrypting seismic transaction")]
    pub encryption_private_key: Option<String>,
}

#[derive(Debug, Parser)]
pub enum CallSubcommands {
    /// ignores the address field and simulates creating a contract
    #[command(name = "--create")]
    Create {
        /// Bytecode of contract.
        code: String,

        /// The signature of the constructor.
        sig: Option<String>,

        /// The arguments of the constructor.
        args: Vec<String>,

        /// Ether to send in the transaction.
        ///
        /// Either specified in wei, or as a string with a unit type.
        ///
        /// Examples: 1ether, 10gwei, 0.01ether
        #[arg(long, value_parser = parse_ether_value)]
        value: Option<U256>,
    },
}

impl CallArgs {
    pub async fn run(self) -> Result<()> {
        let figment = Into::<Figment>::into(&self.eth).merge(&self);
        let evm_opts = figment.extract::<EvmOpts>()?;
        let mut config = Config::from_provider(figment)?.sanitized();
        let state_overrides = self.get_state_overrides()?;

        let Self {
            to,
            mut sig,
            mut args,
            mut tx,
            eth,
            command,
            block,
            trace,
            evm_version,
            debug,
            decode_internal,
            labels,
            data,
            with_local_artifacts,
            encryption_private_key,
            ..
        } = self;

        if let Some(data) = data {
            sig = Some(data);
        }

        let provider = utils::get_provider(&config)?;
        let sender = SenderKind::from_wallet_opts(eth.wallet.clone()).await?;
        let from = sender.address();

        // Get wallet signer directly for seismic transactions
        let signer = eth.wallet.signer().await?;

        println!("Sender address: {:?}", sender.address());
        println!("Signer address: {:?}", signer.address());

        // set gas price if not provided
        if tx.gas_price.is_none() {
            tx.gas_price = Some(U256::from(provider.get_gas_price().await?));
        }
        
        let code = if let Some(CallSubcommands::Create {
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

        let (tx, func) = CastTxBuilder::new(&provider, tx, &config)
            .await?
            .with_to(to)
            .await?
            .with_code_sig_and_args(code, sig, args)
            .await?
            .build(sender)
            // .build_raw(sender)
            .await?;

        if trace {
            if let Some(BlockId::Number(BlockNumberOrTag::Number(block_number))) = self.block {
                // Override Config `fork_block_number` (if set) with CLI value.
                config.fork_block_number = Some(block_number);
            }

            let create2_deployer = evm_opts.create2_deployer;
            let (mut env, fork, chain, odyssey) =
                TracingExecutor::get_fork_material(&config, evm_opts).await?;

            // modify settings that usually set in eth_call
            env.evm_env.cfg_env.disable_block_gas_limit = true;
            env.evm_env.block_env.gas_limit = u64::MAX;

            let trace_mode = TraceMode::Call
                .with_debug(debug)
                .with_decode_internal(if decode_internal {
                    InternalTraceMode::Full
                } else {
                    InternalTraceMode::None
                })
                .with_state_changes(shell::verbosity() > 4);
            let mut executor = TracingExecutor::new(
                env,
                fork,
                evm_version,
                trace_mode,
                odyssey,
                create2_deployer,
            )?;

            let value = tx.inner.inner.value.unwrap_or_default();
            let input = tx.inner.inner.input.into_input().unwrap_or_default();
            let tx_kind = tx.inner.inner.to.expect("set by builder");
            let env_tx = &mut executor.env_mut().tx;

            if let Some(tx_type) = tx.inner.inner.transaction_type {
                env_tx.tx_type = tx_type;
            }

            if let Some(access_list) = tx.inner.inner.access_list {
                env_tx.access_list = access_list;

                if env_tx.tx_type == TransactionType::Legacy as u8 {
                    env_tx.tx_type = TransactionType::Eip2930 as u8;
                }
            }

            let trace = match tx_kind {
                TxKind::Create => {
                    let deploy_result = executor.deploy(from, input, value, None);
                    TraceResult::try_from(deploy_result)?
                }
                TxKind::Call(to) => TraceResult::from_raw(
                    executor.transact_raw(from, to, input, value)?,
                    TraceKind::Execution,
                ),
            };

            handle_traces(
                trace,
                &config,
                chain,
                labels,
                with_local_artifacts,
                debug,
                decode_internal,
            )
            .await?;

            return Ok(());
        }

        // sh_println!("{}", Cast::new(provider).call(&tx, func.as_ref(), block, state_overrides).await?);

        // Always do encryption/decryption logic
        // Get or generate encryption key (generates temporary key if not provided)
        let encryption_sk = get_or_generate_encryption_key(encryption_private_key)?;
        let seismic_elements = create_seismic_elements(&encryption_sk);
        
        // Get the network's TEE public key
        let network_pubkey = provider.get_tee_pubkey().await?;
        
        // Get the original transaction input data
        let original_input = tx.inner.input.input().unwrap_or_default().clone();
        
        // Encrypt the input data
        let encrypted_input = seismic_elements
            .client_encrypt(&original_input, &network_pubkey, &encryption_sk)
            .map_err(|e| eyre::eyre!("Failed to encrypt input data: {}", e))?;
        
        // Create encrypted transaction
        let mut encrypted_tx = tx.clone();
        encrypted_tx.inner.input = alloy_rpc_types::TransactionInput {
            input: Some(Bytes::from(encrypted_input)),
            data: None,
        };
        encrypted_tx.inner.transaction_type = Some(seismic_prelude::foundry::TxSeismic::TX_TYPE);
        encrypted_tx.seismic_elements = Some(seismic_elements.clone());
        
        // Convert EIP-1559 fields back to legacy gas_price for seismic transactions
        if let Some(max_fee) = encrypted_tx.inner.max_fee_per_gas {
            encrypted_tx.inner.gas_price = Some(max_fee);
            encrypted_tx.inner.max_fee_per_gas = None;
            encrypted_tx.inner.max_priority_fee_per_gas = None;
        }
        
        // Sign the transaction to create a raw signed seismic tx
        let ethereum_wallet = EthereumWallet::from(signer);
        let signed_envelope = encrypted_tx.build(&ethereum_wallet).await?;

        println!("Signed envelope: {:?}", signed_envelope);

        // DEBUG: Manually recover the signer from the signed envelope to verify signature
        println!("DEBUG: Attempting signature recovery from signed envelope...");
        match &signed_envelope {
            seismic_prelude::foundry::AnyTxEnvelope::Seismic(seismic_signed) => {
                println!("DEBUG: Found seismic transaction, attempting signature recovery...");
                match seismic_signed.recover_signer() {
                    Ok(recovered_signer) => {
                        println!("Successfully recovered signer from signed envelope: {}", recovered_signer);
                    }
                    Err(e) => {
                        println!("Failed to recover signer from seismic transaction: {:?}", e);
                    }
                }
            }
            _ => {
                println!("Non-seismic envelope type, cannot recover signer");
            }
        }
        
        // Make the seismic call using signed raw transaction
        let encrypted_response = provider
            .seismic_call(SendableTx::Envelope(signed_envelope))
            .await
            .map_err(|e| eyre::eyre!("Seismic call failed: {}", e))?;

        // Decrypt the response (seismic_call should return Bytes directly, no need to decode hex)
        let decrypted_response = seismic_elements
            .client_decrypt(&encrypted_response, &network_pubkey, &encryption_sk)
            .map_err(|e| eyre::eyre!("Failed to decrypt response: {}", e))?;
        
        let result = hex::encode_prefixed(&decrypted_response);
        sh_println!("{}", result)?;

        Ok(())
    }
    /// Parse state overrides from command line arguments
    pub fn get_state_overrides(&self) -> eyre::Result<StateOverride> {
        let mut state_overrides_builder = StateOverridesBuilder::default();

        // Parse balance overrides
        for override_str in self.balance_overrides.iter().flatten() {
            let (addr, balance) = address_value_override(override_str)?;
            state_overrides_builder =
                state_overrides_builder.with_balance(addr.parse()?, balance.parse()?);
        }

        // Parse nonce overrides
        for override_str in self.nonce_overrides.iter().flatten() {
            let (addr, nonce) = address_value_override(override_str)?;
            state_overrides_builder =
                state_overrides_builder.with_nonce(addr.parse()?, nonce.parse()?);
        }

        // Parse code overrides
        for override_str in self.code_overrides.iter().flatten() {
            let (addr, code_str) = address_value_override(override_str)?;
            state_overrides_builder =
                state_overrides_builder.with_code(addr.parse()?, Bytes::from_str(code_str)?);
        }

        // Parse state overrides
        for override_str in self.state_overrides.iter().flatten() {
            let (addr, slot, value) = address_slot_value_override(override_str)?;
            state_overrides_builder =
                state_overrides_builder.with_state(addr, [(slot.into(), value.into())]);
        }

        // Parse state diff overrides
        for override_str in self.state_diff_overrides.iter().flatten() {
            let (addr, slot, value) = address_slot_value_override(override_str)?;
            state_overrides_builder =
                state_overrides_builder.with_state_diff(addr, [(slot.into(), value.into())]);
        }

        Ok(state_overrides_builder.build())
    }
}

impl figment::Provider for CallArgs {
    fn metadata(&self) -> Metadata {
        Metadata::named("CallArgs")
    }

    fn data(&self) -> Result<Map<Profile, Dict>, figment::Error> {
        let mut map = Map::new();

        if self.odyssey {
            map.insert("odyssey".into(), self.odyssey.into());
        }

        if let Some(evm_version) = self.evm_version {
            map.insert("evm_version".into(), figment::value::Value::serialize(evm_version)?);
        }

        Ok(Map::from([(Config::selected_profile(), map)]))
    }
}

/// Parse an override string in the format address:value.
fn address_value_override(address_override: &str) -> Result<(&str, &str)> {
    address_override.split_once(':').ok_or_else(|| {
        eyre::eyre!("Invalid override {address_override}. Expected <address>:<value>")
    })
}

/// Parse an override string in the format address:slot:value.
fn address_slot_value_override(address_override: &str) -> Result<(Address, U256, U256)> {
    let captures = OVERRIDE_PATTERN.captures(address_override).ok_or_else(|| {
        eyre::eyre!("Invalid override {address_override}. Expected <address>:<slot>:<value>")
    })?;

    Ok((
        captures[1].parse()?, // Address
        captures[2].parse()?, // Slot (U256)
        captures[3].parse()?, // Value (U256)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn can_parse_call_data() {
        let data = hex::encode("hello");
        let args = CallArgs::parse_from(["foundry-cli", "--data", data.as_str()]);
        assert_eq!(args.data, Some(data));

        let data = hex::encode_prefixed("hello");
        let args = CallArgs::parse_from(["foundry-cli", "--data", data.as_str()]);
        assert_eq!(args.data, Some(data));
    }

    #[test]
    fn can_parse_state_overrides() {
        let args = CallArgs::parse_from([
            "foundry-cli",
            "--override-balance",
            "0x123:0x1234",
            "--override-nonce",
            "0x123:1",
            "--override-code",
            "0x123:0x1234",
            "--override-state",
            "0x123:0x1:0x1234",
        ]);

        assert_eq!(args.balance_overrides, Some(vec!["0x123:0x1234".to_string()]));
        assert_eq!(args.nonce_overrides, Some(vec!["0x123:1".to_string()]));
        assert_eq!(args.code_overrides, Some(vec!["0x123:0x1234".to_string()]));
        assert_eq!(args.state_overrides, Some(vec!["0x123:0x1:0x1234".to_string()]));
    }

    #[test]
    fn can_parse_multiple_state_overrides() {
        let args = CallArgs::parse_from([
            "foundry-cli",
            "--override-balance",
            "0x123:0x1234",
            "--override-balance",
            "0x456:0x5678",
            "--override-nonce",
            "0x123:1",
            "--override-nonce",
            "0x456:2",
            "--override-code",
            "0x123:0x1234",
            "--override-code",
            "0x456:0x5678",
            "--override-state",
            "0x123:0x1:0x1234",
            "--override-state",
            "0x456:0x2:0x5678",
        ]);

        assert_eq!(
            args.balance_overrides,
            Some(vec!["0x123:0x1234".to_string(), "0x456:0x5678".to_string()])
        );
        assert_eq!(args.nonce_overrides, Some(vec!["0x123:1".to_string(), "0x456:2".to_string()]));
        assert_eq!(
            args.code_overrides,
            Some(vec!["0x123:0x1234".to_string(), "0x456:0x5678".to_string()])
        );
        assert_eq!(
            args.state_overrides,
            Some(vec!["0x123:0x1:0x1234".to_string(), "0x456:0x2:0x5678".to_string()])
        );
    }
}
