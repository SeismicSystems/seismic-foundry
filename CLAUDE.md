# Seismic Foundry

Fork of [Foundry](https://github.com/foundry-rs/foundry) adding **shielded transactions and private storage** to the EVM toolchain. Provides three Seismic-specific binaries — `sforge`, `sanvil`, `scast` — that integrate with the Seismic Solidity compiler [`ssolc`](https://github.com/SeismicSystems/seismic-solidity) and the Mercury EVM for privacy-aware smart contract development.

---

## CRITICAL: The `seismic-prelude` Import Aliasing Strategy

**This is the single most important pattern in this codebase.** Understanding it is essential before making any changes.

### The Problem

Seismic replaces many core types (`TxEnvelope`, `AnyNetwork`, `SpecId`, etc.) with Seismic-aware versions (`SeismicTxEnvelope`, `SeismicFoundry`, `SeismicSpecId`, etc.). Naively, every function signature, return type, and variable using these types would need to change — creating massive diffs and guaranteed merge conflicts with upstream Foundry.

### The Solution

The `seismic-prelude` crate (lives in [`seismic-alloy/crates/prelude/`](https://github.com/SeismicSystems/seismic-alloy)) re-exports all Seismic types **aliased to their upstream names**:

```rust
// In seismic-prelude/src/foundry.rs:
pub use seismic_alloy_consensus::SeismicTxEnvelope as TxEnvelope;
pub use seismic_alloy_network::foundry::SeismicFoundry as AnyNetwork;
pub use seismic_revm::SeismicSpecId as SpecId;
pub use seismic_revm::SeismicEvm as RevmEvm;
// ... etc
```

Then in seismic-foundry source files, the import is often the **only line that changes**, drastically reducing the diff:

```rust
// Instead of: use alloy_consensus::TxEnvelope;
use seismic_prelude::foundry::TxEnvelope;

// The rest of the file uses `TxEnvelope` unchanged — zero diff from upstream
fn process_tx(tx: TxEnvelope) -> Result<...> { ... }
```

This means upstream PRs that reference `TxEnvelope`, `AnyNetwork`, `SpecId`, etc. merge with near-zero friction — those names already resolve to Seismic equivalents via the prelude.

### Key Aliases

| Seismic Type (real name) | Alias (upstream name) |
|---|---|
| `SeismicTxEnvelope` | `TxEnvelope` |
| `SeismicReceiptEnvelope` | `AnyReceiptEnvelope` |
| `SeismicFoundry` | `AnyNetwork` |
| `SeismicFoundryTxEnvelope` | `AnyTxEnvelope` |
| `SeismicFoundryTypedTransaction` | `AnyTypedTransaction` |
| `SeismicFoundryRpcBlock` | `AnyRpcBlock` |
| `SeismicFoundryRpcTransaction` | `AnyRpcTransaction` |
| `SeismicFoundryTransactionRequest` | `AnyTransactionRequest` |
| `SeismicTransactionRequest` | `TransactionRequest` |
| `SeismicTransactionReceipt` | `TransactionReceipt` |
| `SeismicTransaction` (network) | `RpcTransaction` |
| `SeismicGasFiller` | `GasFiller` |
| `SeismicSpecId` | `SpecId` |
| `SeismicEvm` | `RevmEvm` |
| `SeismicContext` | `EthEvmContext` |
| `SeismicInstructions` | `EthInstructions` |
| `SeismicHaltReason` | `OpHaltReason` |
| `SeismicTransaction` (revm) | `OpTransaction` |
| `SeismicWallet<AnyNetwork>` | `EthereumWallet` |
| `SeismicTransaction<RevmTxEnv>` | `TxEnv` |
| `RevmCfgEnv<SeismicSpecId>` | `CfgEnv` |

### Rules

- **When adding a new Seismic type that replaces an upstream type**: Add the alias in `seismic-prelude/src/foundry.rs`, then import from `seismic_prelude::foundry::` in consuming files. Never rename at every call site.
- **When upstream adds new code using these type names**: It compiles immediately — the prelude alias resolves it to the Seismic version.
- All consuming files use `use seismic_prelude::foundry::{...}` — currently used across ~96 source files.

### Comment-Out Strategy for Cleaner Diffs

When removing upstream code, **prefer wrapping it in a multi-line comment** rather than deleting it:

```rust
/*
fn upstream_function_we_dont_need() {
    // original upstream code
}
*/
```

This tricks git/GitHub into presenting a cleaner diff — the lines show as modified rather than deleted+added, which makes upstream merges significantly easier to review and resolve.

---

## Build

```bash
# Build individual binaries (recommended)
cargo build --bin sforge
cargo build --bin sanvil
cargo build --bin scast
```

### Prerequisites

- Rust (stable toolchain)
- `ssolc` binary at `/usr/local/bin/ssolc` (required for sforge tests)
  - Install via [sfoundryup](https://docs.seismic.systems/getting-started/installation)
  - Or download from [seismic-solidity releases](https://github.com/SeismicSystems/seismic-solidity/releases)

---

## Test

### Seismic CI tests (what CI runs on every PR)

```bash
cargo nextest run test_seismic_tx_encoding
cargo nextest run test_seismic_
cargo nextest run private_storage_
```

### Viem integration tests

```bash
bun install && bun viem:test
```

Runs `packages/client-tests/` — uses `seismic-viem` and `seismic-viem-tests` to test `sanvil` end-to-end. Covers: SeismicTx deployment and calls, typed data signing (EIP-712), WebSocket connections, all 6 Mercury precompiles (RNG, ECDH, HKDF, AES-GCM, secp256k1 sign), and transaction trace shielding. Requires a built `sanvil` binary.

### Contract tests

```bash
bun install && bun forge:test
```

Runs `packages/sforge-tests/` — clones Seismic contract repos (currently `poker`) and runs `sforge build` + `sforge test` against them. Verifies that real shielded contracts compile and pass their test suites with the current `sforge` binary. Requires an installed `sforge` in PATH.

---

## CI

**`seismic.yml` is the only CI workflow we use.** The other workflow files (`test.yml`, `nextest.yml`, `benchmarks.yml`, etc.) are inherited from upstream Foundry and are not active on the `seismic` branch.

`.github/workflows/seismic.yml` runs 6 jobs:

1. **rustfmt** — `cargo fmt --all --check` (nightly)
2. **build** — `cargo build --bin sforge` + `cargo build --bin sanvil`
3. **warnings** — `RUSTFLAGS="-D warnings" cargo check` on sforge and sanvil
4. **test** — installs `ssolc`, runs `test_seismic_tx_encoding`, `test_seismic_`, `private_storage_`
5. **viem** — builds `sanvil`, runs `bun viem:test`
6. **contract-tests** — installs `sforge`, runs `bun forge:test`

---

## Key Seismic Modifications

This section maps the major changes from upstream Foundry. It covers the most important modifications but may not be exhaustive — when in doubt, check the actual code.

### Binary Renaming

| Upstream | Seismic | Location |
|----------|---------|----------|
| `forge` | `sforge` | `crates/forge/Cargo.toml` `[[bin]]` |
| `anvil` | `sanvil` | `crates/anvil/Cargo.toml` `[[bin]]` |
| `cast` | `scast` | `crates/cast/Cargo.toml` `[[bin]]` |

### Patched Dependencies (`Cargo.toml [patch.crates-io]`)

All core Foundry dependencies are replaced with Seismic forks pinned to specific commits:

| Seismic Fork Repo | What It Replaces |
|---|---|
| `seismic-alloy-core` | `alloy-primitives`, `alloy-sol-types`, `alloy-dyn-abi`, `alloy-json-abi`, `alloy-sol-macro*` — adds `FlaggedStorage`, shielded types |
| `seismic-revm` | `revm`, `revm-interpreter`, `revm-primitives`, `revm-context-interface`, `op-revm` — Mercury EVM with CLOAD/CSTORE opcodes and 6 precompiles |
| `seismic-alloy` | `seismic-alloy-consensus`, `seismic-alloy-network`, `seismic-alloy-provider`, `seismic-alloy-rpc-types`, `seismic-prelude` — TxSeismic, SeismicProviderExt, type aliasing |
| `seismic-evm` | `alloy-evm`, `alloy-op-evm`, `alloy-seismic-evm` — block execution layer |
| `seismic-compilers` | `foundry-compilers*` — compiler integration for `ssolc` |
| `seismic-foundry-fork-db` | `foundry-fork-db` — fork DB with FlaggedStorage support |
| `seismic-trie` | `alloy-trie` — Merkle trie with `is_private` flag per leaf |
| `seismic-revm-inspectors` | `revm-inspectors` — EVM tracing for Seismic |
| `enclave` | `seismic-enclave` — TEE mock (unsecure sample keys for local dev) |

### `crates/config/` — Global Config

- **`src/lib.rs`**: `seismic: bool` field on `Config` (default: `true`) — master switch for using `ssolc` instead of standard `solc`
- `sanitize_seismic_settings()` — auto-sets `seismic = true` when `evm_version == Mercury`
- `get_default_ssolc_path()` — `/usr/local/bin/ssolc` (Linux/macOS), `C:\Program Files\Seismic\bin\ssolc.exe` (Windows)
- `ensure_solc()` — when `seismic = true`, overrides solc resolution to use `ssolc`

### `crates/anvil/` — sanvil (largest set of changes)

**`src/hardfork.rs`**:
- `SeismicHardfork` enum (`Mercury`, `Latest`)
- `ChainHardfork` enum wrapping Ethereum/Optimism/Seismic hardforks
- Conversion: `SeismicHardfork` → `SeismicSpecId::MERCURY`

**`src/config.rs`**:
- `enable_seismic: bool` on `NodeConfig`, `with_seismic()` builder
- Injects 3 system contracts at genesis: `AES_LIB`, `DIRECTORY`, `INTELLIGENCE` (addresses at `0x100000000000000000000000000000000000000{3,4,5}`)

**`src/cmd.rs`**:
- `--seismic` CLI flag on `AnvilEvmArgs`

**`src/eth/api.rs`**:
- `seismic_getTeePublicKey` RPC — returns the unsecure sample secp256k1 public key (TEE mock)
- `eth_getFlaggedStorageAt` RPC — returns `FlaggedStorage` (value + `is_private` flag)
- `seismic_call()` handler — executes encrypted calls

**`src/eth/error.rs`**:
- `FailedToDecryptCalldata`, `SeismicDecryptionFailed`, `SignedReadMismatch`, `MissingRequiredFields` error variants

**`src/eth/backend/mem/mod.rs`** (the core):
- System contract bytecode injection at startup
- `seismic_call()` + `seismic_call_with_state()` — full encrypted call pipeline (decrypt input → execute → encrypt output)
- `validate_seismic_call_tx_metadata()` — validates SeismicTx fields
- `validate_pool_transaction()` — rejects invalid SeismicTx (bad signature, failed decryption, signed-read-as-write)
- `flagged_storage_at()` — returns value + privacy flag
- Uses `seismic_enclave::get_unsecure_sample_secp256k1_sk()` as mock TEE I/O key

**`src/eth/backend/mem/state.rs`**:
- `trie_storage()` passes `is_private` flag per leaf to `seismic-trie`

**`src/eth/backend/db.rs`**:
- `set_storage_at()` and `storage_ref()` use `FlaggedStorage` instead of `U256`
- `SerializableAccountRecord.storage` is `BTreeMap<U256, FlaggedStorage>`

**`src/eth/backend/env.rs`**:
- `Env.is_seismic: bool` (hardcoded `true`)

### `crates/anvil/core/` — Transaction Types

**`src/eth/mod.rs`**:
- `SeismicGetTeePublicKey` and `EthGetFlaggedStorageAt` variants in `EthRequest` enum

**`src/eth/transaction/mod.rs`**:
- `TypedTransaction::Seismic(Signed<TxSeismic>)` variant
- `TypedTransactionRequest::Seismic(TxSeismic)` variant
- `transaction_request_to_typed()` handles `SEISMIC_TX_TYPE_ID` (type 74)
- `to_evm_tx_env()` decrypts SeismicTx calldata before EVM execution
- `Decodable2718` recognizes type 74 and decodes into `Signed<TxSeismic>`
- `test_seismic_tx_encoding()` — cross-checks encoding with `seismic-viem-tests`

### `crates/cast/` — scast

**`src/cmd/send.rs`**:
- `--seismic [ENCRYPTION_PRIVATE_KEY]` flag
- Fetches TEE pubkey via `provider.get_tee_pubkey()`, encrypts calldata via ECDH + AEAD
- Converts EIP-1559 gas fields to legacy `gas_price` (SeismicTx uses legacy gas format)
- Sets `transaction_type = TxSeismic::TX_TYPE` (74)

**`src/cmd/call.rs`**:
- `--encryption-private-key [KEY]` flag
- Encrypts calldata, calls `provider.seismic_call()`, decrypts response

**`src/cmd/da_estimate.rs`**:
- Panics on SeismicTx — "Seismic transactions are not supported for DA estimates"

### `crates/evm/core/` — EVM Backend

**`src/seismic_constants.rs`** (new file):
- Hardcoded addresses and runtime bytecodes for AES_LIB, DIRECTORY, INTELLIGENCE system contracts

**`src/backend/mod.rs`**:
- `unsafe_private_storage: bool` on `Backend` — **enforcement point**: if a private storage slot is read and this flag is `false`, returns `DatabaseError::PrivateStorage` instead of the value
- `storage()` and `storage_ref()` return `FlaggedStorage` (not `U256`)

**`src/opts.rs`**:
- `unsafe_private_storage: bool` on `EvmOpts` (default `false`)

**`src/evm.rs`**:
- EVM construction uses `SeismicChain::default()` context, `SeismicPrecompiles`, `EthInstructions`
- Type alias: `SeismicFoundryPrecompiles`

**`src/either_evm.rs`**:
- `EitherEvm` has only one variant: `Seismic(...)` — upstream Eth/Op variants are removed

**`src/backend/snapshot.rs`**:
- Storage snapshots use `HashMap<U256, FlaggedStorage>`

### `crates/evm/evm/` — Executor Layer

**`src/executors/mod.rs`**:
- `insert_account_storage()` and `set_storage_at()` take `FlaggedStorage` instead of `U256`

**`src/executors/trace.rs`**:
- State map uses `HashMap<U256, FlaggedStorage>`

### `crates/forge/` — sforge

**`src/multi_runner.rs`**:
- `db.set_unsafe_private_storage(true)` — all test runs unconditionally allow private storage access (tests need to read shielded state)

**`tests/cli/script.rs`**:
- `private_storage_blocked_without_flag` and `private_storage_allowed_with_flag` integration tests

### `crates/script/`

**`src/lib.rs`**:
- `--unsafe-private-storage` CLI flag, propagated to `evm_opts.unsafe_private_storage`
- `seismic_elements: None` set explicitly on `TransactionRequest` construction

### `crates/cheatcodes/`

**`src/inspector.rs`**:
- Defensive `seismic_elements: None` in transaction request construction (no new Seismic cheatcodes added)

### `crates/common/fmt/`

**`src/ui.rs`**:
- `UIfmt` implementation for `Signed<TxSeismic>` — pretty-prints `encryptionPubkey`, `encryptionNonce`, `messageVersion`

### New Directories (Seismic-only, not in upstream)

| Directory | Purpose |
|---|---|
| `packages/client-tests/` | Viem integration tests against sanvil (TypeScript/Bun) |
| `packages/sforge-tests/` | Contract compilation/test validation with sforge (TypeScript/Bun) |
| `sfoundryup/` | Installer script — installs `ssolc`, builds and installs `sforge`/`sanvil`/`scast` |
| `docs/seismic/` | Seismic-specific technical documentation |
| `.github/workflows/seismic.yml` | Seismic CI workflow (the only active one) |
| `crates/anvil/tests/it/seismic.rs` | Anvil integration tests for SeismicTx and precompiles |

### Pervasive Changes

- **`FlaggedStorage` replaces `U256`** for all storage values throughout the EVM stack (backend, executor, snapshots, state trie, DB serialization)
- **`seismic_prelude::foundry::*` imports** replace direct `alloy`/`revm` imports in ~96 files (see the import aliasing section above)

---

## Branches

- `seismic` — main branch (PR target)
- Upstream Foundry is not tracked via a branch in this repo

## Code Style

- **Formatting**: `cargo +nightly fmt --all` (100 char max width, crate-level imports)
- **Linting**: `cargo clippy` — disallows `std::print`/`println` (use `sh_print`/`sh_println` from `foundry_common::shell`)
- **Other formatters**: `dprint` for Markdown, TOML, JSON, TypeScript, YAML
- **Spell check**: `typos` CLI
- **Lint commands**: `make fmt`, `make lint-clippy`, `make lint-typos`, `make lint` (all)
