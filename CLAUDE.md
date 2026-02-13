# Seismic Foundry

Fork of [Foundry](https://github.com/foundry-rs/foundry) that adds **shielded transactions and private storage** to the EVM toolchain. Provides three Seismic-specific binaries — `sforge`, `sanvil`, `scast` — that integrate with the Seismic Solidity compiler (`ssolc`) and Seismic EVM (`SEVM`) for privacy-aware smart contract development.

## What This Does

Standard Foundry tools (`forge`, `anvil`, `cast`) target public Ethereum. Seismic extends them with:
- **`sforge`** — testing framework for shielded contracts; uses `ssolc` (at `/usr/local/bin/ssolc`) by default
- **`sanvil`** — local node with native private storage and shielded transaction support (encryption/decryption done in-node, no TEE required)
- **`scast`** — CLI with `--seismic` flag for client-side encryption of send/call transactions via secp256k1 key exchange

All three use Seismic-patched dependencies (`seismic-revm`, `seismic-alloy`, `seismic-evm`, etc.) pinned via `[patch.crates-io]` in the workspace `Cargo.toml`.

## Build

Rust workspace using Cargo. MSRV: **1.89**, edition: **2024**. Outputs are in `target/debug/` (or `target/release/`).

### Prerequisites (all platforms)

- Rust 1.89+ (stable toolchain)
- `ssolc` binary at `/usr/local/bin/ssolc` (required for sforge tests; install via [sfoundryup](https://docs.seismic.systems/getting-started/installation))

### macOS (arm64/x86_64)

```bash
# Build individual binaries (recommended — faster than full workspace)
cargo build --bin sforge
cargo build --bin sanvil
cargo build --bin scast

# Or build all three
cargo build --bin sforge --bin sanvil --bin scast
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

cargo build --bin sforge
cargo build --bin sanvil
cargo build --bin scast
```

### Full workspace build (includes all features)

```bash
# The Makefile sets features: jemalloc aws-kms gcp-kms cli asm-keccak
make build
# Or with custom profile:
make build PROFILE=release
```

### Install to PATH

```bash
cargo install --root=$HOME/.seismic --path ./crates/forge --locked   # sforge
cargo install --root=$HOME/.seismic --path ./crates/anvil --locked   # sanvil
cargo install --root=$HOME/.seismic --path ./crates/cast --locked    # scast
# Add $HOME/.seismic/bin to your PATH
```

### Verify

```bash
./target/debug/sforge --version   # sforge Version: 1.3.5-dev
./target/debug/sanvil --version   # anvil Version: 1.3.5-dev
./target/debug/scast --version    # cast Version: 1.3.5-dev
```

## Test

### Seismic-specific tests (CI suite)

These are the tests that CI runs on every PR. They all pass locally.

```bash
# Seismic unit tests
cargo nextest run test_seismic_tx_encoding

# Seismic integration tests
cargo nextest run test_seismic_

# Private storage tests
cargo nextest run private_storage_
```

### Full unit test suite

Requires `cargo-nextest` (`cargo install cargo-nextest`).

```bash
# From bash (the ! in the filter expression requires bash, not zsh)
bash -c 'cargo nextest run -E "kind(test) & !test(/\b(issue|ext_integration)/)"'

# Or use make (runs via bash internally)
make test-unit
```

### Doc tests

```bash
# All workspace doc tests (cast doctests require a running RPC node — expect failures)
cargo test --doc --workspace

# Doc tests excluding cast (all pass)
cargo test --doc --workspace --exclude cast
```

### Viem integration tests

Requires `bun` and a built `sanvil` binary.

```bash
bun install
bun viem:test    # runs packages/client-tests
```

### Contract tests (sforge)

Requires `bun` and an installed `sforge` binary.

```bash
bun install
bun forge:test   # runs packages/sforge-tests
```

## Project Layout

```
crates/
  forge/               sforge binary — test framework for shielded contracts
  anvil/               sanvil binary — local Seismic node
    core/              Core transaction types (TxSeismic encoding)
    rpc/               RPC server implementation
    server/            HTTP/WS server
  cast/                scast binary — CLI with --seismic encryption
  cheatcodes/          EVM cheatcodes (+ spec/ for cheatcode definitions)
  config/              Workspace config (seismic flag, seismic_version, ssolc path)
  evm/
    core/              EVM backend (private storage implementation)
    evm/               Main EVM execution
    coverage/          Code coverage
    fuzz/              Fuzz testing with proptest
    traces/            Execution traces
  common/              Shared utilities (+ fmt/ for formatting)
  cli/                 CLI framework shared by all binaries
  fmt/                 Solidity formatter
  lint/                Solidity linter
  doc/                 Documentation generator
  debugger/            Interactive debugger
  wallets/             Wallet integration (HW wallets, AWS/GCP KMS)
  script/              Script execution engine
  script-sequence/     Script sequencing
  verify/              Contract verification
  chisel/              REPL (not yet supported for Seismic)
  macros/              Proc macros
  test-utils/          Test utilities
  linking/             Contract linking
  sol-macro-gen/       Solidity macro generation
packages/
  client-tests/        Viem integration tests (bun)
  sforge-tests/        Contract tests via sforge (bun)
npm/                   npm package wrappers for multi-platform distribution
testdata/              Test fixtures
docs/seismic/          Seismic-specific technical documentation
sfoundryup/            Installation script
```

## Key Seismic Modifications

- **Config**: `crates/config/src/lib.rs` — `seismic` flag (default: `true`), `seismic_version` for SEVM spec
- **Private storage**: `crates/evm/core/` — backend support for shielded storage reads/writes
- **Transaction types**: `crates/anvil/core/` — `TxSeismic` type with encryption parameters (public key, nonce, message version, block hash, expiry)
- **scast encryption**: `crates/cast/` — `--seismic` flag for send, `--encryption-private-key` for call; fetches TEE pubkey via `get_tee_pubkey()` RPC
- **Patched dependencies**: `Cargo.toml` `[patch.crates-io]` — Seismic forks of alloy-core, revm, alloy, compilers, fork-db, evm, trie

## Code Style

- **Rust formatting**: `rustfmt` (nightly) — `rustfmt.toml`: 100 char max width, crate-level import granularity
- **Linting**: `clippy` (nightly) — disallows `std::print`/`println` (use `sh_print`/`sh_println` from `foundry_common::shell`)
- **Other formatters**: `dprint` for Markdown, TOML, JSON, TypeScript, YAML (`dprint.json`)
- **Spell check**: `typos` CLI (`typos.toml`)
- **Lint commands**: `make fmt`, `make lint-clippy`, `make lint-typos`, `make lint` (all)

## CI

GitHub Actions (`.github/workflows/seismic.yml`):

1. **rustfmt** — `cargo fmt --all --check` (nightly)
2. **build** — `cargo build --bin sforge` + `cargo build --bin sanvil`
3. **warnings** — `RUSTFLAGS="-D warnings" cargo check --bin sforge/sanvil`
4. **test** — installs `ssolc`, runs `test_seismic_tx_encoding`, `test_seismic_`, `private_storage_`
5. **viem** — builds `sanvil`, runs `bun viem:test`
6. **contract-tests** — installs `sforge`, runs `bun forge:test`

## Branches

- `seismic` — main branch (PR target)
- Upstream Foundry is not tracked via a branch in this repo

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `make test-unit` fails with `expected expression` (filter parse error) | The `!` in the nextest filter is escaped by zsh. Run via `bash -c '...'` or use `make test-unit` which invokes through make's shell. |
| `can_get_code_by_hash` test fails with DNS error | This is a forking test that requires network access to `eu-central-mainnet.rpc.ithaca.xyz`. Expected to fail offline. Not part of Seismic CI. |
| `test_shanghai_fields` fails (blob_gas_used assertion) | Known upstream test incompatible with Seismic's hardfork changes. Not part of Seismic CI test suite. |
| `cast` doc tests fail (20 failures) | All `cast` doc tests require a running RPC node. Run `cargo test --doc --workspace --exclude cast` to skip them. |
| `sforge` tests fail with "ssolc not found" | Install `ssolc` to `/usr/local/bin/ssolc` via [sfoundryup](https://docs.seismic.systems/getting-started/installation) or download from [seismic-solidity releases](https://github.com/SeismicSystems/seismic-solidity/releases). |
| Build slow on macOS | First build compiles ~500 crates (~2-3 min). Subsequent incremental builds are fast. Use `cargo build --bin sforge` instead of full workspace to reduce scope. |
| `chisel` not supported | Seismic does not yet support the `chisel` REPL. Avoid `cargo build --workspace` if chisel deps cause issues. |
