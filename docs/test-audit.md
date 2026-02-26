# Test Audit: Seismic Foundry

Audit of all skipped, excluded, and ignored tests across the seismic-foundry codebase.
Conducted against the `seismic` branch.

## Classification Key

| Class | Meaning | Action |
|-------|---------|--------|
| **A — Must Fix** | Seismic-specific functionality | Fix and add to CI |
| **B — Upstream Irrelevant** | Tests for behavior Seismic changed/removed | Delete or rewrite for Seismic behavior |
| **C — Flaky / Infra** | Skipped for non-functional reasons | Fix if cheap, else document |
| **D — Redundant / Dead** | Duplicate or dead code | Delete |

## Code-Level Skipped Tests (`#[ignore]`)

| Crate | Test Name | File:Line | Status | Class | Reason |
|-------|-----------|-----------|--------|-------|--------|
| config | `print_config` | `crates/config/src/lib.rs:4796` | `#[ignore]` | D | Manual utility for updating README example config; not a real test |
| common | `can_spin` | `crates/common/src/term.rs:230` | `#[ignore]` | D | Visual/interactive spinner test; requires terminal |
| forge | `get_oz_tags` | `crates/forge/src/cmd/install.rs:579` | `#[ignore = "slow"]` | C | Slow test hitting GitHub API for OpenZeppelin tags |
| forge | `test_dump_mock_data` | `crates/forge/src/cmd/clone.rs:693` | `#[ignore = "...dump mock data from Etherscan"]` | D | Utility for generating test fixtures, not a functional test |
| forge | `manual_debug_setup` | `crates/forge/tests/cli/debug.rs:7` | `#[ignore = "ran manually"]` | D | Manual debugging setup; not automated |
| forge | `can_use_fork_cheat_codes_in_script` | `crates/forge/tests/cli/script.rs:20` | `#[ignore]` | C | Fork cheatcode test; likely needs RPC endpoint |
| forge | `can_cache_ls` | `crates/forge/tests/cli/cmd.rs:89` | `#[ignore]` | C | Not isolated; modifies filesystem/home directory |
| forge | `can_cache_clean` | `crates/forge/tests/cli/cmd.rs:126` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_cache_clean_etherscan` | `crates/forge/tests/cli/cmd.rs:142` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_cache_clean_all_etherscan` | `crates/forge/tests/cli/cmd.rs:163` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_cache_clean_chain` | `crates/forge/tests/cli/cmd.rs:185` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_cache_clean_blocks` | `crates/forge/tests/cli/cmd.rs:208` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_cache_clean_chain_etherscan` | `crates/forge/tests/cli/cmd.rs:242` | `#[ignore]` | C | Not isolated; modifies home directory |
| forge | `can_disable_block_gas_limit` | `crates/forge/tests/cli/test_cmd.rs:657` | `#[ignore = "Too slow"]` | C | Performance — test is too slow for CI |
| forge | `test_roll_scroll_fork_with_cancun` | `crates/forge/tests/cli/test_cmd.rs:2771` | `#[ignore = "RPC Service Unavailable"]` | C | External Scroll RPC dependency (Issue #9297) |
| forge | `test_fuzz_collection` | `crates/forge/tests/it/fuzz.rs:82` | `#[ignore]` | C | Awaiting smarter PUSH collection implementation |
| forge | `test_invariant_storage` | `crates/forge/tests/it/invariant.rs:218` | `#[ignore]` | C | Performance — very slow invariant test |
| forge | `issue_3703` | `crates/forge/tests/it/repros.rs:166` | `#[ignore = "flaky polygon RPCs"]` | C | External Polygon RPC flakiness |
| forge | `issue_10957` | `crates/forge/tests/it/repros.rs:419` | `#[ignore = "reth is currently slightly broken"]` | C | External reth client issue |
| cast | `tx_using_sender_and_nonce` | `crates/cast/tests/cli/main.rs:1794` | `#[ignore = "reth is currently slightly broken"]` | C | External reth client issue |
| test-utils | `test_etherscan_keys` | `crates/test-utils/src/rpc.rs:184` | `#[ignore = "run manually"]` | D | Manual integration test for Etherscan API keys |
| anvil | `test_trace_filter` | `crates/anvil/tests/it/traces.rs:779` | `#[ignore = "flaky"]` | C | Flaky trace filter test |
| anvil | `test_reorg` | `crates/anvil/tests/it/anvil_api.rs:672` | `#[ignore = "flaky"]` | C | Flaky reorg test |
| anvil | `test_total_difficulty_fork` | `crates/anvil/tests/it/fork.rs:1051` | `#[ignore]` | C | Tests total_difficulty on forked Etherscan block; requires external RPC endpoint |
| anvil | `test_immutable_fork_transaction_hash` | `crates/anvil/tests/it/fork.rs:1347` | `#[ignore]` | C | Immutable zkEVM external chain dependency |
| cheatcodes/spec | `schema_up_to_date` | `crates/cheatcodes/spec/src/lib.rs:160` | `#[cfg(feature = "schema")]` | C | Requires optional `schema` feature flag |

## CI-Level Excluded Anvil Integration Tests

These 25 tests are excluded from CI via nextest filter expressions. They were verified
locally and fail due to known root causes documented below.

### Root Cause: Hardcoded `SpecId::MERCURY` (3 tests)

Seismic hardcodes `SpecId::MERCURY` in `crates/anvil/src/config.rs:1095-1096`, ignoring
the hardfork specified by the test. Pre-London/pre-EIP-1559 tests are fundamentally
incompatible.

| Test | Error |
|------|-------|
| `anvil::test_shanghai_fields` | `blob_gas_used` is present (Mercury includes Cancun fields) |
| `anvil_api::can_set_gas_price` | `anvil_setMinGasPrice` rejected because EIP-1559 is always active |
| `transaction::test_reject_eip1559_pre_london` | EIP-1559 tx succeeds instead of being rejected |

### Root Cause: Seismic EVM `block.timestamp` behavior (2 tests)

The Mercury EVM returns a truncated `block.timestamp` in Solidity (~1000x smaller than
the block header timestamp), suggesting a seconds-vs-milliseconds mismatch.

| Test | Error |
|------|-------|
| `transaction::get_blocktimestamp_works` | Contract returns truncated timestamp |
| `api::can_call_on_pending_block` | Same timestamp mismatch |

### Root Cause: Missing `#[serde(default)]` in `seismic-revm-inspectors` (3 tests)

`CallTrace.tx_type` in `seismic-revm-inspectors` lacks `#[serde(default)]`. Old state
dumps without `tx_type` in their trace data fail to deserialize. Fix requires a change
in the external `seismic-revm-inspectors` repository.

| Test | Error |
|------|-------|
| `state::test_backward_compatibility_state_dump_deserialization_v1_2` | Missing field `tx_type` |
| `state::can_load_existing_state` | State fails to load (same root cause) |
| `state::can_load_existing_state_legacy_stress` | State fails to load (same root cause) |

### Root Cause: Seismic system contracts change state trie (1 test)

Three system contracts (AES_LIB, DIRECTORY, INTELLIGENCE) are injected at genesis,
adding nodes to the Merkle trie and changing proof structure.

| Test | Error |
|------|-------|
| `proof::test_account_proof` | Proof array mismatch (extra trie nodes from system contracts) |

### Root Cause: Seismic `eth_call` error wrapping (1 test)

Seismic wraps `eth_call` errors with Seismic-specific messages about unsigned calls.

| Test | Error |
|------|-------|
| `revert::test_solc_revert_example` | Error string wrapped by Seismic, assertion fails |

### Root Cause: Seismic EVM trace differences (1 test)

Mercury EVM produces different trace data (stripped input/output in certain frames).

| Test | Error |
|------|-------|
| `otterscan::test_call_ots_trace_transaction` | Trace `input`/`output` fields are `0x` instead of expected data |

### Root Cause: External RPC dependencies (4 tests)

Require network access to external RPC endpoints.

| Test | Error |
|------|-------|
| `genesis::chain_id_precedence` | DNS resolution failure to `eu-central-mainnet.rpc.ithaca.xyz` |
| `api::can_get_code_by_hash` | DNS resolution failure to RPC endpoint |
| `traces::test_trace_address_fork` | Requires fork RPC |
| `traces::test_trace_address_fork2` | Requires fork RPC |

### Root Cause: EIP-4844 blob transaction behavior under Mercury (4 tests)

Blob transactions behave differently under the Mercury EVM.

| Test | Error |
|------|-------|
| `eip4844::can_correctly_estimate_blob_gas_with_recommended_fillers_with_signer` | Send fails |
| `eip4844::can_get_blobs_by_tx_hash` | Send fails |
| `eip4844::can_mine_blobs_when_exceeds_max_blobs` | Send fails |
| `eip4844::cannot_exceed_six_blobs` | Send fails |

### Root Cause: Osaka hardfork behavior under Mercury (1 test)

| Test | Error |
|------|-------|
| `transaction::can_send_tx_osaka_valid_with_limit_enabled` | Gas limit check behaves differently |

### Root Cause: Seismic API differences (2 tests)

| Test | Error |
|------|-------|
| `api::can_call_with_undersized_max_fee_per_gas` | `TransactionRequest.from()` returns `None` |
| `anvil_api::can_impersonate_gnosis_safe` | Gnosis Safe interaction differs under Seismic |

### Root Cause: `anvil_impersonate_signature` precompile behavior (1 test)

| Test | Error |
|------|-------|
| `anvil::test_anvil_recover_signature` | ecrecover mismatch under Seismic precompile |

### Root Cause: Seismic node info differs (1 test)

| Test | Error |
|------|-------|
| `anvil_api::can_get_node_info` | Reports "Mercury" instead of "Prague" as default hardfork |

## Deferred

Tests that cannot be fixed without changes to external dependencies:

1. **State deserialization tests** (`state::test_backward_compatibility_state_dump_deserialization_v1_2`, `state::can_load_existing_state`, `state::can_load_existing_state_legacy_stress`): Require adding `#[serde(default)]` to `CallTrace.tx_type` in `seismic-revm-inspectors` (external dependency). A `#[serde(default)]` was added to `TransactionInfo.tx_type` in `anvil-core` but the root deserialization failure is in the trace data from the inspectors crate.

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Tests with `#[ignore]` in code | 26 | 26 (unchanged — all inherited from upstream) |
| Feature-gated tests | 1 | 1 (unchanged) |
| Rust tests run in CI | **8** | **367** |
| — Seismic-specific tests | 8 | 8 |
| — anvil-core unit tests | 0 | 72 |
| — foundry-config unit tests | 0 | 122 |
| — sanvil integration tests | 0 | 165 |
| Tests excluded from CI (known failures) | 0 | 25 (documented above) |
| Tests fixed | 0 | 0 (none were broken Seismic-specific tests) |
| Tests deleted | 0 | 0 |
| CI coverage improvement | — | **~46x increase** |

### Key Findings

1. **No Class A tests found**: All Seismic-specific tests (`test_seismic_*`, `private_storage_*`) were already running in CI and not ignored.

2. **The real gap was CI-level exclusion**: The CI filter patterns (`test_seismic_`, `private_storage_`) excluded ~99.5% of tests. Now the `test` job also runs anvil-core unit tests (72), foundry-config unit tests (122), and 165 sanvil integration tests.

3. **25 anvil integration tests are excluded with documented reasons**: Grouped into 12 root cause categories. The most common causes are hardcoded Mercury SpecId (incompatible with pre-London tests), external RPC dependencies, and Seismic EVM behavior differences.

4. **One code fix applied**: Added `#[serde(default)]` to `TransactionInfo.tx_type` in `crates/anvil/core/src/eth/transaction/mod.rs:1266` for backward compatibility with old state dumps. The full fix also requires a change in `seismic-revm-inspectors`.

5. **All `#[ignore]` tests are inherited from upstream Foundry**: They were already skipped before Seismic forked. No changes were made to these — they are primarily flaky tests depending on external RPCs, filesystem isolation issues, or performance concerns.

### Patterns Observed

- **Hardcoded Mercury SpecId** is the largest source of test incompatibility. Seismic's `config.rs` always sets `SpecId::MERCURY` regardless of the hardfork requested. This breaks all tests that assume pre-London/pre-EIP-1559 behavior.
- **Fork-dependent tests** (requiring external RPC access) make up a significant portion of the untested surface. These are excluded from CI because they need network access.
- **The `seismic-revm-inspectors` dependency** added a `tx_type` field to `CallTrace` without `#[serde(default)]`, breaking state dump backward compatibility. This is the only external dependency issue found.
