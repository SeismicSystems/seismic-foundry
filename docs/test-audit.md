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

## CI-Level Excluded Anvil Integration Tests (15)

These tests are excluded from CI via nextest filter expressions in `.github/workflows/seismic.yml`.
They were verified locally and fail due to known root causes documented below.

### Permanent — Hardfork Incompatibility (5 tests)

Mercury is the only supported hardfork. These tests explicitly require pre-London or
non-Mercury hardfork behavior and are fundamentally incompatible.

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `anvil::test_shanghai_fields` | Asserts Shanghai blocks have `withdrawals_root` but no blob fields | Mercury is post-Cancun; blob fields are always present |
| `anvil_api::can_set_gas_price` | Tests `anvil_set_min_gas_price` on Berlin (pre-EIP-1559) | Mercury always has EIP-1559; legacy gas price setting rejected |
| `transaction::test_reject_eip1559_pre_london` | Asserts EIP-1559 txs rejected on Berlin | Mercury accepts EIP-1559 by design |
| `transaction::can_send_tx_osaka_valid_with_limit_enabled` | Tests Osaka-specific TX_GAS_LIMIT_CAP enforcement | Mercury doesn't include Osaka gas limit caps |
| `anvil::test_anvil_recover_signature` | Tests `ecrecover` precompile via signature impersonation | Mercury modifies `ecrecover` behavior (privacy design) |

### Permanent — External RPC / Fork Dependency (5 tests)

Require network access to external RPC endpoints that CI doesn't provide.

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `anvil_api::can_impersonate_gnosis_safe` | Forks mainnet, fetches Gnosis Safe code, tests impersonation | Uses `fork_config()` — requires mainnet RPC |
| `traces::test_trace_address_fork` | Replays mainnet block, checks trace address paths | Requires mainnet fork RPC |
| `traces::test_trace_address_fork2` | Same as above, different block | Requires mainnet fork RPC |
| `api::can_get_code_by_hash` | Calls `debug_getCodeByHash` on archive node | Requires `next_http_archive_rpc_url()` |
| `genesis::chain_id_precedence` | Tests chain_id precedence (CLI > fork > genesis > default) | 3 of 6 scenarios use `fork_config()` requiring mainnet RPC |

### Temporary — Needs Upstream Fix: `seismic-revm-inspectors` serde (3 tests)

`CallTrace.tx_type` in `seismic-revm-inspectors` lacks `#[serde(default)]`. Old state
dumps without `tx_type` in their trace data fail to deserialize. Fix requires a change
in the external `seismic-revm-inspectors` repository.

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `state::can_load_existing_state` | Loads `state-dump.json`, checks account state | Missing field `tx_type` during deserialization |
| `state::can_load_existing_state_legacy_stress` | Loads legacy stress state dump | Same serde issue |
| `state::test_backward_compatibility_state_dump_deserialization_v1_2` | Tests v1.2 state dump backward compat | Same serde issue + older dumps lack `is_private` flags |

### Temporary — Seismic Trace Shielding (1 test)

Mercury intentionally strips calldata and return data from transaction traces for privacy.

| Test | What it does | Why it fails | Fix |
|------|-------------|-------------|-----|
| `otterscan::test_call_ots_trace_transaction` | Checks otterscan trace structure (input/output per call) | Trace shielding zeros out `input` on top-level CALL and `output` on STATICCALL | Rewrite test to expect shielded trace output |

### Temporary — Seismic Trie Structure (1 test)

`seismic-trie` adds `is_private` flag per leaf, plus system contracts (AES_LIB, DIRECTORY,
INTELLIGENCE) are injected at genesis, changing the Merkle proof structure.

| Test | What it does | Why it fails | Fix |
|------|-------------|-------------|-----|
| `proof::test_account_proof` | Validates Merkle proofs against hardcoded values | Proof hashes differ due to seismic-trie structure and system contracts | Update hardcoded proofs or validate generically |

## Previously Excluded, Now Fixed (5)

These tests were fixed and re-enabled in CI:

| Test | Root cause | Fix applied |
|------|-----------|-------------|
| `anvil_api::can_get_node_info` | Hardcoded `SpecId::PRAGUE` expected | Changed to `SpecId::MERCURY` |
| `api::can_call_with_undersized_max_fee_per_gas` | Read `last_sender` from tx request instead of call result | Decode from `seismic_call()` return bytes via `abi_decode` |
| `revert::test_solc_revert_example` | Unused `sender` variable and `with_from(sender)` incompatible with Seismic tx flow | Removed unused code |
| `api::can_call_on_pending_block` | Compared block header timestamp (seconds) with Mercury EVM timestamp (milliseconds) directly | Divide header timestamp by 1000 before comparison |
| `transaction::get_blocktimestamp_works` | Same timestamp mismatch + mock timestamp in wrong units | Divide header by 1000; multiply mock timestamp by 1000 |

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Tests with `#[ignore]` in code | 26 | 26 (unchanged — all inherited from upstream) |
| Feature-gated tests | 1 | 1 (unchanged) |
| Rust tests run in CI | **8** | **372** |
| — Seismic-specific tests | 8 | 8 |
| — anvil-core unit tests | 0 | 72 |
| — foundry-config unit tests | 0 | 122 |
| — sanvil integration tests | 0 | 170 |
| Tests excluded from CI (known failures) | 0 | 15 (documented above) |
| Tests fixed and re-enabled | 0 | 5 |
| CI coverage improvement | — | **~46x increase** |

### Key Findings

1. **No Class A tests found**: All Seismic-specific tests (`test_seismic_*`, `private_storage_*`) were already running in CI and not ignored.

2. **The real gap was CI-level exclusion**: The CI filter patterns (`test_seismic_`, `private_storage_`) excluded ~99.5% of tests. Now the `test` job also runs anvil-core unit tests (72), foundry-config unit tests (122), and 170 sanvil integration tests.

3. **15 anvil integration tests are excluded with documented reasons**: The most common causes are hardcoded Mercury SpecId (5 tests), external RPC dependencies (5 tests), and state deserialization needing upstream serde fixes (3 tests).

4. **5 tests were fixed and re-enabled**: Fixes ranged from correcting expected hardfork values to accounting for Mercury's millisecond timestamps and adapting to the Seismic call flow.

5. **All `#[ignore]` tests are inherited from upstream Foundry**: They were already skipped before Seismic forked. No changes were made to these.

### Remaining Fixable Items

1. **`seismic-revm-inspectors` serde defaults** (3 tests): Add `#[serde(default)]` to `CallTrace.tx_type` in the external `seismic-revm-inspectors` repo to unblock state dump deserialization tests.

2. **Otterscan trace test** (1 test): Rewrite `test_call_ots_trace_transaction` to expect shielded trace output (empty `input`/`output` fields where Seismic strips them).

3. **Account proof test** (1 test): Update `test_account_proof` to validate proof structure generically instead of against hardcoded upstream hashes.
