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

## CI-Level Excluded Anvil Integration Tests (10)

These tests are excluded from CI via nextest filter expressions in `.github/workflows/seismic.yml`.
They were verified locally and fail due to known root causes documented below.

### Permanent — Hardfork Incompatibility (4 tests)

Mercury is the only supported hardfork. These tests explicitly require pre-London or
non-Mercury hardfork behavior and are fundamentally incompatible.

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `anvil::test_shanghai_fields` | Asserts Shanghai blocks have `withdrawals_root` but no blob fields | Mercury is post-Cancun; blob fields are always present |
| `anvil_api::can_set_gas_price` | Tests `anvil_set_min_gas_price` on Berlin (pre-EIP-1559) | Mercury always has EIP-1559; legacy gas price setting rejected |
| `transaction::test_reject_eip1559_pre_london` | Asserts EIP-1559 txs rejected on Berlin | Mercury accepts EIP-1559 by design |
| `transaction::can_send_tx_osaka_valid_with_limit_enabled` | Tests Osaka-specific TX_GAS_LIMIT_CAP enforcement | Mercury doesn't include Osaka gas limit caps |

### Permanent — External RPC / Fork Dependency (5 tests)

Require network access to external RPC endpoints that CI doesn't provide.

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `anvil_api::can_impersonate_gnosis_safe` | Forks mainnet, fetches Gnosis Safe code, tests impersonation | Uses `fork_config()` — requires mainnet RPC |
| `traces::test_trace_address_fork` | Replays mainnet block, checks trace address paths | Requires mainnet fork RPC |
| `traces::test_trace_address_fork2` | Same as above, different block | Requires mainnet fork RPC |
| `api::can_get_code_by_hash` | Calls `debug_getCodeByHash` on archive node | Requires `next_http_archive_rpc_url()` |
| `genesis::chain_id_precedence` | Tests chain_id precedence (CLI > fork > genesis > default) | 3 of 6 scenarios use `fork_config()` requiring mainnet RPC |

### Potentially Fixable — `anvil_impersonate_signature` (1 test)

| Test | What it does | Why it fails |
|------|-------------|-------------|
| `anvil::test_anvil_recover_signature` | Tests `anvil_impersonate_signature` + `ecrecover` precompile | The `CheatEcrecover` precompile wrapper is commented out in `executor.rs` because `SeismicPrecompiles` doesn't support replacing existing precompiles. Inspector-based interception is viable (the inspector `call()` hook fires for ecrecover at `0x01`) but requires resolving `SharedBuffer` input from the EVM context. |

**Approach**: Intercept ecrecover calls in `AnvilInspector::call()` by checking `inputs.bytecode_address == 0x01`, extracting the signature from the `SharedBuffer` input via the EVM context, and returning a `CallOutcome` with the faked address. All changes in `crates/anvil/` — no upstream dep changes needed.

**Effort**: ~1-2 hours. The inspector hook fires correctly but the EVM passes precompile input as `CallInput::SharedBuffer` (a range into shared memory) rather than `CallInput::Bytes`. The fix requires threading the `&mut CTX` context into the interception logic to resolve the buffer, which means the ecrecover check must happen inline in the `call()` method rather than in a separate helper.

## Previously Excluded, Now Fixed (10)

These tests were fixed and re-enabled in CI on the `ameya/complete-ci-coverage` branch:

| Test | Root cause | Fix applied |
|------|-----------|-------------|
| `anvil_api::can_get_node_info` | Hardcoded `SpecId::PRAGUE` expected | Changed to `SpecId::MERCURY` |
| `api::can_call_with_undersized_max_fee_per_gas` | Read `last_sender` from tx request instead of call result | Decode from `seismic_call()` return bytes via `abi_decode` |
| `revert::test_solc_revert_example` | Unused `sender` variable and `with_from(sender)` incompatible with Seismic tx flow | Removed unused code |
| `api::can_call_on_pending_block` | Compared block header timestamp (seconds) with Mercury EVM timestamp (milliseconds) directly | Divide header timestamp by 1000 before comparison |
| `transaction::get_blocktimestamp_works` | Same timestamp mismatch + mock timestamp in wrong units | Divide header by 1000; multiply mock timestamp by 1000 |
| `proof::test_account_proof` | Hardcoded Merkle proofs didn't account for system contracts in Seismic trie | Regenerated proof bytes from current sanvil |
| `otterscan::test_call_ots_trace_transaction` | Expected full trace input/output but Seismic trace shielding strips them | Updated expected values to match shielded output (empty `input`/`output`) |
| `state::can_load_existing_state_legacy_stress` | Fixture had mixed storage format (2 `FlaggedStorage`, 1 plain string) from partial Alloy 1 merge conversion | Regenerated fixture from current sanvil with proper `FlaggedStorage` entries |
| `state::can_load_existing_state` | `CallTrace.tx_type` in `seismic-revm-inspectors` lacked `#[serde(default)]` — old state dumps without `tx_type` failed to deserialize | Bumped `seismic-revm-inspectors` to `e2a96b7d` which adds the serde default |
| `state::test_backward_compatibility_state_dump_deserialization_v1_2` | Same `CallTrace.tx_type` serde issue | Same `seismic-revm-inspectors` bump |

### Note on `CallTrace.tx_type` serde default

Old state dumps (pre Oct 2025) lack the `tx_type` field on `CallTrace`. It defaults to `0`
via `#[serde(default)]`, which corresponds to legacy transaction type. While the actual
transactions may have been EIP-1559 (type 2), this is safe because nothing reads
`CallTrace.tx_type` from deserialized state — the trace shielding code that would use it
(`storage.rs:581-589`) is commented out as a TODO, and it only checks for
`TxSeismic::TX_TYPE` (74), so old traces with `tx_type=0` would correctly be left unshielded
even when that code is enabled.

## Summary

| Metric | Before | After |
|--------|--------|-------|
| Tests with `#[ignore]` in code | 26 | 26 (unchanged — all inherited from upstream) |
| Feature-gated tests | 1 | 1 (unchanged) |
| Rust tests run in CI | **8** | **~380** |
| — Seismic-specific tests | 8 | 8 |
| — anvil-core unit tests | 0 | 72 |
| — foundry-config unit tests | 0 | 122 |
| — sanvil integration tests | 0 | ~180 |
| Tests excluded from CI (known failures) | 0 | 10 (documented above) |
| Tests fixed and re-enabled | 0 | 10 |
| CI coverage improvement | — | **~47x increase** |

### Key Findings

1. **No Class A tests found**: All Seismic-specific tests (`test_seismic_*`, `private_storage_*`) were already running in CI and not ignored.

2. **The real gap was CI-level exclusion**: The CI filter patterns (`test_seismic_`, `private_storage_`) excluded ~99.5% of tests. Now the `test` job also runs anvil-core unit tests (72), foundry-config unit tests (122), and ~180 sanvil integration tests.

3. **10 anvil integration tests are excluded with documented reasons**: 4 are permanent hardfork incompatibilities, 5 are external RPC dependencies, and 1 is a potentially fixable `anvil_impersonate_signature` interception issue.

4. **10 tests were fixed and re-enabled**: Fixes ranged from correcting expected hardfork values, to accounting for Mercury's millisecond timestamps, regenerating Merkle proofs and state dump fixtures, updating trace expectations for shielding, and bumping `seismic-revm-inspectors` for serde compatibility.

5. **All `#[ignore]` tests are inherited from upstream Foundry**: They were already skipped before Seismic forked. No changes were made to these.

### Remaining Fixable Item

**`anvil::test_anvil_recover_signature`** (1 test): The `anvil_impersonate_signature` feature's `CheatEcrecover` precompile wrapper is fully implemented in `cheats.rs` but not wired into the EVM due to `SeismicPrecompiles` not supporting precompile replacement. An inspector-based interception approach works (the `call()` hook fires for address `0x01`) but requires handling `CallInput::SharedBuffer` by resolving the input bytes from the EVM context. Estimated effort: ~1-2 hours, all changes in `crates/anvil/`. No upstream dependency changes needed.
