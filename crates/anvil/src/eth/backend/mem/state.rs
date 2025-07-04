//! Support for generating the state root for memdb storage

use crate::eth::error::BlockchainError;
use alloy_primitives::{keccak256, map::HashMap, Address, B256, U256};
use alloy_rlp::Encodable;
use alloy_rpc_types::{state::StateOverride, BlockOverrides};
use alloy_trie::{HashBuilder, Nibbles};
use foundry_evm::backend::DatabaseError;
use revm::{
    bytecode::Bytecode,
    context::BlockEnv,
    database::{CacheDB, DatabaseRef, DbAccount},
    primitives::FlaggedStorage,
    state::AccountInfo,
};

pub fn build_root(values: impl IntoIterator<Item = (Nibbles, Vec<u8>, bool)>) -> B256 {
    let mut builder = HashBuilder::default();
    for (key, value, is_private) in values {
        builder.add_leaf(key, value.as_ref(), is_private);
    }
    builder.root()
}

/// Builds state root from the given accounts
pub fn state_root(accounts: &HashMap<Address, DbAccount>) -> B256 {
    build_root(trie_accounts(accounts))
}

/// Builds storage root from the given storage
pub fn storage_root(storage: &HashMap<U256, FlaggedStorage>) -> B256 {
    build_root(trie_storage(storage))
}

/// Builds iterator over stored key-value pairs ready for storage trie root calculation.
pub fn trie_storage(storage: &HashMap<U256, FlaggedStorage>) -> Vec<(Nibbles, Vec<u8>, bool)> {
    let mut storage = storage
        .iter()
        .map(|(key, value)| {
            let value_u256: U256 = value.into();
            let data = alloy_rlp::encode(value_u256);
            (Nibbles::unpack(keccak256(key.to_be_bytes::<32>())), data, value.is_private)
        })
        .collect::<Vec<_>>();
    storage.sort_by(|(key1, _, _), (key2, _, _)| key1.cmp(key2));

    storage
}

/// Builds iterator over stored key-value pairs ready for account trie root calculation.
pub fn trie_accounts(accounts: &HashMap<Address, DbAccount>) -> Vec<(Nibbles, Vec<u8>, bool)> {
    let mut accounts = accounts
        .iter()
        .map(|(address, account)| {
            let data = trie_account_rlp(&account.info, &account.storage);
            (Nibbles::unpack(keccak256(*address)), data, false)
        })
        .collect::<Vec<_>>();
    accounts.sort_by(|(key1, _, _), (key2, _, _)| key1.cmp(key2));

    accounts
}

/// Returns the RLP for this account.
pub fn trie_account_rlp(info: &AccountInfo, storage: &HashMap<U256, FlaggedStorage>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let list: [&dyn Encodable; 4] =
        [&info.nonce, &info.balance, &storage_root(storage), &info.code_hash];

    alloy_rlp::encode_list::<_, dyn Encodable>(&list, &mut out);

    out
}

/// Applies the given state overrides to the given CacheDB
pub fn apply_state_overrides<D>(
    overrides: StateOverride,
    cache_db: &mut CacheDB<D>,
) -> Result<(), BlockchainError>
where
    D: DatabaseRef<Error = DatabaseError>,
{
    for (account, account_overrides) in &overrides {
        let mut account_info = cache_db.basic_ref(*account)?.unwrap_or_default();

        if let Some(nonce) = account_overrides.nonce {
            account_info.nonce = nonce;
        }
        if let Some(code) = &account_overrides.code {
            account_info.code = Some(Bytecode::new_raw(code.to_vec().into()));
        }
        if let Some(balance) = account_overrides.balance {
            account_info.balance = balance;
        }

        cache_db.insert_account_info(*account, account_info);

        // We ensure that not both state and state_diff are set.
        // If state is set, we must mark the account as "NewlyCreated", so that the old storage
        // isn't read from
        match (&account_overrides.state, &account_overrides.state_diff) {
            (Some(_), Some(_)) => {
                return Err(BlockchainError::StateOverrideError(
                    "state and state_diff can't be used together".to_string(),
                ))
            }
            (None, None) => (),
            (Some(new_account_state), None) => {
                cache_db.replace_account_storage(
                    *account,
                    new_account_state
                        .iter()
                        .map(|(key, value)| {
                            let value_u256: U256 = (*value).into();
                            ((*key).into(), value_u256.into())
                        })
                        .collect(),
                )?;
            }
            (None, Some(account_state_diff)) => {
                for (key, value) in account_state_diff {
                    let value_u256: U256 = (*value).into();
                    cache_db.insert_account_storage(*account, (*key).into(), value_u256.into())?;
                }
            }
        };
    }
    Ok(())
}

/// Applies the given block overrides to the env and updates overridden block hashes in the db.
pub fn apply_block_overrides<DB>(
    overrides: BlockOverrides,
    cache_db: &mut CacheDB<DB>,
    env: &mut BlockEnv,
) {
    let BlockOverrides {
        number,
        difficulty,
        time,
        gas_limit,
        coinbase,
        random,
        base_fee,
        block_hash,
    } = overrides;

    if let Some(block_hashes) = block_hash {
        // override block hashes
        cache_db
            .cache
            .block_hashes
            .extend(block_hashes.into_iter().map(|(num, hash)| (U256::from(num), hash)))
    }

    if let Some(number) = number {
        env.number = number.saturating_to();
    }
    if let Some(difficulty) = difficulty {
        env.difficulty = difficulty;
    }
    if let Some(time) = time {
        env.timestamp = time;
    }
    if let Some(gas_limit) = gas_limit {
        env.gas_limit = gas_limit;
    }
    if let Some(coinbase) = coinbase {
        env.beneficiary = coinbase;
    }
    if let Some(random) = random {
        env.prevrandao = Some(random);
    }
    if let Some(base_fee) = base_fee {
        env.basefee = base_fee.saturating_to();
    }
}
