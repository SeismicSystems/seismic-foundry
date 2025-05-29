//! # anvil-core
//!
//! Core Ethereum types for Anvil.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// Various Ethereum types
pub mod eth;

/// Additional useful types
pub mod types;


/// Seismic overrides to types commonly found in anvil-core
pub type RpcTransaction = alloy_rpc_types::Transaction<seismic_alloy_consensus::SeismicTxEnvelope>;

#[derive(Clone, Debug, derive_more::From, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct AnyRpcTransaction(pub alloy_serde::WithOtherFields<RpcTransaction>);