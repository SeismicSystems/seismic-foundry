//! Seismic overrides to types commonly used in foundry
//! We do this to reduce future merge conflicts
use alloy_network::AnyRpcHeader;
use alloy_rpc_types_eth::{Block, Header};
use alloy_serde::WithOtherFields;
use derive_more::From;
use serde::{Deserialize, Serialize};

pub use seismic_alloy_rpc_types::SeismicTransactionRequest as TransactionRequest;

pub type RpcTransaction = alloy_rpc_types::Transaction<seismic_alloy_consensus::SeismicTxEnvelope>;

#[derive(Clone, Debug, From, PartialEq, Eq, Deserialize, Serialize)]
pub struct AnyRpcTransaction(pub alloy_serde::WithOtherFields<RpcTransaction>);


#[derive(Clone, Debug, From, PartialEq, Eq, Deserialize, Serialize)]
pub struct AnyRpcBlock(pub WithOtherFields<Block<RpcTransaction, Header>>);

/*
alloy_rpc_types::Transaction<seismic_alloy_consensus::transaction::envelope::SeismicTxEnvelope>

*/