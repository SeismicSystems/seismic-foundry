use alloy_dyn_abi::TypedData;
use alloy_primitives::{Bytes, PrimitiveSignature};
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TypedDataRequest {
    pub data: TypedData,
    pub signature: PrimitiveSignature,
}

// Either normal raw tx or typed data with signature
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum SeismicRawTxRequest {
    Bytes(Bytes),
    TypedData(TypedDataRequest),
}

/// Either a normal ETH call, raw tx, or typed data with signature
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum SeismicCallRequest {
    /// EIP-712 signed typed message with signature
    TypedData(TypedDataRequest),
    /// normal call request
    TransactionRequest(WithOtherFields<TransactionRequest>),
    /// signed raw seismic tx
    Bytes(Bytes),
}

impl Into<SeismicCallRequest> for TypedDataRequest {
    fn into(self) -> SeismicCallRequest {
        SeismicCallRequest::TypedData(self)
    }
}

impl Into<SeismicCallRequest> for WithOtherFields<TransactionRequest> {
    fn into(self) -> SeismicCallRequest {
        SeismicCallRequest::TransactionRequest(self)
    }
}

impl Into<SeismicCallRequest> for Bytes {
    fn into(self) -> SeismicCallRequest {
        SeismicCallRequest::Bytes(self)
    }
}
