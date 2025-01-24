use alloy_consensus::TxSeismic;
use alloy_dyn_abi::{Eip712Domain, Resolver, TypedData};
use alloy_primitives::{Address, Bytes, FixedBytes, PrimitiveSignature};
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TypedDataRequest {
    pub data: TypedData,
    pub signature: PrimitiveSignature,
}

/// Either a normal ETH call or a signed/serialized one
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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum SeismicSignature {
    // r, s, y_parity
    Primitive(PrimitiveSignature),
    // raw bytes
    // Bytes(Bytes),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeismicTxTypedData {
    domain: Eip712Domain,
    resolver: Resolver,
    primary_type: String,
    pub tx: TxSeismic,
    signing_hash: FixedBytes<32>,
}

impl SeismicTxTypedData {
    pub fn verify(&self, sig: &PrimitiveSignature) -> anyhow::Result<Address> {
        let vk = sig.recover_from_prehash(&self.signing_hash)?;
        let address = alloy_signer::utils::public_key_to_address(&vk);
        Ok(address)
    }
    
    pub fn from_typed_data(data: TypedData) -> anyhow::Result<Self> {
        let signing_hash = data.eip712_signing_hash()?;
        let tx = serde_json::from_value(data.message)?;
        Ok(Self {
            domain: data.domain,
            resolver: data.resolver,
            primary_type: data.primary_type,
            tx,
            signing_hash,
        })
    }
}

