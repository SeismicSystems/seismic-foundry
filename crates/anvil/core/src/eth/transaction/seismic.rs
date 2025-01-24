use alloy_consensus::TxSeismic;
use alloy_dyn_abi::{Eip712Domain, Resolver, TypedData};
use alloy_primitives::{Address, Bytes, FixedBytes, PrimitiveSignature};
use alloy_rpc_types::TransactionRequest;
use alloy_serde::WithOtherFields;
use serde::{Deserialize, Serialize};

/// Either a normal ETH call or a signed/serialized one
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum SeismicCallRequest {
    /// signed raw seismic tx
    Bytes(Bytes),
    /// normal call request
    TransactionRequest(WithOtherFields<TransactionRequest>),
    /// EIP-712 signed typed message with signature
    TypedData {
        data: TypedData,
        #[serde(flatten)]
        signature: SeismicSignature,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum SeismicSignature {
    // r, s, y_parity
    Primitive(PrimitiveSignature),
    // raw bytes
    // Bytes(Bytes),
}

impl SeismicSignature {
    pub fn to_bytes(&self) -> anyhow::Result<Bytes> {
        match self {
            SeismicSignature::Primitive(sig) => match sig.to_k256() {
                Ok(sig) => Ok(Bytes::from(sig.to_bytes().to_vec())),
                Err(e) => return Err(e.into()),
            },
            // SeismicSignature::Bytes(bytes) => Ok(bytes.clone()),
        }
    }

    pub fn verify(&self, data: &SeismicTxTypedData) -> anyhow::Result<Address> {
        let vk = match self {
            SeismicSignature::Primitive(sig) => sig.recover_from_prehash(&data.signing_hash)?,
        };
        let address = alloy_signer::utils::public_key_to_address(&vk);
        if data.tx.from != address {
            return Err(anyhow::anyhow!("signer mismatch"));
        }
        Ok(address)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeismicTxRequest {
    from: Address,
    #[serde(flatten)]
    pub inner: TxSeismic,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeismicTxTypedData {
    domain: Eip712Domain,
    resolver: Resolver,
    primary_type: String,
    pub tx: SeismicTxRequest,
    signing_hash: FixedBytes<32>,
}

impl SeismicTxTypedData {
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

impl Into<TransactionRequest> for SeismicTxRequest {
    fn into(self) -> TransactionRequest {
        TransactionRequest {
            from: Some(self.from),
            to: self.inner.to.into(),
            gas_price: Some(self.inner.gas_price),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee_per_blob_gas: None,
            gas: Some(self.inner.gas_limit),
            value: Some(self.inner.value),
            input: self.inner.input.into(),
            nonce: Some(self.inner.nonce),
            chain_id: Some(self.inner.chain_id),
            access_list: None,
            transaction_type: None,
            blob_versioned_hashes: None,
            sidecar: None,
            authorization_list: None,
            encryption_pubkey: Some(self.inner.encryption_pubkey),
        }
    }
}
