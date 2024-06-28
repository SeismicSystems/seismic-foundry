use alloy_consensus::{SignableTransaction, Signed, Transaction, TxType};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{keccak256, Address, Bytes, ChainId, Signature, TxKind, B256, U256};
use alloy_rlp::{
    length_of_length, Decodable, Encodable, Error as DecodeError, Header as RlpHeader,
};
use serde::{Deserialize, Serialize};
use std::mem;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeismicTransactionRequest {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub to: TxKind,
    pub gas_limit: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub value: U256,
    pub access_list: AccessList,
    pub input: Bytes,
    pub secret_data: Vec<SecretData>,
}

impl SeismicTransactionRequest {
    pub fn hash(&self) -> B256 {
        B256::from_slice(alloy_primitives::keccak256(alloy_rlp::encode(self)).as_slice())
    }

    /// Encodes only the transaction's fields into the desired buffer, without a RLP header.
    pub(crate) fn encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.value.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.secret_data.encode(out);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeismicTransaction {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub to: TxKind,
    pub gas_limit: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub value: U256,
    pub access_list: AccessList,
    pub input: Bytes,
    pub secret_data: Vec<SecretData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretData {
    pub index: usize,
    pub preimage: Bytes,
}

impl Encodable for SecretData {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.index.encode(out);
        self.preimage.encode(out);
    }

    fn length(&self) -> usize {
        self.index.length() + self.preimage.length()
    }
}
