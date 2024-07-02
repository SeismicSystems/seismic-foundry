use alloy_consensus::{SignableTransaction, Signed, Transaction, TxType};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{keccak256, Address, Bytes, ChainId, Signature, TxKind, B256, U256};
use alloy_rlp::{
    length_of_length, Decodable, Encodable, Error as DecodeError, Header as RlpHeader, BufMut, Header
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
    }

    /// Calculates the length of the RLP-encoded transaction's fields
    /// secret_data is not included in the length calculation since
    /// it is not part of the transaction's signature and hence
    /// not RLP-encoded.
    pub(crate) fn fields_len(&self) -> usize {
        let mut len = 0;
        len += self.chain_id.length();
        len += self.nonce.length();
        len += self.to.length();
        len += self.gas_limit.length();
        len += self.max_fee_per_gas.length();
        len += self.max_priority_fee_per_gas.length();
        len += self.value.length();
        len += self.access_list.length();
        len += self.input.length();
        len
    }

    /// Get transaction type
    pub(crate) const fn tx_type(&self) -> u8 {
        0x64 as u8
    }

    /// Encodes the transaction from RLP bytes, including the signature. This __does not__ encode a
    /// tx type byte or string header.
    ///
    /// This __does__ encode a list header and include a signature.
    pub(crate) fn encode_with_signature_fields(&self, signature: &Signature, out: &mut dyn BufMut) {
        let payload_length = self.fields_len() + signature.rlp_vrs_len();
        let header = Header { list: true, payload_length };
        header.encode(out);
        self.encode_fields(out);
        signature.write_rlp_vrs(out);
    }

     /// Returns what the encoded length should be, if the transaction were RLP encoded with the
    /// given signature, depending on the value of `with_header`.
    ///
    /// If `with_header` is `true`, the payload length will include the RLP header length.
    /// If `with_header` is `false`, the payload length will not include the RLP header length.
    fn encoded_len_with_signature(
        &self,
        signature: &Signature,
        with_header: bool,
    ) -> usize {
        // this counts the tx fields and signature fields
        let payload_length = self.fields_len() + signature.rlp_vrs_len();

        // this counts:
        // * tx type byte
        // * inner header length
        // * inner payload length
        let inner_payload_length =
            1 + Header { list: true, payload_length }.length() + payload_length;

        if with_header {
            // header length plus length of the above, wrapped with a string header
            Header { list: false, payload_length: inner_payload_length }.length()
                + inner_payload_length
        } else {
            inner_payload_length
        }
    }

    pub fn encode_with_signature(
        &self,
        signature: &Signature,
        out: &mut dyn BufMut,
        with_header: bool,
    ) {
        let payload_length = self.fields_len() + signature.rlp_vrs_len();
        if with_header {
            Header {
                list: false,
                payload_length: 1 + Header { list: true, payload_length }.length() + payload_length,
            }
            .encode(out);
        }
        self.encode_with_signature_fields(signature, out);
    }

    pub fn into_signed_without_secrets(self, signature: Signature) -> Signed<SeismicTransaction> {
        let mut buf = Vec::with_capacity(self.encoded_len_with_signature(&signature, false));
        self.encode_with_signature(&signature, &mut buf, false);
        let hash = keccak256(&buf);
        let seismic_tx_without_secrets = SeismicTransaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            to: self.to,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: self.value,
            access_list: self.access_list.clone(),
            input: self.input.clone(),
        };

        // Drop any v chain id value to ensure the signature format is correct at the time of
        // combination for an EIP-1559 transaction. V should indicate the y-parity of the
        // signature.
        Signed::new_unchecked(seismic_tx_without_secrets, signature.with_parity_bool(), hash)
    }

}

impl Transaction for SeismicTransactionRequest {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u128 {
        self.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn to(&self) -> TxKind {
        self.to
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn input(&self) -> &[u8] {
        &self.input
    }
}

impl Encodable for SeismicTransactionRequest {
    fn encode(&self, out: &mut dyn BufMut) {
        Header { list: true, payload_length: self.fields_len() }.encode(out);
        self.encode_fields(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.fields_len();
        Header { list: true, payload_length }.length() + payload_length
    }
}

impl SignableTransaction<Signature> for SeismicTransactionRequest {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(self.tx_type());
        self.encode(out)
    }

    fn payload_len_for_signature(&self) -> usize {
        self.length() + 1
    }

    fn into_signed(self, _signature: Signature) -> Signed<Self> { 
    unimplemented!() // we keep this unimplemented because we don't need the secret data field and hence Signed<SeismicTransactionRequest> is of no use to us
    }

}



///
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
}

impl SeismicTransaction {
    // pub fn hash(&self) -> B256 {
    //     B256::from_slice(alloy_primitives::keccak256(alloy_rlp::encode(self)).as_slice())
    // } -- not necessary for now

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
    }

    /// Calculates the length of the RLP-encoded transaction's fields
    /// secret_data is not included in the length calculation since
    /// it is not part of the transaction's signature and hence
    /// not RLP-encoded.
    pub(crate) fn fields_len(&self) -> usize {
        let mut len = 0;
        len += self.chain_id.length();
        len += self.nonce.length();
        len += self.to.length();
        len += self.gas_limit.length();
        len += self.max_fee_per_gas.length();
        len += self.max_priority_fee_per_gas.length();
        len += self.value.length();
        len += self.access_list.length();
        len += self.input.length();
        len
    }

    /// Get transaction type
    pub(crate) const fn tx_type(&self) -> TxType {
        TxType::Eip1559
    }

    /// Encodes the transaction from RLP bytes, including the signature. This __does not__ encode a
    /// tx type byte or string header.
    ///
    /// This __does__ encode a list header and include a signature.
    pub(crate) fn encode_with_signature_fields(&self, signature: &Signature, out: &mut dyn BufMut) {
        let payload_length = self.fields_len() + signature.rlp_vrs_len();
        let header = Header { list: true, payload_length };
        header.encode(out);
        self.encode_fields(out);
        signature.write_rlp_vrs(out);
    }

     /// Returns what the encoded length should be, if the transaction were RLP encoded with the
    /// given signature, depending on the value of `with_header`.
    ///
    /// If `with_header` is `true`, the payload length will include the RLP header length.
    /// If `with_header` is `false`, the payload length will not include the RLP header length.
    fn encoded_len_with_signature(
        &self,
        signature: &Signature,
        with_header: bool,
    ) -> usize {
        // this counts the tx fields and signature fields
        let payload_length = self.fields_len() + signature.rlp_vrs_len();

        // this counts:
        // * tx type byte
        // * inner header length
        // * inner payload length
        let inner_payload_length =
            1 + Header { list: true, payload_length }.length() + payload_length;

        if with_header {
            // header length plus length of the above, wrapped with a string header
            Header { list: false, payload_length: inner_payload_length }.length()
                + inner_payload_length
        } else {
            inner_payload_length
        }
    }

    pub fn encode_with_signature(
        &self,
        signature: &Signature,
        out: &mut dyn BufMut,
        with_header: bool,
    ) {
        let payload_length = self.fields_len() + signature.rlp_vrs_len();
        if with_header {
            Header {
                list: false,
                payload_length: 1 + Header { list: true, payload_length }.length() + payload_length,
            }
            .encode(out);
        }
        self.encode_with_signature_fields(signature, out);
    }


}

impl Transaction for SeismicTransaction {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u128 {
        self.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None
    }

    fn to(&self) -> TxKind {
        self.to
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn input(&self) -> &[u8] {
        &self.input
    }
}

impl SignableTransaction<Signature> for SeismicTransaction {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        unimplemented!()
    }

    fn payload_len_for_signature(&self) -> usize {
        unimplemented!()
    }

    fn into_signed(self, _signature: Signature) -> Signed<Self> { 
    unimplemented!() 
    }

}

pub fn encode_2718_seismic_transaction(tx: &Signed<SeismicTransaction>, out: &mut dyn alloy_rlp::BufMut){
        tx.tx().encode_with_signature(tx.signature(), out, false);
}

pub fn encode_2718_len(tx: &Signed<SeismicTransaction>) -> usize {
    let payload_length = tx.tx().fields_len() + tx.signature().rlp_vrs_len();
    Header { list: true, payload_length }.length() + payload_length + 1
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
