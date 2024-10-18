use alloy_serde::{OtherFields, WithOtherFields};
use seismic_transaction::{seismic_util::encrypt, types::SeismicTransactionFields};

impl From<SeismicTransactionFields> for OtherFields {
    fn from(value: SeismicTransactionFields) -> Self {
        serde_json::to_value(value).unwrap().try_into().unwrap()
    }
}