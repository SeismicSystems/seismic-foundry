use crate::eth::error::BlockchainError;
use alloy_primitives::{Address, B256, U256};
use anvil_core::eth::transaction::seismic::SecretData;
use foundry_evm::revm::{
    precompile::{PrecompileSpecId, Precompiles},
    primitives::SpecId,
};
use seismic_preimages::{InputPreImage, PreImage, PreImageValue};
use seismic_types::{primitive::PrimitiveBytes, Secret};
use std::fmt;
// use anvil_core::eth::transaction::seismic::Seismic

pub fn get_precompiles_for(spec_id: SpecId) -> Vec<Address> {
    Precompiles::new(PrecompileSpecId::from_spec_id(spec_id)).addresses().copied().collect()
}

/// wrapper type that displays byte as hex
pub struct HexDisplay<'a>(&'a [u8]);

pub fn hex_fmt_many<I, T>(i: I) -> String
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    i.into_iter()
        .map(|item| HexDisplay::from(item.as_ref()).to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl<'a> HexDisplay<'a> {
    pub fn from(b: &'a [u8]) -> Self {
        HexDisplay(b)
    }
}

impl<'a> fmt::Display for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() < 1027 {
            for byte in self.0 {
                f.write_fmt(format_args!("{byte:02x}"))?;
            }
        } else {
            for byte in &self.0[0..512] {
                f.write_fmt(format_args!("{byte:02x}"))?;
            }
            f.write_str("...")?;
            for byte in &self.0[self.0.len() - 512..] {
                f.write_fmt(format_args!("{byte:02x}"))?;
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            f.write_fmt(format_args!("{byte:02x}"))?;
        }
        Ok(())
    }
}

pub fn get_commitment(value: U256) -> B256 {
    let secret = Secret::new(value);
    secret.commit_b256()
}

pub fn process_secret_data(
    secret_data: Vec<SecretData>,
    input: &[u8],
) -> Result<(), BlockchainError> {
    let input_pre_images = create_input_pre_images(&secret_data);
    let preimages = parse_preimages(&input_pre_images)?;
    let calculated_secrets = create_secrets(&preimages);

    let calculated_commitments = calculate_commitments(&calculated_secrets);
    let input_commitments = extract_input_commitments(&secret_data, input)?;

    verify_commitments(&calculated_commitments, &input_commitments)?;

    Ok(())
}

fn create_input_pre_images(secrets: &[SecretData]) -> Vec<InputPreImage> {
    secrets
        .iter()
        .map(|secret| InputPreImage {
            value: secret.preimage.clone(),
            type_: secret.preimage_type.clone(),
        })
        .collect()
}

fn parse_preimages(input_pre_images: &[InputPreImage]) -> Result<Vec<PreImage>, BlockchainError> {
    input_pre_images
        .iter()
        .map(|preimage| {
            preimage
                .parse()
                .map_err(|_| BlockchainError::Message("Failed to parse preimages".to_string()))
        })
        .collect()
}

fn create_secrets(preimages: &[PreImage]) -> Vec<Secret> {
    preimages
        .iter()
        .map(|pre_image| {
            Secret::from_bytes(match pre_image {
                PreImage::Bool(v) => v.to_bytes_vec(),
                PreImage::U8(v) => v.to_bytes_vec(),
                PreImage::U16(v) => v.to_bytes_vec(),
                PreImage::U32(v) => v.to_bytes_vec(),
                PreImage::U64(v) => v.to_bytes_vec(),
                PreImage::U128(v) => v.to_bytes_vec(),
                PreImage::U256(v) => v.to_bytes_vec(),
                PreImage::I8(v) => v.to_bytes_vec(),
                PreImage::I16(v) => v.to_bytes_vec(),
                PreImage::I32(v) => v.to_bytes_vec(),
                PreImage::I64(v) => v.to_bytes_vec(),
                PreImage::I128(v) => v.to_bytes_vec(),
                PreImage::I256(v) => v.to_bytes_vec(),
                PreImage::Address(v) => v.to_bytes_vec(),
            })
        })
        .collect()
}

fn calculate_commitments(secrets: &[Secret]) -> Vec<B256> {
    secrets.iter().map(|secret| secret.commit_b256()).collect()
}

fn extract_input_commitments(
    secret_data: &[SecretData],
    input: &[u8],
) -> Result<Vec<B256>, BlockchainError> {
    secret_data
        .iter()
        .map(|secret| {
            let index = secret.index as usize;
            let start = index;
            let end = start + 32;
            if end <= input.len() {
                Ok(B256::from_slice(&input[start..end]))
            } else {
                Err(BlockchainError::Message("Failed to calculate input commitments".to_string()))
            }
        })
        .collect()
}

fn verify_commitments(calculated: &[B256], input: &[B256]) -> Result<(), BlockchainError> {
    if calculated != input {
        Err(BlockchainError::Message(
            "Calculated commitments do not match input commitments".to_string(),
        ))
    } else {
        Ok(())
    }
}
