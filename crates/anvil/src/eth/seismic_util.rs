use crate::eth::error::BlockchainError;
use alloy_primitives::{B256, U256};
use anvil_core::eth::transaction::seismic::SecretData;
use seismic_preimages::{InputPreImage, PreImage};
use seismic_types::{primitive::PrimitiveBytes, Secret};
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
