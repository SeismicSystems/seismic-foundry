use std::str::FromStr;

use alloy_consensus::Signed;
use alloy_primitives::{FixedBytes, SignatureError};
use once_cell::sync::Lazy;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use seismic_transaction::transaction::SeismicTransaction;
use tee_service_api::{aes_decrypt, aes_encrypt, derive_aes_key, get_sample_secp256k1_pk, get_sample_secp256k1_sk};

static ENCRYPTION_KEY: Lazy<SecretKey> = Lazy::new(|| get_sample_secp256k1_sk());
static PUBLIC_KEY: Lazy<PublicKey> = Lazy::new(|| get_sample_secp256k1_pk());

pub fn encrypt(secret_key: &SecretKey, public_key: &PublicKey, plaintext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    let shared_secret = SharedSecret::new(public_key, secret_key);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    aes_encrypt(&aes_key, plaintext, nonce)
}

pub fn decrypt(secret_key: &SecretKey, public_key: &PublicKey, ciphertext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    let shared_secret = SharedSecret::new(public_key, secret_key);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    aes_decrypt(&aes_key, ciphertext, nonce)
}

pub fn server_decrypt(public_key: &PublicKey, ciphertext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    decrypt(&ENCRYPTION_KEY, public_key, ciphertext, nonce)
}

pub fn server_encrypt(public_key: &PublicKey, plaintext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    encrypt(&ENCRYPTION_KEY, public_key, plaintext, nonce)
}

pub fn client_decrypt(secret_key: &SecretKey, ciphertext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    decrypt(secret_key, &PUBLIC_KEY, ciphertext, nonce)
}

pub fn client_encrypt(secret_key: &SecretKey, plaintext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    encrypt(secret_key, &PUBLIC_KEY, plaintext, nonce)
}

pub fn secret_key(fixed_bytes: FixedBytes<32>) -> SecretKey {
    SecretKey::from_str(&fixed_bytes.to_string()).unwrap()
}

#[derive(Debug)]
pub enum RecoverPublicKeyError {
    Secp256K1(secp256k1::Error),
    SignatureError(SignatureError),
}

impl From<SignatureError> for RecoverPublicKeyError {
    fn from(value: SignatureError) -> Self {
        RecoverPublicKeyError::SignatureError(value)
    }
}

impl From<secp256k1::Error> for RecoverPublicKeyError {
    fn from(value: secp256k1::Error) -> Self {
        RecoverPublicKeyError::Secp256K1(value)
    }
}

/// Recover the public key from a signed seismic transaction
pub fn recover_public_key(tx: &Signed<SeismicTransaction>) -> Result<PublicKey, RecoverPublicKeyError> {
    let sighash = tx.signature_hash();
    let verifying_key = tx
        .signature()
        .recover_from_prehash(&sighash)?;
    let pk_bytes = verifying_key.to_sec1_bytes();
    let public_key = secp256k1::PublicKey::from_slice(&pk_bytes)?;
    Ok(public_key)
}
