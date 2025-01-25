use alloy_consensus::{transaction::TxSeismic, Signed};
use alloy_primitives::{FixedBytes, SignatureError};
use once_cell::sync::Lazy;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use tee_service_api::{
    aes_decrypt, aes_encrypt, derive_aes_key, get_sample_secp256k1_pk, get_sample_secp256k1_sk,
    nonce::Nonce,
};

static ENCRYPTION_KEY: Lazy<SecretKey> = Lazy::new(|| get_sample_secp256k1_sk());
static PUBLIC_KEY: Lazy<PublicKey> = Lazy::new(|| get_sample_secp256k1_pk());

pub fn encrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    plaintext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Ok(vec![])
    }
    let shared_secret = SharedSecret::new(public_key, secret_key);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    aes_encrypt(&aes_key, plaintext, nonce)
}

pub fn decrypt(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    ciphertext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    let shared_secret = SharedSecret::new(public_key, secret_key);
    let aes_key = derive_aes_key(&shared_secret)
        .map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    aes_decrypt(&aes_key, ciphertext, nonce)
}

pub fn server_decrypt(
    public_key: &PublicKey,
    ciphertext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    if ciphertext.is_empty() {
        return Ok(vec![])
    }
    decrypt(&ENCRYPTION_KEY, public_key, ciphertext, nonce)
}

pub fn server_encrypt(
    public_key: &PublicKey,
    plaintext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    encrypt(&ENCRYPTION_KEY, public_key, plaintext, nonce)
}

pub fn client_decrypt(
    secret_key: &SecretKey,
    ciphertext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    decrypt(secret_key, &PUBLIC_KEY, ciphertext, nonce)
}

pub fn client_encrypt(
    secret_key: &SecretKey,
    plaintext: &[u8],
    nonce: impl Into<Nonce>,
) -> anyhow::Result<Vec<u8>> {
    encrypt(secret_key, &PUBLIC_KEY, plaintext, nonce)
}

pub fn secret_key(fixed_bytes: &FixedBytes<32>) -> SecretKey {
    SecretKey::from_slice(&fixed_bytes.to_vec()[..]).unwrap()
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
pub fn recover_public_key(tx: &Signed<TxSeismic>) -> Result<PublicKey, RecoverPublicKeyError> {
    let sighash = tx.signature_hash();
    let verifying_key = tx.signature().recover_from_prehash(&sighash)?;
    let pk_bytes = verifying_key.to_sec1_bytes();
    let public_key = secp256k1::PublicKey::from_slice(&pk_bytes)?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::ecdh::shared_secret_point;
    use std::str::FromStr;

    #[test]
    fn test_aes_keygen() {
        let pk1 = secp256k1::PublicKey::from_str(
            // network pk
            "028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0",
        )
        .unwrap();
        let sk1 = secp256k1::SecretKey::from_str(
            // user sk
            "a30363336e1bb949185292a2a302de86e447d98f3a43d823c8c234d9e3e5ad77",
        )
        .unwrap();
        let pt1 = shared_secret_point(&pk1, &sk1);
        let ss1 = SharedSecret::new(&pk1, &sk1);
        let aes1 = derive_aes_key(&ss1).unwrap();

        let pk2 = secp256k1::PublicKey::from_str(
            // user pk
            "025f210a5daaca346fa1fd8d6ea36e813e756ea34659fe42c757de4e6ed1d0903c",
        )
        .unwrap();
        let sk2 = secp256k1::SecretKey::from_str(
            // network sk
            "311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505",
        )
        .unwrap();
        let pt2 = shared_secret_point(&pk2, &sk2);
        let ss2 = SharedSecret::new(&pk2, &sk2);
        let aes2 = derive_aes_key(&ss2).unwrap();

        assert_eq!(pt1, pt2);
        assert_eq!(ss1, ss2);
        assert_eq!(aes1, aes2);
        // let version = (pt1[63] & 0x01) | 0x02;
        // println!("version = {}", version);
    }
}
