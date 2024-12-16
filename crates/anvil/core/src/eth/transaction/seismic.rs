use once_cell::sync::Lazy;
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use tee_service_api::{aes_decrypt, aes_encrypt, derive_aes_key, get_sample_secp256k1_sk}; 

static ENCRYPTION_KEY: Lazy<SecretKey> = Lazy::new(|| {
    get_sample_secp256k1_sk()
});

pub fn encrypt(public_key: &PublicKey, plaintext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    let shared_secret = SharedSecret::new(public_key, &ENCRYPTION_KEY);
    let aes_key = derive_aes_key(&shared_secret).map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    aes_encrypt(&aes_key, plaintext, nonce)
}

pub fn decrypt(public_key: &PublicKey, ciphertext: &[u8], nonce: u64) -> anyhow::Result<Vec<u8>> {
    println!("Encryption key = {:?}", &ENCRYPTION_KEY);
    let shared_secret = SharedSecret::new(public_key, &ENCRYPTION_KEY);
    let aes_key = derive_aes_key(&shared_secret).map_err(|e| anyhow::anyhow!("Error deriving AES key: {:?}", e))?;
    println!("AES Key = {:?}", aes_key);
    println!("Nonce = {}, Ciphertext = {:?}", nonce, ciphertext);
    aes_decrypt(&aes_key, ciphertext, nonce)
}
