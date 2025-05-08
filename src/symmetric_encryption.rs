use aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, KeySizeUser};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use typenum::Unsigned;

use zeroize::Zeroizing;

/// Base function for AEAD encryption and decryption.
///
/// # Arguments
/// * `key` - Encryption/decryption key as bytes.
/// * `nonce` - Nonce as bytes.
/// * `data` - Plaintext or ciphertext depending on mode.
/// * `mode` - `true` for encryption, `false` for decryption.
///
/// # Returns
/// * `Ok(Vec<u8>)` with the result, or `Err(aead::Error)` if the operation fails.
fn aead_base<C>(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<Vec<u8>, aead::Error>
where
    C: Aead + KeyInit + AeadCore + KeySizeUser,
{
    let key_len = <C as KeySizeUser>::KeySize::to_usize();
    let nonce_len = <C as AeadCore>::NonceSize::to_usize();

    assert_eq!(
        key.len(),
        key_len,
        "key must be {} bytes, got {} bytes",
        key_len,
        key.len()
    );
    assert_eq!(
        nonce.len(),
        nonce_len,
        "nonce must be {} bytes, got {} bytes",
        nonce_len,
        nonce.len()
    );

    let key_arr = Zeroizing::new(GenericArray::clone_from_slice(key));
    let nonce_arr = GenericArray::from_slice(nonce);
    let cipher = C::new(&key_arr);

    if encrypt {
        cipher.encrypt(nonce_arr, data)
    } else {
        cipher.decrypt(nonce_arr, data)
    }
}

pub fn aes_gcm_enc(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    aead_base::<Aes256Gcm>(key, nonce, data, true)
}

pub fn aes_gcm_dec(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    aead_base::<Aes256Gcm>(key, nonce, ciphertext, false)
}

pub fn chacha20poly1305_enc(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    aead_base::<ChaCha20Poly1305>(key, nonce, data, true)
}

pub fn chacha20poly1305_dec(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    aead_base::<ChaCha20Poly1305>(key, nonce, ciphertext, false)
}
