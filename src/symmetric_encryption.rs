use aead::{generic_array::GenericArray, Aead, AeadCore, Error as AeadError, KeyInit, KeySizeUser};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use typenum::Unsigned;

use crate::constants::*;

/// Performs authenticated encryption or decryption using the specified AEAD cipher.
///
/// This function provides a generic interface over AEAD algorithms that implement
/// the `Aead`, `KeyInit`, `AeadCore`, and `KeySizeUser` traits. It supports both
/// encryption and decryption based on the `encrypt` flag.
///
/// # Parameters
/// - `key`: The encryption key; must be the correct size for the AEAD cipher.
/// - `nonce`: Optional nonce; required for encryption and must match the AEAD cipher's nonce size.
/// - `data`: The input data to encrypt or decrypt.
/// - `aad`: Optional associated data; used for authentication but not encrypted.
/// - `encrypt`: A boolean flag indicating whether to encrypt (`true`) or decrypt (`false`).
///
/// # Returns
/// - `Ok(Vec<u8>)`: Encrypted ciphertext with prepended nonce (on encryption), or plaintext (on decryption).
/// - `Err(AeadError)`: If encryption or decryption fails, or input sizes are invalid.
///
/// # Panics
/// Panics if key or nonce sizes do not match the expected sizes for the cipher.
fn aead_base<C>(
    key: &[u8],
    nonce: Option<&[u8]>,
    data: &[u8],
    aad: Option<&[u8]>,
    encrypt: bool,
) -> Result<Vec<u8>, AeadError>
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

    if let Some(nonce) = nonce {
        assert_eq!(
            nonce.len(),
            nonce_len,
            "nonce must be {} bytes, got {} bytes",
            nonce_len,
            nonce.len()
        );
    }

    let key_arr = GenericArray::clone_from_slice(key);
    let cipher = C::new(&key_arr);

    let aad = aad.unwrap_or(&[]); // Default to empty AAD if not provided

    if encrypt {
        let nonce_arr = GenericArray::from_slice(nonce.unwrap());
        let ciphertext = cipher.encrypt(nonce_arr, aead::Payload { msg: data, aad })?;

        let mut out = Vec::with_capacity(nonce_len + ciphertext.len());
        out.extend_from_slice(nonce.unwrap());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    } else {
        if data.len() < nonce_len {
            return Err(AeadError);
        }
        let (nonce_bytes, ciphertext) = data.split_at(nonce_len);
        let nonce_arr = GenericArray::from_slice(nonce_bytes);
        cipher.decrypt(
            nonce_arr,
            aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
    }
}

/// Encrypts data using the specified AEAD algorithm identified by `alg_id`.
///
/// This function wraps `aead_base` to support algorithm selection via a numeric ID.
/// It performs authenticated encryption using AES-GCM or ChaCha20-Poly1305 based on the input.
///
/// # Parameters
/// - `alg_id`: Identifier for the AEAD algorithm (e.g., `AES_GCM_ID`, `CHA_CHA_20_POLY_1305_ID`).
/// - `key`: Encryption key; must match the key size required by the chosen algorithm.
/// - `nonce`: Nonce; must match the required nonce size (typically 12 bytes).
/// - `data`: Plaintext data to encrypt.
/// - `aad`: Optional associated data for authentication (not encrypted).
///
/// # Returns
/// - `Ok(Vec<u8>)`: The resulting ciphertext with the nonce prepended (as handled in `aead_base`).
/// - `Err(aead::Error)`: If encryption fails due to input validation or AEAD operation.
///
/// # Panics
/// Panics if an unsupported algorithm ID is provided.
pub fn id_encrypt(
    alg_id: u8,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, aead::Error> {
    match alg_id {
        AES_GCM_ID => aead_base::<Aes256Gcm>(key, Some(nonce), data, aad, true),
        CHA_CHA_20_POLY_1305_ID => aead_base::<ChaCha20Poly1305>(key, Some(nonce), data, aad, true),
        _ => panic!(
            "Attempted encryption with unsupported algorithm ID: {}",
            alg_id
        ),
    }
}

/// Decrypts data using the specified AEAD algorithm identified by `alg_id`.
///
/// This function wraps `aead_base` to support algorithm selection via a numeric ID.
/// It performs authenticated decryption using AES-GCM or ChaCha20-Poly1305 based on the input.
///
/// # Parameters
/// - `alg_id`: Identifier for the AEAD algorithm (e.g., `AES_GCM_ID`, `CHA_CHA_20_POLY_1305_ID`).
/// - `key`: Decryption key; must match the key size required by the chosen algorithm.
/// - `data`: Ciphertext with the nonce prepended (as expected by `aead_base`).
/// - `aad`: Optional associated data that was authenticated during encryption.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The decrypted plaintext if authentication and decryption succeed.
/// - `Err(aead::Error)`: If decryption or authentication fails (e.g., due to tampering).
///
/// # Panics
/// Panics if an unsupported algorithm ID is provided.
pub fn id_decrypt(
    alg_id: u8,
    key: &[u8],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, aead::Error> {
    match alg_id {
        AES_GCM_ID => aead_base::<Aes256Gcm>(key, None, data, aad, false),
        CHA_CHA_20_POLY_1305_ID => aead_base::<ChaCha20Poly1305>(key, None, data, aad, false),
        _ => panic!(
            "Attempted decryption with unsupported algorithm ID: {}",
            alg_id
        ),
    }
}

// Tests for aeads
#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_aes_gcm_kat_encrypt_decrypt() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex!("000000000000000000000000");
        let plaintext = hex!("00000000000000000000000000000000");

        // NIST: Ciphertext (16 bytes) + Tag (16 bytes)
        let expected_ciphertext =
            hex!("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        // Our encrypt prepends nonce, so expected output is nonce || expected_ciphertext
        let expected_output = [&nonce[..], &expected_ciphertext[..]].concat();

        let ciphertext_with_nonce = id_encrypt(AES_GCM_ID, &key, &nonce, &plaintext, None).unwrap();

        assert_eq!(
            ciphertext_with_nonce, expected_output,
            "AES-GCM ciphertext (with nonce) does not match expected"
        );

        // Decrypt using full buffer: nonce + ciphertext + tag
        let decrypted_plaintext =
            id_decrypt(AES_GCM_ID, &key, &ciphertext_with_nonce, None).unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Decrypted plaintext does not match original"
        );
    }

    #[test]
    fn test_chacha_20_kat_encrypt_decrypt() {
        let key = hex!(
            "1c9240a5eb55d38af333888604f6b5f0
         473917c1402b80099dca5cbc207075c0"
        );
        let nonce = hex!("000000000102030405060708");
        let plaintext =
            hex!("496e7465726e65742d4472616674732061726520647261667420646f63756d656e7473");

        // Correct ciphertext (from RFC 8439) + tag (no AAD used in our implementation)
        let expected_ciphertext = hex!("00000000010203040506070864a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfce39ab006ad7516926f09107c693cc136")
;

        let ciphertext =
            id_encrypt(CHA_CHA_20_POLY_1305_ID, &key, &nonce, &plaintext, None).unwrap();

        assert_eq!(
            ciphertext, expected_ciphertext,
            "ChaCha20Poly1305 ciphertext (with nonce) does not match expected"
        );

        let decrypted_plaintext =
            id_decrypt(CHA_CHA_20_POLY_1305_ID, &key, &ciphertext, None).unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Decrypted plaintext does not match original"
        );
    }

    #[test]
    #[should_panic(expected = "Attempted encryption with unsupported algorithm ID")]
    fn test_encrypt_with_invalid_algorithm() {
        let _ = id_encrypt(99, b"key", b"nonce", b"data", None);
    }

    #[test]
    #[should_panic(expected = "Attempted decryption with unsupported algorithm ID")]
    fn test_decrypt_with_invalid_algorithm() {
        let _ = id_decrypt(99, b"key", b"data", None);
    }
}
