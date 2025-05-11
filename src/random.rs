use rand::rngs::OsRng;
use rand::RngCore;

/// Generates a cryptographically secure random byte vector of the specified length.
///
/// Uses the operating system's cryptographically secure random number generator (`OsRng`)
/// to fill a buffer with random bytes.
///
/// # Arguments
/// * `length` - Number of random bytes to generate.
///
/// # Returns
/// A `Vec<u8>` containing the generated random bytes.
///
/// # Panics
/// May panic if the OS random number generator fails, though this is highly unlikely.
pub fn get_random_val(length: usize) -> Vec<u8> {
    let mut val = vec![0u8; length];
    OsRng.fill_bytes(&mut val);
    val
}

/// Generates a 12-byte cryptographically secure random nonce.
///
/// This is typically used for AEAD encryption schemes that require a 96-bit (12-byte) nonce.
///
/// # Returns
/// A `Vec<u8>` containing 12 securely generated random bytes.
pub fn get_nonce() -> Vec<u8> {
    get_random_val(12)
}

/// Generates a 16-byte cryptographically secure random salt.
///
/// This is typically used for KDF schemes that require a 128-bit (16-byte) nonce.
///
/// # Returns
/// A `Vec<u8>` containing 16 securely generated random bytes.
pub fn get_salt() -> Vec<u8> {
    get_random_val(16)
}
