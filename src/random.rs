// random.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Utilities for generating cryptographically secure random values,
// including salts, nonces, and arbitrary-length byte sequences.

use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;

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
pub fn get_random_val(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut val = vec![0u8; length];
    OsRng.fill_bytes(&mut val);
    Ok(val)
}

/// Generates a 12-byte cryptographically secure random nonce.
///
/// This is typically used for AEAD encryption schemes that require a 96-bit (12-byte) nonce.
///
/// # Returns
/// A `Vec<u8>` containing 12 securely generated random bytes.
pub fn get_nonce() -> Result<Vec<u8>, Box<dyn Error>> {
    get_random_val(12)
}

/// Generates a 16-byte cryptographically secure random salt.
///
/// This is typically used for KDF schemes that require a 128-bit (16-byte) nonce.
///
/// # Returns
/// A `Vec<u8>` containing 16 securely generated random bytes.
pub fn get_salt() -> Result<Vec<u8>, Box<dyn Error>> {
    get_random_val(16)
}
