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

/// Generates a vector of cryptographically secure random bytes with the specified size.
///
/// Relies on the operating system’s secure random number generator (`OsRng`)
/// to populate a buffer with unpredictable byte values.
///
/// # Arguments
/// * `length` - The number of random bytes to produce.
///
/// # Returns
/// A `Result` containing a `Vec<u8>` with the securely generated random bytes,
/// or an error if random byte generation fails.
///
/// # Errors
/// Returns an error if the operating system’s random number generator is unavailable
/// or fails to provide sufficient entropy.
pub fn get_random_val(length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut val = vec![0u8; length];
    OsRng.try_fill_bytes(&mut val)?;
    Ok(val)
}

/// Generates a 12-byte cryptographically secure random nonce.
///
/// Commonly used in AEAD encryption algorithms that require a 96-bit nonce for
/// ensuring uniqueness and preventing replay attacks.
///
/// # Returns
/// A `Result` containing a `Vec<u8>` with 12 securely generated random bytes,
/// or an error if random byte generation fails.
///
/// # Errors
/// Returns an error if the operating system’s random number generator is unavailable
/// or fails to provide sufficient entropy.

pub fn get_nonce() -> Result<Vec<u8>, Box<dyn Error>> {
    get_random_val(12)
}

/// Generates a 16-byte cryptographically secure random salt.
///
/// Typically used in key derivation functions (KDFs) that require a 128-bit salt to
/// introduce randomness and defend against precomputation attacks.
///
/// # Returns
/// A `Result` containing a `Vec<u8>` with 16 securely generated random bytes,
/// or an error if random byte generation fails.
///
/// # Errors
/// Returns an error if the operating system’s random number generator is unavailable
/// or fails to provide sufficient entropy.

pub fn get_salt() -> Result<Vec<u8>, Box<dyn Error>> {
    get_random_val(16)
}
