// key_derivation.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Implements key derivation functions (KDFs) including support for
// algorithms like Argon2 and PBKDF2.

use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::constants::*;

/// Derives a symmetric key from a password using the Argon2id key derivation function.
///
/// This function applies the Argon2id algorithm with customizable parameters to derive a key
/// of the specified length from the provided password and salt.
///
/// # Arguments
///
/// * `password` - A secret string containing the user password.
/// * `salt` - A byte slice used as the cryptographic salt.
/// * `dklen` - Desired length of the derived key in bytes.
/// * `mem_cost` - Optional memory cost (in KiB) for Argon2 (default: 256 * 1024).
/// * `t_cost` - Optional number of iterations (default: 8).
/// * `par` - Optional level of parallelism (default: 4).
///
/// # Returns
///
/// * `Secret<Vec<u8>>` - The derived symmetric key, wrapped in a `Secret` for secure handling.
///
/// # Panics
///
/// This function will panic if:
/// - The Argon2 parameters are invalid.
/// - The key derivation process fails.
///
/// # Security
///
/// The derived key is zeroized in memory after being wrapped in `Secret`.
fn argon2_derive_key(
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    mem_cost: Option<u32>,
    t_cost: Option<u32>,
    par: Option<u32>,
) -> Result<Secret<Vec<u8>>, Box<dyn std::error::Error>> {
    // Default values
    let memory_cost = match mem_cost {
        Some(n) => n,
        None => 256 * 1024,
    };
    let time_cost = match t_cost {
        Some(n) => n,
        None => 8,
    };
    let parallelism = match par {
        Some(n) => n,
        None => 4,
    };

    let params = Params::new(memory_cost, time_cost, parallelism, Some(dklen))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; dklen];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_e| "Argon2 hashing failed")?;

    let secret_key = Secret::new(key.clone());
    key.zeroize();
    Ok(secret_key)
}

/// Derives a symmetric key from a password using PBKDF2 with HMAC-SHA256.
///
/// This function uses the PBKDF2 algorithm to derive a fixed-length key from a password
/// and cryptographic salt, with a configurable number of iterations.
///
/// # Arguments
///
/// * `password` - A secret string representing the user password.
/// * `salt` - A byte slice used as the salt in key derivation.
/// * `dklen` - Desired length of the derived key in bytes.
/// * `iters` - Optional number of iterations (default: 100,000).
///
/// # Returns
///
/// * `Secret<Vec<u8>>` - The derived symmetric key, wrapped in a `Secret` for secure memory handling.
///
/// # Security
///
/// The derived key is zeroized in memory after being securely wrapped in `Secret`.
fn pbkdf2_derive_key(
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    iters: Option<u32>,
) -> Result<Secret<Vec<u8>>, Box<dyn std::error::Error>> {
    let iterations = match iters {
        Some(n) => n,
        None => 600_000,
    };

    let mut key = vec![0u8; dklen];
    pbkdf2_hmac::<Sha256>(
        password.expose_secret().as_bytes(),
        salt,
        iterations,
        &mut key,
    );

    let secret_key = Secret::new(key.clone());
    key.zeroize();

    Ok(secret_key)
}

/// Derives a symmetric key from a password using the specified key derivation algorithm.
///
/// This function dispatches to the appropriate key derivation function (Argon2id or PBKDF2)
/// based on the provided `alg_id`. Parameters specific to each algorithm must be passed in
/// via the `params` map.
///
/// # Arguments
///
/// * `alg_id` - Identifier for the key derivation algorithm (e.g., `ARGON2_ID`, `PBKDF2_ID`).
/// * `password` - A secret string containing the user password.
/// * `salt` - A byte slice used as the cryptographic salt.
/// * `dklen` - Desired length of the derived key in bytes.
/// * `params` - A map of parameter names to values:
///   - For Argon2id: `"memory_cost"`, `"time_cost"`, `"parallelism"`
///   - For PBKDF2: `"iterations"`
///
/// # Returns
///
/// * `Secret<Vec<u8>>` - The derived symmetric key, securely wrapped in a `Secret`.
///
/// # Panics
///
/// This function panics if the `alg_id` does not correspond to a supported KDF.
pub fn id_derive_key(
    alg_id: u8,
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    params: &HashMap<String, u32>,
) -> Result<Secret<Vec<u8>>, Box<dyn std::error::Error>> {
    match alg_id {
        ARGON2_ID => argon2_derive_key(
            password,
            salt,
            dklen,
            params.get("memory_cost").copied(),
            params.get("time_cost").copied(),
            params.get("parallelism").copied(),
        ),
        PBKDF2_ID => pbkdf2_derive_key(password, salt, dklen, params.get("iterations").copied()),
        _ => Err(format!(
            "Attempted key derivation with unknown algorithm ID: {}",
            alg_id
        )
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_derive_key_kat() -> Result<(), Box<dyn std::error::Error>> {
        let password = Secret::new(String::from("password"));
        let salt = b"1234567890abcdef";
        let dklen = 32;
        let mem_cost = Some(65536); // 64 MiB
        let t_cost = Some(3);
        let par = Some(1);

        let expected_key_bytes: [u8; 32] = [
            0xec, 0xf1, 0xbe, 0x99, 0x6c, 0xb4, 0x73, 0xd2, 0xc7, 0xbd, 0x29, 0x96, 0x36, 0xda,
            0x0f, 0x93, 0x56, 0x3f, 0xfe, 0x3c, 0x9a, 0x2d, 0x7e, 0xc3, 0xf7, 0xfb, 0xf5, 0x58,
            0x9f, 0x63, 0x34, 0xc1,
        ];
        let derived_key = argon2_derive_key(password, salt, dklen, mem_cost, t_cost, par)?;

        assert_eq!(derived_key.expose_secret(), &expected_key_bytes);
        Ok(())
    }

    #[test]
    fn test_pbkdf2_derive_key_kat() -> Result<(), Box<dyn std::error::Error>> {
        let password = Secret::new("password123".to_string());
        let salt = b"1234567890abcdef"; // 16 bytes salt
        let dklen = 32;
        let iters = Some(100_000);

        let expected_key_bytes: [u8; 32] = [
            88, 7, 242, 176, 202, 200, 110, 191, 100, 135, 100, 111, 218, 5, 123, 246, 104, 77,
            132, 0, 185, 175, 159, 195, 14, 242, 161, 166, 66, 113, 164, 12,
        ];
        let derived_key = pbkdf2_derive_key(password, salt, dklen, iters)?;

        // Print the derived key bytes as hex for your reference (remove in final test)
        println!("Derived key: {:02x?}", derived_key.expose_secret());

        assert_eq!(derived_key.expose_secret(), &expected_key_bytes);
        Ok(())
    }
}
