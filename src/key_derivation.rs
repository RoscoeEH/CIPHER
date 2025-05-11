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
) -> Secret<Vec<u8>> {
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
        .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; dklen];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .expect("Argon2 hashing failed");

    let secret_key = Secret::new(key.clone());
    key.zeroize();
    secret_key
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
) -> Secret<Vec<u8>> {
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

    secret_key
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
) -> Secret<Vec<u8>> {
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
        _ => panic!(
            "Attempted key derivation with unknown algorithm ID: {}",
            alg_id
        ),
    }
}
