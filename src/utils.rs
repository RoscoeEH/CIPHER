// utils.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// General-purpose utility functions used throughout the application, such as
// time handling, parsing helpers, etc...

use crate::constants::*;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::process::exit;

/// Converts a human-readable algorithm name into its corresponding algorithm ID.
///
/// Accepts names like `"aes-gcm"`, `"chacha20poly1305"`, `"rsa"`, `"ecc"`,
/// `"argon2"`, and `"pbkdf2"`, and returns the corresponding predefined constant ID.
///
/// # Arguments
/// * `name` - A string slice representing the algorithm name (case-insensitive).
///
/// # Returns
/// * `Ok(u8)` with the algorithm ID if recognized.
/// * `Err` if the algorithm name is unknown.
pub fn alg_name_to_id(name: &str) -> Result<u8, Box<dyn Error>> {
    match name.to_lowercase().as_str() {
        "aes-gcm" => Ok(AES_GCM_ID),
        "chacha20poly1305" => Ok(CHA_CHA_20_POLY_1305_ID),
        "rsa" => Ok(RSA_ID),
        "ecc" => Ok(ECC_ID),
        "argon2" => Ok(ARGON2_ID),
        "pbkdf2" => Ok(PBKDF2_ID),
        "kyber" => Ok(KYBER_ID),
        "dilithium" => Ok(DILITHIUM_ID),
        _ => Err(format!("Unknown algorithm name: {}", name).into()),
    }
}

/// Returns the string name of an algorithm given its numeric ID.
///
/// Maps known algorithm IDs to human-readable names like `"aes-gcm"`, `"rsa"`, etc.
/// If the ID is not recognized, returns `"unknown"`.
///
/// # Arguments
/// * `id` - A `u8` representing the algorithm identifier.
///
/// # Returns
/// * A `&'static str` with the name of the algorithm, or `"unknown"` if unrecognized.
pub fn alg_id_to_name(id: u8) -> &'static str {
    match id {
        AES_GCM_ID => "aes-gcm",
        CHA_CHA_20_POLY_1305_ID => "chacha20poly1305",
        RSA_ID => "rsa",
        ECC_ID => "ecc",
        ARGON2_ID => "argon2",
        PBKDF2_ID => "pbkdf2",
        KYBER_ID => "kyber",
        DILITHIUM_ID => "dilithium",
        _ => "unknown",
    }
}

/// Returns the current time as a UNIX timestamp (seconds since epoch).
pub fn now_as_u64() -> u64 {
    Utc::now().timestamp() as u64
}

/// Converts a DateTime<Utc> to a UNIX timestamp (u64).
pub fn datetime_to_u64(datetime: DateTime<Utc>) -> u64 {
    datetime.timestamp() as u64
}

/// Converts a UNIX timestamp (u64) to a DateTime<Utc>.
pub fn u64_to_datetime(ts: u64) -> DateTime<Utc> {
    // Safe as ts is from chrono timestamps, and this returns Result
    DateTime::<Utc>::from_timestamp(ts as i64, 0).expect("Invalid UNIX timestamp value")
}

/// Parses a string into a `u32`, exiting the program with an error message if parsing fails.
///
/// # Arguments
/// * `field` - The name of the field being parsed, used in the error message.
/// * `value` - The string value to parse into a `u32`.
///
/// # Returns
/// * The parsed `u32` value.
///
/// # Panics
/// This function does not panic, but it will terminate the program with a message
/// if parsing fails.
pub fn parse_u32_or_exit(field: &str, value: &str) -> u32 {
    value.parse::<u32>().unwrap_or_else(|_| {
        eprintln!("Invalid number for '{}'", field);
        exit(0);
    })
}

/// Computes the SHA-256 hash of the input data.
///
/// # Arguments
/// * `data` - A byte slice containing the data to hash.
///
/// # Returns
/// * A `Vec<u8>` containing the 32-byte SHA-256 digest.
pub fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
