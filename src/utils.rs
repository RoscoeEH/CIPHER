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
use std::error::Error;

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
