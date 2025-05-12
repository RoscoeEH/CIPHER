// constants.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Contains constant values used throughout the application, such as
// algorithm identifiers, key lengths, and configuration defaults.

// AEAD
pub const AES_GCM_ID: u8 = 0;
pub const CHA_CHA_20_POLY_1305_ID: u8 = 1;

pub const AEAD_NAMES: [&str; 2] = ["aes-gcm", "chacha20poly1305"];

// Asymmetric
pub const RSA_ID: u8 = 8;
pub const ECC_ID: u8 = 9;
pub const KYBER_ID: u8 = 10;
pub const DILITHIUM_ID: u8 = 11;
pub const ASYM_NAMES: [&str; 4] = ["rsa", "ecc", "kyber", "dilithium"];

// KDF
pub const ARGON2_ID: u8 = 16;
pub const PBKDF2_ID: u8 = 17;

pub const KDF_NAMES: [&str; 2] = ["argon2", "pbkdf2"];

// Other
pub const SYM_KEY_LEN: usize = 32; // may implement other key sizes in the future

// by birthday paradox it should become a probem at around
// 4 billion uses so this is a low enough threshold
pub const SYM_KEY_USE_LIMIT: u32 = 1_000_000_000;
