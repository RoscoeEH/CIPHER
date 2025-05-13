// main.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Entry point of the application. Orchestrates high-level logic and integrates
// components including CLI processing, encryption routines, key management, and profile handling.

use rpassword::read_password;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::exit;

pub mod asymmetric_crypto;
pub mod constants;
use crate::constants::*;
mod cli;
pub mod key_derivation;
pub mod key_storage;
pub mod random;
pub mod symmetric_encryption;
pub mod user;
pub mod utils;

use clap::Parser;

/// Prompts the user for a password, optionally verifying it by re-entry.
///
/// This function displays a context-specific prompt based on whether the key
/// is symmetric, asymmetric, or unspecified. It securely reads the password
/// input from the user and, if verification is enabled, prompts for re-entry
/// to ensure they match. If the verification fails, the program exits with
/// an error message.
///
/// # Arguments
/// * `verify` - Whether to prompt the user to re-enter the password for verification.
/// * `is_sym_key` - Optional flag to indicate if the password is for a symmetric key
///   (`Some(true)`), asymmetric key (`Some(false)`), or unspecified (`None`).
///
/// # Returns
/// * `Secret<String>` - The password securely wrapped in a `Secret`.
///
/// # Panics
/// Panics if reading the password fails due to an I/O error.
///
/// # Exits
/// Exits the process with status 0 if password verification fails.
fn get_password(verify: bool, is_sym_key: Option<bool>) -> Secret<String> {
    match is_sym_key {
        Some(true) => println!("Enter password for symmetric key: "),
        Some(false) => println!("Enter password for asymmetric key: "),
        None => println!("Enter password: "),
    };

    let password = Secret::new(read_password().expect("rpassword failure".into()));

    if verify {
        println!("Re-enter password: ");
        let verify_password = Secret::new(read_password().expect("rpassword failure".into()));
        if verify_password.expose_secret() != password.expose_secret() {
            println!("The passwords did not match.");
            exit(0); // Changed from panic for nicer error messages
        }
    }

    password
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
fn parse_u32_or_exit(field: &str, value: &str) -> u32 {
    value.parse::<u32>().unwrap_or_else(|_| {
        eprintln!("Invalid number for '{}'", field);
        std::process::exit(1);
    })
}

/// Computes the SHA-256 hash of the input data.
///
/// # Arguments
/// * `data` - A byte slice containing the data to hash.
///
/// # Returns
/// * A `Vec<u8>` containing the 32-byte SHA-256 digest.
fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Contains metadata and material for a derived cryptographic key.
///
/// This structure holds the derived key along with the parameters
/// used in its derivation, such as the key derivation function (KDF) ID,
/// salt, and any algorithm-specific parameters.
///
/// # Fields
/// * `kdf_id` - Identifier of the key derivation function used (e.g., Argon2, PBKDF2).
/// * `key` - The securely stored derived key material.
/// * `salt` - The salt used during key derivation.
/// * `params` - A map of KDF-specific parameters (e.g., iterations, memory cost).
pub struct DerivedKeyInfo {
    pub kdf_id: u8,
    pub key: Secret<Vec<u8>>,
    pub salt: Vec<u8>,
    pub params: HashMap<String, u32>,
}
/// Derives a symmetric encryption key using CLI arguments and user profile settings.
///
/// This function selects a key derivation function (KDF) based on the CLI arguments
/// or defaults to the user profile's configured KDF. It prompts the user for a password
/// (with verification), generates a random salt, and derives the encryption key using
/// the specified KDF and profile parameters.
///
/// # Arguments
/// * `args` - Command-line arguments that may specify a custom KDF name.
/// * `profile` - The user's cryptographic profile containing default KDF ID and parameters.
///
/// # Returns
/// * `DerivedKeyInfo` - Struct containing the derived key, salt, KDF ID, and parameters.
///
/// # Panics
/// Panics if the specified or resolved KDF ID is unsupported, or if password input fails.
pub fn generate_key_from_args(
    args: &cli::EncryptArgs,
    profile: &user::UserProfile,
) -> DerivedKeyInfo {
    let kdf_id = match args.kdf {
        Some(ref s) => utils::alg_name_to_id(s.as_str()).unwrap(),
        None => profile.kdf_id,
    };

    let password = get_password(true, Some(true));
    let salt = random::get_salt(); // Vec<u8>

    let key = match kdf_id {
        ARGON2_ID => {
            key_derivation::id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &profile.params)
        }
        PBKDF2_ID => {
            key_derivation::id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &profile.params)
        }
        _ => {
            panic!("Unsupported KDF algorithm ID: {}", kdf_id);
        }
    };

    DerivedKeyInfo {
        kdf_id,
        key,
        salt,
        params: profile.params.clone(),
    }
}

/// Derives a symmetric encryption key from stored metadata and user-provided password.
///
/// This function uses stored key metadata (including KDF ID, salt, and parameters)
/// to derive a key from the user’s password. It verifies the derived key against a
/// stored hash to ensure correctness and increments the key usage counter if verified.
/// The updated key metadata is then persisted back to storage.
///
/// # Arguments
/// * `sym_key` - A mutable reference to the stored symmetric key metadata.
/// * `password` - The user-provided password, securely wrapped in a `Secret`.
///
/// # Returns
/// * `Result<DerivedKeyInfo, String>` - On success, returns a struct with the derived
///    key, KDF ID, salt, and parameters. Returns an error if verification fails or
///    storing the key metadata fails.
///
/// # Panics
/// Panics if an unsupported KDF ID is specified or password input fails.
pub fn derive_key_from_stored(
    sym_key: &mut key_storage::SymKey,
    password: Secret<String>,
) -> Result<DerivedKeyInfo, String> {
    let derived = key_derivation::id_derive_key(
        sym_key.derivation_method_id,
        password,
        &sym_key.salt,
        SYM_KEY_LEN,
        &sym_key.derivation_params,
    );

    let derived_hash = Sha256::digest(&derived.expose_secret());
    if derived_hash[..] != sym_key.verification_hash[..] {
        return Err("Key verification failed".into());
    }

    sym_key.use_count += 1;
    key_storage::store_key(sym_key).map_err(|e| format!("Store error: {e}"))?;

    Ok(DerivedKeyInfo {
        kdf_id: sym_key.derivation_method_id,
        key: derived,
        salt: sym_key.salt.clone(),
        params: sym_key.derivation_params.clone(),
    })
}

/// Generates an asymmetric keypair and securely stores it using a password-derived KEK.
///
/// This function retrieves the specified user profile (or initializes the default if not found),
/// determines the algorithm ID from the input name, and generates a new keypair using that algorithm.
/// The private key is then encrypted using a symmetric key derived from the user's password
/// and profile-based key derivation settings. The resulting encrypted keypair, along with metadata,
/// is persisted to the keystore.
///
/// # Arguments
/// * `asym_id` - The name of the asymmetric algorithm (e.g., `"rsa"` or `"ecc"`).
/// * `password` - The user-supplied password used to derive a Key Encryption Key (KEK).
/// * `profile_id` - The ID of the user profile specifying encryption and KDF settings.
/// * `name` - A name to associate with the stored keypair.
/// * `bits` - Key size or curve size in bits (depending on the algorithm).
///
/// # Returns
/// * `Result<(), Box<dyn Error>>` - Indicates success or failure during key generation or storage.
///
/// # Panics
/// Panics if the algorithm name is invalid, encryption fails, or storage fails unexpectedly.
///
/// # Errors
/// Returns an error if profile lookup, key derivation, or encryption fails.
fn gen_asym_key(
    asym_id: String,
    password: Secret<String>,
    profile_id: String,
    name: String,
    bits: usize,
) -> Result<(), Box<dyn Error>> {
    let profile = match user::get_profile(profile_id.as_str()).unwrap() {
        Some(p) => p,
        None => user::init_profile().unwrap(),
    };
    let alg_id = utils::alg_name_to_id(asym_id.as_str()).unwrap();

    let (priv_key, pub_key) = asymmetric_crypto::id_keypair_gen(alg_id, Some(bits)).unwrap();

    let kek_salt_bytes = random::get_salt();
    // Fix how profiles store params first
    let kek = key_derivation::id_derive_key(
        profile.kdf_id,
        password,
        &kek_salt_bytes,
        SYM_KEY_LEN,
        &profile.params,
    );

    let keypair_to_store = key_storage::AsymKeyPair {
        id: name,
        key_type: alg_id,
        public_key: pub_key,
        private_key: symmetric_encryption::id_encrypt(
            profile.aead_alg_id,
            &kek.expose_secret(),
            &random::get_nonce(),
            &priv_key.expose_secret(),
            None,
        )
        .unwrap(),
        kek_salt: kek_salt_bytes,
        kek_kdf: profile.kdf_id,
        kek_params: profile.params,
        kek_aead: profile.aead_alg_id,
        created: utils::now_as_u64(),
    };
    key_storage::store_key(&keypair_to_store).expect("Failed to store keypair");
    Ok(())
}

/// Generates a symmetric key from a password and stores it with metadata for future use.
///
/// This function retrieves the specified user profile (or initializes the default if not found),
/// then derives a symmetric key using the profile's key derivation function (KDF) parameters.
/// It generates a random salt and uses the provided password to derive the key.
/// The derived key is not stored directly; instead, a hash of the key is saved for later verification,
/// along with KDF parameters, salt, and metadata.
///
/// # Arguments
/// * `password` - The user-provided password, securely wrapped in a `Secret<String>`.
/// * `profile_id` - The ID of the user profile defining the KDF method and its parameters.
/// * `name` - A unique name to associate with the stored symmetric key.
///
/// # Returns
/// * `Result<(), Box<dyn Error>>` - Indicates success or error in key generation or storage.
///
/// # Panics
/// Panics if storing the key fails unexpectedly.
///
/// # Errors
/// Returns an error if the profile cannot be retrieved or initialized, or if key derivation fails.
fn gen_sym_key(
    password: Secret<String>,
    profile_id: String,
    name: String,
) -> Result<(), Box<dyn Error>> {
    let salt_vec = random::get_salt();
    let profile = match user::get_profile(profile_id.as_str()).unwrap() {
        Some(p) => p,
        None => user::init_profile().unwrap(),
    };
    let params: HashMap<String, u32> = profile.params;
    let key =
        key_derivation::id_derive_key(profile.kdf_id, password, &salt_vec, SYM_KEY_LEN, &params);
    let key_to_store = key_storage::SymKey {
        id: name,
        salt: salt_vec,
        derivation_method_id: profile.kdf_id,
        derivation_params: params.clone(),
        verification_hash: hash(&key.expose_secret()),
        created: utils::now_as_u64(),
        use_count: 0,
    };

    key_storage::store_key(&key_to_store).expect("Failed to store key");
    Ok(())
}

/// Reads the entire contents of a file into a byte vector.
///
/// Opens the file at the specified path and reads all bytes into memory.
/// Useful for loading binary or text data as raw bytes.
///
/// # Arguments
/// * `path` - A string slice representing the path to the file.
///
/// # Returns
/// * `Result<Vec<u8>, Box<dyn Error>>` - Returns a `Vec<u8>` with the file contents on success,
///   or an error boxed as `Box<dyn Error>` if the file cannot be opened or read.
fn read_file(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

/// Displays a warning message and prompts the user for confirmation before continuing.
///
/// This function prints the provided message followed by a `[y/N]` prompt. If the user
/// does not respond with `"y"` (case-insensitive), the program prints a cancellation
/// message and exits with status code 0. Used to prevent accidental continuation of
/// sensitive or destructive operations.
///
/// # Arguments
/// * `message` - The warning message to display before prompting the user.
///
/// # Exits
/// Exits the process with status 0 if the user does not confirm with `"y"`.
///
/// # Panics
/// Panics if writing to stdout or reading from stdin fails.
fn warn_user_or_exit(message: &str) {
    print!("{} [y/N]: ", message);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled");
        exit(0);
    }
}

/// Represents a public key entry that may be either owned or unowned by the user.
///
/// This enum abstracts over both unowned public keys (e.g., imported from external sources)
/// and fully owned asymmetric key pairs. It provides unified access to common key metadata
/// such as the key ID, type, and public key bytes.
enum PublicKeyEntry {
    Unowned(key_storage::UnownedPublicKey),
    Owned(key_storage::AsymKeyPair),
}
impl PublicKeyEntry {
    pub fn id(&self) -> String {
        match self {
            PublicKeyEntry::Unowned(k) => k.internal_id.clone(),
            PublicKeyEntry::Owned(k) => k.id.clone(),
        }
    }

    pub fn key_type(&self) -> u8 {
        match self {
            PublicKeyEntry::Unowned(k) => k.key_type,
            PublicKeyEntry::Owned(k) => k.key_type,
        }
    }
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            PublicKeyEntry::Unowned(k) => k.public_key.clone(),
            PublicKeyEntry::Owned(k) => k.public_key.clone(),
        }
    }
}

/// Attempts to retrieve a public key by ID, checking both unowned and owned key stores.
///
/// This function first looks for an unowned public key matching the provided ID. If not found,
/// it optionally prompts the user (unless `quiet` is true) before attempting to load an owned
/// asymmetric key pair with the same ID. Returns a wrapped `PublicKeyEntry` if a matching key
/// is found, or `Ok(None)` if no matching key is available or the type is incompatible.
///
/// # Arguments
/// * `key_id` - The identifier of the public key to retrieve.
/// * `quiet` - If `true`, suppresses user interaction and warnings when falling back to owned keys.
///
/// # Returns
/// * `Result<Option<PublicKeyEntry>, Box<dyn Error>>` -
///   - `Ok(Some(PublicKeyEntry))` if a matching key is found.
///   - `Ok(None)` if no key matches or a type mismatch occurs.
///   - `Err` if a non-recoverable error occurs during key retrieval.
///
/// # Panics
/// Panics if the unowned key check fails unexpectedly.
///
/// # Exits
/// Exits the process if the user declines to fall back to owned keys (when `quiet` is `false`).
fn get_unowned_or_owned_public_key(
    key_id: &str,
    quiet: bool,
) -> Result<Option<PublicKeyEntry>, Box<dyn Error>> {
    let public_key = key_storage::get_unowned_public_key(&key_id)
        .expect("Failed to check for unowned public key.");

    let key_entry = match public_key {
        Some(k) => PublicKeyEntry::Unowned(k),
        None => {
            if !quiet {
                warn_user_or_exit(&format!(
                "Could not find unowned public key with ID: {}. Would you like to try an owned key?",
                key_id
            ))
            };

            // Try getting owned key of the expected type (AsymKeyPair)
            match key_storage::get_key::<key_storage::AsymKeyPair>(&key_id) {
                Ok(Some(keypair)) => PublicKeyEntry::Owned(keypair),
                Ok(None) => return Ok(None), // Key not found
                Err(e) => {
                    // If it's a type mismatch error (e.g., found SymKey instead of AsymKeyPair), return None
                    if e.to_string().contains("expected type `AsymKeyPair`") {
                        return Ok(None);
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    };

    Ok(Some(key_entry))
}

/// Builds a signed blob consisting of a header, file information, and the data, signed by a private key.
///
/// This function constructs a "blob" that contains metadata (such as key ID, algorithm ID, and filename)
/// and data (such as the content to be signed), then signs the resulting structure with the provided private key.
/// The output is a vector that contains the concatenated header, data, and signature.
///
/// # Arguments
/// * `magic` - A 4-byte static magic value to prefix the blob.
/// * `alg_id` - The identifier of the signing algorithm to use.
/// * `key_id` - The identifier of the key used for signing.
/// * `filename` - The name of the file being signed.
/// * `data` - The data to be signed, which could be a file or message content.
/// * `decrypted_priv` - The decrypted private key (wrapped securely in a `Secret`) used for signing.
///
/// # Returns
/// * `Result<Vec<u8>, Box<dyn Error>>` - A result containing the signed blob as a `Vec<u8>`. The blob includes:
///    - A header with metadata about the key and data.
///    - The data itself.
///    - A signature of the concatenated header and data.
///
/// # Panics
/// Panics if the signing process fails (e.g., if the private key cannot be used to sign the data).
///
/// # Errors
/// Returns an error if the signing operation encounters an issue, such as key mismatch or cryptographic failure.
fn build_signed_blob(
    magic: &'static [u8; 4],
    alg_id: u8,
    key_id: &str,
    filename: &str,
    data: &[u8],
    decrypted_priv: &secrecy::Secret<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let key_id_bytes = key_id.as_bytes();
    let filename_bytes = filename.as_bytes();

    // Build header
    let mut header = Vec::new();
    header.extend_from_slice(magic);
    header.push(alg_id);
    header.push(key_id_bytes.len() as u8);
    header.extend_from_slice(key_id_bytes);
    header.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(filename_bytes);
    header.extend_from_slice(&(data.len() as u64).to_be_bytes()); // DATA_LEN

    // Sign header+data
    let mut signed_blob = header.clone();
    signed_blob.extend_from_slice(data);
    let data_hash = hash(&signed_blob);
    let signature = asymmetric_crypto::id_sign(alg_id, decrypted_priv.expose_secret(), &data_hash)
        .expect("Signing failed");

    // Output full blob
    signed_blob.extend_from_slice(&signature);
    Ok(signed_blob)
}

/// Constructs an encrypted blob containing a file's metadata and encrypted content using asymmetric encryption.
///
/// This function creates an encrypted blob consisting of a header with metadata (algorithm IDs, key ID, filename length),
/// followed by the actual ciphertext, which is the result of encrypting the provided plaintext using asymmetric encryption.
/// The symmetric algorithm ID is included for future decryption, and the blob is signed by the public key associated with the given key entry.
///
/// # Arguments
/// * `alg_id` - The identifier of the asymmetric encryption algorithm to use.
/// * `sym_alg_id` - The identifier of the symmetric encryption algorithm (used optionally in encryption).
/// * `key` - A `PublicKeyEntry` containing the public key and related metadata for encryption.
/// * `filename` - The name of the file or resource being encrypted.
/// * `plaintext` - The data (in bytes) to be encrypted.
///
/// # Returns
/// * `Result<Vec<u8>, Box<dyn std::error::Error>>` - A result containing the encrypted blob as a `Vec<u8>`. The blob includes:
///    - A header consisting of magic bytes, algorithm IDs, key ID length, key ID, and filename length.
///    - The encrypted content (ciphertext).
///
/// # Errors
/// Returns an error if the encryption process fails, such as an invalid public key or encryption algorithm error.
fn build_asym_encrypted_blob(
    alg_id: u8,
    sym_alg_id: u8,
    key: &PublicKeyEntry,
    filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pub_key = key.public_key();

    let data_to_encrypt = plaintext.to_vec();

    // encrypt the data
    let ciphertext =
        asymmetric_crypto::id_asym_enc(alg_id, &pub_key, &data_to_encrypt, Some(sym_alg_id))?;

    // collects info for header
    let key_id = key.id();
    let key_id_bytes = key_id.as_bytes();
    let key_id_len = key_id_bytes.len() as u16;
    let filename_len = filename.as_bytes().len() as u16;

    let mut blob = Vec::new();

    // Header: MAGIC | ALG_ID | SYM_ALG_ID | KEY_ID_LEN | KEY_ID | FILENAME_LEN
    blob.extend_from_slice(b"ENC2");
    blob.push(alg_id);
    blob.push(sym_alg_id);
    blob.extend_from_slice(&key_id_len.to_be_bytes());
    blob.extend_from_slice(key_id_bytes);
    blob.extend_from_slice(&filename_len.to_be_bytes());

    // add ciphertext to header
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

/// Decrypts a private key using a key encryption key (KEK) derived from a password.
///
/// This function prompts the user for a password, derives a key encryption key (KEK) based on the provided password
/// and stored parameters, and uses that KEK to decrypt the stored private key associated with the given asymmetric key pair.
///
/// # Arguments
/// * `keypair` - The asymmetric key pair containing the key encryption key (KEK) parameters, salt, and the encrypted private key.
///
/// # Returns
/// * `Result<Secret<Vec<u8>>, Box<dyn Error>>` - A result containing the decrypted private key as a `Secret<Vec<u8>>` wrapped in a `Result`.
///   - If successful, it contains the decrypted private key.
///
/// # Errors
/// Returns an error if the password derivation, decryption, or any other operation fails.
/// Specifically, it could fail if the key derivation or symmetric decryption process fails.
fn decrypt_private_key(
    keypair: &key_storage::AsymKeyPair,
) -> Result<Secret<Vec<u8>>, Box<dyn Error>> {
    // Prompt for password
    let kek_password = get_password(false, Some(false));

    // Derive KEK using stored parameters
    let kek = key_derivation::id_derive_key(
        keypair.kek_kdf,
        kek_password,
        &keypair.kek_salt,
        SYM_KEY_LEN,
        &keypair.kek_params,
    );

    // Decrypt the stored private key
    let decrypted = symmetric_encryption::id_decrypt(
        keypair.kek_aead,
        &kek.expose_secret(),
        &keypair.private_key,
        None,
    )
    .unwrap();

    Ok(Secret::new(decrypted))
}

/// Verifies the signature of a signed blob.
///
/// This function checks the validity of a signature associated with a blob of data.
/// It starts by reading and parsing the header to ensure the integrity of the data, followed by checking the signature using the appropriate public key.
///
/// # Arguments
/// * `raw` - A byte slice representing the raw signed data. This includes both the header and the signature.
///
/// # Returns
/// * `Result<bool, Box<dyn std::error::Error>>` - A result containing a boolean:
///   - `true` if the signature is successfully verified,
///   - `false` if no matching public key is found or signature verification fails.
///
/// # Errors
/// Returns an error if the blob's magic is invalid, the header is not properly formatted, or there is an issue during signature verification.
/// Possible errors include:
///   - Invalid magic value in the header,
///   - Inconsistent blob length compared to the header's data length,
///   - Failure to find or verify the public key for the signature.
fn verify_signature(raw: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(raw);

    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;

    if &magic != b"SIG1" && &magic != b"SIG2" {
        return Err(format!(
            "Bad magic: {:?}",
            std::str::from_utf8(&magic).unwrap_or("<non-UTF8>")
        )
        .into());
    }

    // Parse header
    let mut buf1 = [0u8; 1];
    cursor.read_exact(&mut buf1)?;
    let alg_id = buf1[0];

    cursor.read_exact(&mut buf1)?;
    let key_id_len = buf1[0] as usize;
    let mut key_id_bytes = vec![0u8; key_id_len];
    cursor.read_exact(&mut key_id_bytes)?;
    let key_id = String::from_utf8_lossy(&key_id_bytes).to_string();

    let mut buf2 = [0u8; 2];
    cursor.read_exact(&mut buf2)?;
    let filename_len = u16::from_be_bytes(buf2) as usize;
    let mut filename_bytes = vec![0u8; filename_len];
    cursor.read_exact(&mut filename_bytes)?;

    let mut buf8 = [0u8; 8];
    cursor.read_exact(&mut buf8)?;
    let data_len = u64::from_be_bytes(buf8) as usize;

    let header_len = 4 + 1 + 1 + key_id_len + 2 + filename_len + 8;
    let data_end = header_len + data_len;

    if raw.len() < data_end {
        return Err("Blob too short".into());
    }

    // Fully parsed blocks here
    let signed_blob = &raw[..data_end];
    let signature = &raw[data_end..];
    let data_hash = hash(signed_blob);

    let pub_key_option = get_unowned_or_owned_public_key(&key_id, false);
    match pub_key_option {
        Ok(pub_key) => {
            asymmetric_crypto::id_verify(
                alg_id,
                &pub_key.unwrap().public_key(),
                &data_hash,
                signature,
            )?;
            Ok(true)
        }
        Err(_e) => Ok(false),
    }
}

/// Strips the signature blob into its components: filename and data.
///
/// This function extracts the `filename` and the signed `data` from a signed data blob.
/// It starts by parsing the header to retrieve the necessary information such as algorithm ID, key ID, filename length, and data length,
/// then it returns the filename and the actual signed data.
///
/// # Arguments
/// * `raw` - A byte slice representing the raw signed data blob, which contains a header followed by the signature data.
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>>` - A tuple containing:
///   - `Vec<u8>` representing the filename bytes (in the form of UTF-8),
///   - `Vec<u8>` representing the actual signed data.
///
/// # Errors
/// Returns an error if the blob has an invalid magic, malformed header, or the data length doesn't match the expected size of the blob.
/// Possible errors include:
///   - Invalid magic value in the header (should be either `SIG1` or `SIG2`),
///   - Inconsistent blob length compared to the header's data length.
fn strip_signature_blob(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(raw);

    // Magic should be some SIGi
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;

    if &magic != b"SIG1" && &magic != b"SIG2" {
        return Err(format!(
            "Bad magic: {:?}",
            std::str::from_utf8(&magic).unwrap_or("<non-UTF8>")
        )
        .into());
    }

    // parse header
    let mut buf1 = [0u8; 1];
    cursor.read_exact(&mut buf1)?; // alg_id

    cursor.read_exact(&mut buf1)?;
    let key_id_len = buf1[0] as usize;
    cursor.set_position(cursor.position() + key_id_len as u64);

    let mut buf2 = [0u8; 2];
    cursor.read_exact(&mut buf2)?;
    let filename_len = u16::from_be_bytes(buf2) as usize;
    let mut filename_bytes = vec![0u8; filename_len];
    cursor.read_exact(&mut filename_bytes)?;

    let mut buf8 = [0u8; 8];
    cursor.read_exact(&mut buf8)?;
    let data_len = u64::from_be_bytes(buf8) as usize;

    let header_len = cursor.position() as usize;
    let data_end = header_len + data_len;

    // Error if the blob is to small
    if raw.len() < data_end {
        return Err("Blob too short".into());
    }

    let data = raw[header_len..data_end].to_vec();

    Ok((filename_bytes, data))
}

/// Decrypts an asymmetric encrypted blob, extracting the filename and the plaintext data.
///
/// This function first validates the provided encrypted blob by checking the header and extracting necessary metadata.
/// It then uses the appropriate private key to decrypt the encrypted content and extracts both the filename and the plaintext data.
///
/// # Arguments
/// * `blob` - A byte slice representing the encrypted data blob, which includes the header, encryption metadata,
///   and the ciphertext that needs to be decrypted.
///
/// # Returns
/// * `Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>>` - A tuple containing:
///   - `Vec<u8>` representing the filename bytes (in UTF-8),
///   - `Vec<u8>` representing the decrypted plaintext data.
///
/// # Errors
/// Returns an error in the following cases:
///   - Invalid magic value in the header (should be `ENC2`),
///   - Error reading the algorithm IDs or key ID,
///   - Failure to retrieve the private key from the key storage,
///   - Decryption failure, including if the filename length exceeds the decrypted content size.
fn decrypt_asym_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(blob);

    // Check header
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if &magic != b"ENC2" {
        return Err("Bad magic: expected ENC2".into());
    }

    // Read algorithm IDs
    let mut buf1 = [0u8; 1];
    cursor.read_exact(&mut buf1)?;
    let alg_id = buf1[0];
    cursor.read_exact(&mut buf1)?;
    let sym_alg_id = buf1[0];

    // Read key ID
    let mut buf2 = [0u8; 2];
    cursor.read_exact(&mut buf2)?;
    let key_id_len = u16::from_be_bytes(buf2) as usize;
    let mut key_id_buf = vec![0u8; key_id_len];
    cursor.read_exact(&mut key_id_buf)?;
    let key_id = String::from_utf8_lossy(&key_id_buf).to_string();

    // Read filename length
    cursor.read_exact(&mut buf2)?;
    let filename_len = u16::from_be_bytes(buf2) as usize;

    // Read ciphertext
    let mut ciphertext = Vec::new();
    cursor.read_to_end(&mut ciphertext)?;

    // Retrieve private key from keystore and decrypt
    let keypair = key_storage::get_key(&key_id)
        .unwrap()
        .ok_or("Key entry is None")?;

    let decrypted_priv_key = decrypt_private_key(&keypair)?;

    let plaintext_with_filename = asymmetric_crypto::id_asym_dec(
        alg_id,
        &decrypted_priv_key.expose_secret(),
        &ciphertext,
        Some(sym_alg_id),
    )?;

    let total_len = plaintext_with_filename.len();
    if filename_len > total_len {
        return Err("Corrupted data: filename length exceeds decrypted content size".into());
    }

    let filename_start = total_len - filename_len;
    let filename_bytes = plaintext_with_filename[filename_start..].to_vec();
    let plaintext = plaintext_with_filename[..filename_start].to_vec();

    Ok((filename_bytes, plaintext))
}

/// Decrypts a symmetric encrypted blob, extracting the file data and the filename.
///
/// This function starts by validating the header of the provided encrypted blob and reading metadata, including key derivation
/// parameters, the encryption salt, and the filename length. It then derives a symmetric key using the provided KDF parameters,
/// decrypts the ciphertext, and extracts the file data and filename.
///
/// # Arguments
/// * `blob` - A byte slice representing the encrypted data blob, which includes the header, key derivation parameters,
///   salt, ciphertext, and filename.
///
/// # Returns
/// * `Result<(Vec<u8>, String), Box<dyn std::error::Error>>` - A tuple containing:
///   - `Vec<u8>` representing the decrypted file data,
///   - `String` representing the filename (UTF-8 encoded).
///
/// # Errors
/// Returns an error in the following cases:
///   - Invalid magic value in the header (should be `ENC1`),
///   - Failure in reading or processing KDF parameters or salt,
///   - Decryption failure,
///   - Corrupted data, where the filename length exceeds the size of the decrypted content.
fn decrypt_sym_blob(blob: &[u8]) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(blob);

    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if &magic != b"ENC1" {
        return Err("Invalid magic bytes".into());
    }

    let mut kdf_id_buf = [0u8; 1];
    cursor.read_exact(&mut kdf_id_buf)?;
    let kdf_id = kdf_id_buf[0];

    let mut aead_id_buf = [0u8; 1];
    cursor.read_exact(&mut aead_id_buf)?;
    let aead_id = aead_id_buf[0];

    let mut salt_len_buf = [0u8; 4];
    cursor.read_exact(&mut salt_len_buf)?;
    let salt_len = u32::from_be_bytes(salt_len_buf) as usize;

    let mut salt = vec![0u8; salt_len];
    cursor.read_exact(&mut salt)?;

    // KDF parameters
    let mut param_bytes = Vec::new();
    let mut params = HashMap::new();

    match kdf_id {
        ARGON2_ID => {
            let mut buf = [0u8; 4];
            cursor.read_exact(&mut buf)?;
            param_bytes.extend_from_slice(&buf);
            params.insert("memory_cost".to_string(), u32::from_be_bytes(buf));

            cursor.read_exact(&mut buf)?;
            param_bytes.extend_from_slice(&buf);
            params.insert("time_cost".to_string(), u32::from_be_bytes(buf));

            cursor.read_exact(&mut buf)?;
            param_bytes.extend_from_slice(&buf);
            params.insert("parallelism".to_string(), u32::from_be_bytes(buf));
        }
        PBKDF2_ID => {
            let mut buf = [0u8; 4];
            cursor.read_exact(&mut buf)?;
            param_bytes.extend_from_slice(&buf);
            params.insert("iterations".to_string(), u32::from_be_bytes(buf));
        }
        _ => return Err(format!("Unknown KDF ID: {}", kdf_id).into()),
    }

    let mut filename_len_buf = [0u8; 2];
    cursor.read_exact(&mut filename_len_buf)?;
    let filename_len = u16::from_be_bytes(filename_len_buf) as usize;

    // Reconstruct AAD
    let mut aad = Vec::new();
    aad.extend_from_slice(b"ENC1");
    aad.push(kdf_id);
    aad.push(aead_id);
    aad.extend_from_slice(&salt_len_buf);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&param_bytes);
    aad.extend_from_slice(&filename_len_buf);

    // Remaining is ciphertext
    let mut ciphertext = Vec::new();
    cursor.read_to_end(&mut ciphertext)?;

    // Derive key
    let password = get_password(false, Some(true));
    let key = key_derivation::id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &params);

    let plaintext_with_filename =
        symmetric_encryption::id_decrypt(aead_id, &key.expose_secret(), &ciphertext, Some(&aad))
            .unwrap();

    let total_len = plaintext_with_filename.len();
    if filename_len > total_len {
        return Err("Corrupted data: filename length exceeds decrypted content size".into());
    }

    let filename_start = total_len - filename_len;
    let file_data = plaintext_with_filename[..filename_start].to_vec();
    let filename = String::from_utf8_lossy(&plaintext_with_filename[filename_start..]).into();

    Ok((file_data, filename))
}

/// Encrypts a symmetric blob with additional metadata in the header.
///
/// This function generates a structured blob starting with a header that contains information
/// about the key derivation, encryption parameters, and a filename length. It then encrypts
/// the provided plaintext using symmetric encryption with authenticated encryption with
/// associated data (AEAD). The header and ciphertext are concatenated into the final encrypted blob.
///
/// # Arguments
/// * `key_info` - A reference to a `DerivedKeyInfo` structure containing key derivation information
///   (e.g., KDF ID, salt, and associated parameters).
/// * `aead_id` - An identifier for the AEAD algorithm to use for encryption.
/// * `plaintext` - The data to be encrypted.
/// * `filename_len` - The length of the filename that will be included in the header.
///
/// # Returns
/// * `Result<Vec<u8>, Box<dyn Error>>` - The encrypted blob consisting of the header and ciphertext.
///   - The header includes metadata like KDF ID, AEAD ID, salt, and filename length.
///   - The ciphertext is the result of encrypting the `plaintext` using the derived key.
///
/// # Errors
/// Returns an error if:
///   - The KDF ID is unknown (i.e., neither `ARGON2_ID` nor `PBKDF2_ID`).
///   - There is a failure in encryption.
fn encrypt_sym_blob(
    key_info: &DerivedKeyInfo,
    aead_id: u8,
    plaintext: &[u8],
    filename_len: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let nonce = random::get_nonce();

    // === Construct header in memory
    let mut header = Vec::new();
    header.extend_from_slice(b"ENC1");
    header.extend_from_slice(&[key_info.kdf_id, aead_id]);
    header.extend_from_slice(&(key_info.salt.len() as u32).to_be_bytes());
    header.extend_from_slice(&key_info.salt);

    match key_info.kdf_id {
        ARGON2_ID => {
            header.extend_from_slice(&key_info.params["memory_cost"].to_be_bytes());
            header.extend_from_slice(&key_info.params["time_cost"].to_be_bytes());
            header.extend_from_slice(&key_info.params["parallelism"].to_be_bytes());
        }
        PBKDF2_ID => {
            header.extend_from_slice(&key_info.params["iterations"].to_be_bytes());
        }
        _ => return Err("Unknown KDF ID".into()),
    }

    header.extend_from_slice(&filename_len.to_be_bytes());

    // === Encrypt with header as AAD
    let ciphertext = symmetric_encryption::id_encrypt(
        aead_id,
        key_info.key.expose_secret(),
        &nonce,
        plaintext,
        Some(&header),
    )
    .unwrap();

    // === Return blob: header || ciphertext
    let mut blob = header;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn main() {
    let cli = cli::Cli::parse();

    match cli.command {
        // Handles all symmetric and asymmetric encryption; also can sign encrypted blobs
        cli::Command::Encrypt(args) => {
            cli::validate_args(&args);

            // Checks id the user provided a profile
            let profile = match args.profile.as_str() {
                "Default" => user::init_profile().unwrap(),
                other => user::get_profile(other).unwrap().unwrap(),
            };

            let input_path = PathBuf::from(args.input.clone().unwrap());
            let filename = input_path.file_name().unwrap().to_str().unwrap();
            let filename_bytes = filename.as_bytes();
            let filename_len = filename_bytes.len() as u16;

            // Read plaintext ===
            let mut plaintext = read_file(input_path.to_str().unwrap()).unwrap();
            plaintext.extend_from_slice(filename_bytes); // Append filename for recovery

            // Determine output path
            let out_path = match args.output {
                Some(ref path) => {
                    let mut p = PathBuf::from(path);
                    p.set_extension("enc");
                    p
                }
                None => {
                    let mut p = PathBuf::from(args.input.clone().unwrap());
                    p.set_extension("enc");
                    p
                }
            };

            // Determines if the given key is sym or asym; no key routes to sym
            let asym = match &args.input_key {
                Some(k_id) => get_unowned_or_owned_public_key(&k_id, true).is_ok(),
                None => false,
            };

            match asym {
                true => {
                    // Asymmetric encryption
                    let input_key_id = args
                        .input_key
                        .clone()
                        .expect("Missing input key ID for asymmetric encryption");

                    let key = get_unowned_or_owned_public_key(&input_key_id, false)
                        .unwrap()
                        .unwrap();

                    let sym_alg_id = match args.aead {
                        Some(ref a) => utils::alg_name_to_id(a).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let alg_id = key.key_type();

                    let mut blob =
                        build_asym_encrypted_blob(alg_id, sym_alg_id, &key, filename, &plaintext)
                            .expect("Failed to encrypt");

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair =
                            match key_storage::get_key(args.sign_key.unwrap().as_str()).unwrap() {
                                Some(k) => k,
                                None => panic!("Signing key not found."),
                            };
                        let sign_private_key = decrypt_private_key(&sign_key).unwrap();
                        blob = build_signed_blob(
                            b"SIG2",
                            sign_key.key_type,
                            &sign_key.id,
                            "verified.enc",
                            &blob,
                            &sign_private_key,
                        )
                        .unwrap();
                    }
                    let mut f = File::create(&out_path).expect("Failed to create output file");
                    f.write_all(&blob).expect("Failed to write ciphertext");

                    println!(
                        "Asymmetric encrypted file written to {}",
                        out_path.display()
                    );
                }

                false => {
                    // Symmetric encryption

                    // Either get a key from the store or generate a single use one
                    let key_info = match args.input_key {
                        Some(ref input_key_id) => {
                            let mut sym_key: key_storage::SymKey =
                                key_storage::get_key(input_key_id)
                                    .unwrap()
                                    .ok_or("Key ID not found")
                                    .unwrap();

                            let password = get_password(false, Some(true));
                            derive_key_from_stored(&mut sym_key, password)
                                .expect("Failed to derive key from stored key")
                        }
                        None => generate_key_from_args(&args, &profile),
                    };

                    let aead_id = match args.aead {
                        Some(ref s) => utils::alg_name_to_id(s).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let mut blob = encrypt_sym_blob(&key_info, aead_id, &plaintext, filename_len)
                        .expect("Failed to construct encrypted blob");

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair =
                            match key_storage::get_key(args.sign_key.unwrap().as_str()).unwrap() {
                                Some(k) => k,
                                None => panic!("Signing key not found."),
                            };
                        let sign_private_key = decrypt_private_key(&sign_key).unwrap();
                        blob = build_signed_blob(
                            b"SIG2",
                            sign_key.key_type,
                            &sign_key.id,
                            "verified.enc",
                            &blob,
                            &sign_private_key,
                        )
                        .unwrap();
                    }
                    let mut f = File::create(&out_path).expect("Failed to create output file");
                    f.write_all(&blob).expect("Failed to write ciphertext");

                    println!("Symmetric encrypted file written to {}", out_path.display());
                }
            };
        }

        cli::Command::Decrypt(args) => {
            cli::validate_args(&args);
            let in_path = PathBuf::from(args.input.clone().unwrap());
            let mut f = File::open(&in_path).expect("Failed to open encrypted file");

            // Read blob and magic
            let mut blob = Vec::new();
            f.read_to_end(&mut blob).expect("Failed to read input file");

            let mut magic: [u8; 4] = blob[..4].try_into().expect("Failed to get magic bytes");

            // Check if data is signed and encrypted
            // if it is => verify/strip the signature
            if &magic == b"SIG2" {
                let valid_sig = verify_signature(&blob).expect("signature verfication failed.");
                if valid_sig {
                    println!("Signature verified!")
                } else {
                    warn_user_or_exit("Unrecognized signature. Would you like to decrypt anyway?");
                }
                let (_, encrypted_unsigned_data) = strip_signature_blob(&blob).unwrap();
                blob = encrypted_unsigned_data;
                magic = blob[..4]
                    .try_into()
                    .expect("Blob too short to contain magic");
            }

            match &magic {
                b"ENC2" => {
                    // Asymmetric decryption
                    let (filename_bytes, plaintext) = decrypt_asym_blob(&blob).unwrap();
                    let original_filename = String::from_utf8_lossy(&filename_bytes);

                    // Get out path and write to file
                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(original_filename.to_string()),
                    };

                    let mut out_file =
                        File::create(&out_path).expect("Failed to create output file");
                    out_file
                        .write_all(&plaintext)
                        .expect("Failed to write decrypted data");

                    println!(
                        "Decryption complete. Output written to {}",
                        out_path.display()
                    );
                }
                b"ENC1" => {
                    // Symmetric decryption
                    let (file_data, filename) = decrypt_sym_blob(&blob).expect("Decryption failed");
                    // Get out path and write file
                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(filename),
                    };

                    let mut out_file =
                        File::create(&out_path).expect("Failed to create output file");
                    out_file
                        .write_all(&file_data)
                        .expect("Failed to write decrypted data");

                    println!(
                        "Decryption complete. Output written to {}",
                        out_path.display()
                    );
                }
                // The magic is unrecognized
                _ => panic!("Unknown encryption format"),
            };
        }
        // Handles changed to default parameters
        cli::Command::Profile(args) => {
            cli::validate_args(&args);
            let id = args
                .profile
                .clone()
                .unwrap_or_else(|| "Default".to_string());

            // Either make a new profile or get the existing one to edit
            let mut profile = match user::get_profile(&id).unwrap() {
                Some(p) => p,
                None => user::get_new_profile(id.clone()),
            };

            // find the thing to update
            match args.update_field.as_str() {
                "aead" => match utils::alg_name_to_id(&args.value) {
                    Ok(id) => profile.aead_alg_id = id,
                    Err(e) => {
                        eprintln!("Invalid aead_alg_id: {}", e);
                        std::process::exit(1);
                    }
                },

                "kdf" => match utils::alg_name_to_id(&args.value) {
                    Ok(id) => profile.kdf_id = id,
                    Err(e) => {
                        eprintln!("Invalid kdf_id: {}", e);
                        std::process::exit(1);
                    }
                },
                "memory_cost" | "time_cost" | "parallelism" | "iterations" => {
                    let number = parse_u32_or_exit(&args.update_field, &args.value);
                    profile.params.insert(args.update_field.clone(), number);
                }
                field => {
                    eprintln!("Unknown field '{}'. No changes made.", field);
                    std::process::exit(1);
                }
            }

            // Set the new profile
            user::set_profile(&profile).expect("Failed to save updated profile");
            println!("Updated profile '{}': {:#?}", profile.id, profile);
        }

        cli::Command::ListProfiles => {
            user::init_profile().expect("Failed to set a default profile");
            user::list_profiles().expect("Failed to list profiles");
        }

        cli::Command::KeyGen(args) => {
            cli::validate_args(&args);

            // Avoid overwriting keys
            if key_storage::does_key_exist(args.id.clone()).unwrap() {
                warn_user_or_exit(&format!(
                    "There is already a key with the id: {}. Overwrite?",
                    args.id
                ));
            }

            // Proceed with key generation
            let password = get_password(true, None);

            match &args.asymmetric {
                Some(alg) => {
                    gen_asym_key(
                        alg.clone(),
                        password,
                        args.profile.clone(),
                        args.id.clone(),
                        args.bits,
                    )
                    .expect("Failed to generate new key.");
                }
                None => {
                    gen_sym_key(password, args.profile.clone(), args.id.clone())
                        .expect("Failed to generate new key.");
                }
            }
        }
        cli::Command::ListKeys(args) => {
            if !args.unowned {
                key_storage::list_keys().expect("Failed to list keys");
            } else {
                // Can list keys from others
                key_storage::list_unowned_public_keys().expect("Failed to list keys")
            }
        }
        // Erases option to erase all keys and data
        cli::Command::Wipe(mut args) => {
            // if none were specified wipe all
            if !args.wipe_keys && !args.wipe_profiles && !args.wipe_unowned_keys {
                args.wipe_keys = true;
                args.wipe_profiles = true;
                args.wipe_unowned_keys = true;
            }
            warn_user_or_exit(
                "Are you sure you want to wipe all data? This action cannot be undone.",
            );

            if args.wipe_profiles {
                user::wipe_profiles().expect("Failed to wipe profile data.");
            }
            if args.wipe_keys {
                key_storage::wipe_keystore().expect("Failed to wipe keys.");
            }
            if args.wipe_unowned_keys {
                key_storage::wipe_public_keystore().expect("Failed to wipe unowned keys")
            }
        }

        cli::Command::DeleteKey(args) => {
            if args.unowned {
                if key_storage::does_public_key_exist(args.id.clone()).unwrap() {
                    key_storage::delete_public_key(args.id.as_str())
                        .expect("Failed to delete key.");
                    println!("Key has been deleted.")
                } else {
                    println!("Key does not exist.")
                }
            } else {
                if key_storage::does_key_exist(args.id.clone()).unwrap() {
                    key_storage::delete_key(args.id.as_str()).expect("Failed to delete key.");
                    println!("Key has been deleted.")
                } else {
                    println!("Key does not exist.")
                }
            }
        }

        // signs any data and creates a .sig file
        cli::Command::Sign(args) => {
            cli::validate_args(&args);

            let input_path = PathBuf::from(&args.input);
            let filename = input_path.file_name().unwrap().to_str().unwrap();
            let data = read_file(input_path.to_str().unwrap()).unwrap();

            // load/decrypt private key
            let keypair: key_storage::AsymKeyPair = key_storage::get_key(&args.key_id)
                .unwrap()
                .ok_or("Key ID not found in keystore")
                .unwrap();
            // Compute the kek
            let kek_password = get_password(false, Some(false));
            let kek = key_derivation::id_derive_key(
                keypair.kek_kdf,
                kek_password,
                &keypair.kek_salt,
                SYM_KEY_LEN,
                &keypair.kek_params,
            );
            let decrypted_private_key = Secret::new(
                symmetric_encryption::id_decrypt(
                    keypair.kek_aead,
                    &kek.expose_secret(),
                    &keypair.private_key,
                    None,
                )
                .unwrap(),
            );

            // sign the blob
            let blob = build_signed_blob(
                b"SIG1",
                keypair.key_type,
                args.key_id.as_str(),
                filename,
                &data,
                &decrypted_private_key,
            )
            .expect("Signing failed.");

            // Write out blob
            let sig_path = input_path.with_extension("sig");
            let mut f = File::create(&sig_path).expect("Failed to create output file");
            f.write_all(&blob).unwrap();

            println!("Signed file written to '{}'", sig_path.display());
        }
        // Verify .sig files and optionally strip the sig data
        cli::Command::Verify(args) => {
            cli::validate_args(&args);
            let sig_path = PathBuf::from(&args.input);
            let raw = read_file(sig_path.to_str().unwrap()).unwrap();

            if !verify_signature(&raw).unwrap() {
                println!("Signature verification failed");
                exit(0);
            }

            println!("Signature verified.");

            // Stip blob and create new file
            if !args.only_verify {
                let (filename_bytes, data) = strip_signature_blob(&raw).unwrap();
                let original_filename = String::from_utf8_lossy(&filename_bytes);
                let out = sig_path.with_file_name(original_filename.to_string());
                let mut f = File::create(&out).unwrap();
                f.write_all(&data).unwrap();
                println!("Unsigned data written to '{}'", out.display());
            }
        }
        // Creates a .pub of one of your keypairs that others can import
        cli::Command::ExportKey(args) => {
            let key = key_storage::export_key(args.key_id.as_str()).unwrap();
            let mut key_file = Vec::new();
            key_file.extend_from_slice(b"KEY1");
            key_file.extend_from_slice(&key);

            let file_name = match args.name {
                Some(s) => s,
                None => String::from("Public_key"),
            };
            let output_path = PathBuf::from(&file_name).with_extension("pub");
            let mut f = File::create(&output_path).expect("Failed to create output file");
            f.write_all(&key_file).unwrap();
            println!("Public key written to '{}'", output_path.display());
        }

        // Reads in .pub files into your key store
        cli::Command::ImportKey(args) => {
            cli::validate_args(&args);
            let key_path = PathBuf::from(&args.input_file);
            let raw = read_file(key_path.to_str().unwrap()).unwrap();
            let mut cursor = std::io::Cursor::new(&raw);

            // === Parse header ===
            let mut magic = [0u8; 4];
            cursor.read_exact(&mut magic).unwrap();
            if &magic != b"KEY1" {
                panic!("Bad magic");
            }

            // add warning about overwriting keys?
            let key = raw[4..].to_vec();
            key_storage::import_key(&key, args.name).expect("Failed to import key");
            println!("Public key imported successfully")
        }
    }
}
