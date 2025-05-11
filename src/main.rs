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

/// Prompts the user to enter a password securely, optionally verifying it by double entry.
///
/// This function reads a password from stdin without echoing it to the terminal.
/// If `verify` is `true`, the user is prompted to re-enter the password for confirmation.
/// If the entries do not match, an error is returned.
///
/// # Arguments
/// * `verify` - If `true`, requires the user to enter the password twice for verification.
///
/// # Returns
/// * `Ok(Secret<String>)` containing the password if input (and verification) succeeded.
/// * `Err` if reading fails or the passwords do not match.
fn get_password(verify: bool) -> Result<Secret<String>, Box<dyn Error>> {
    println!("Enter password: ");
    let password = Secret::new(read_password()?);

    if verify {
        println!("Re-enter password: ");
        let verify_password = Secret::new(read_password()?);
        if verify_password.expose_secret() != password.expose_secret() {
            return Err("The passwords did not match.".into());
        }
    }

    Ok(password)
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
pub fn generate_key_from_args(
    args: &cli::EncryptArgs,
    profile: &user::UserProfile,
) -> DerivedKeyInfo {
    let kdf_id = match args.kdf {
        Some(ref s) => utils::alg_name_to_id(s.as_str()).unwrap(),
        None => profile.kdf_id,
    };

    let password = get_password(true).unwrap();
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

/// Derives a symmetric encryption key based on CLI input and user profile settings.
///
/// This function prompts the user for a password (with optional verification),
/// selects the appropriate key derivation function (KDF) based on CLI arguments
/// or a fallback user profile, and derives a key using a randomly generated salt
/// and the specified parameters.
///
/// # Arguments
/// * `args` - CLI arguments provided by the user, possibly containing a custom KDF name.
/// * `profile` - The user's cryptographic profile containing default KDF and parameters.
///
/// # Returns
/// * `DerivedKeyInfo` - Struct containing the derived key, salt, KDF ID, and parameters.
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

/// Checks if a key with the given ID exists in the keystore.
///
/// This function attempts to look up both symmetric (`SymKey`) and asymmetric (`AsymKeyPair`)
/// key entries with the provided ID. If either exists, the function returns `true`.
///
/// # Arguments
/// * `id` - The string identifier of the key to check for existence.
///
/// # Returns
/// * `Result<bool, Box<dyn Error>>` - Returns `Ok(true)` if a key with the given ID exists,
///   `Ok(false)` if not, or an `Err` if an unexpected error occurs during lookup.
///
/// # Notes
/// Errors from individual key lookups are ignored (assumed as "not found").
fn does_key_exist(id: String) -> Result<bool, Box<dyn Error>> {
    // Check if a symmetric or asymmetric key with the same ID already exists
    let sym_key_exists = match key_storage::get_key::<key_storage::SymKey>(id.as_str()) {
        Ok(opt) => opt.is_some(),
        Err(_e) => false,
    };

    let asym_key_exists = match key_storage::get_key::<key_storage::AsymKeyPair>(id.as_str()) {
        Ok(opt) => opt.is_some(),
        Err(_e) => false,
    };
    Ok(sym_key_exists || asym_key_exists)
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

fn main() {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Encrypt(args) => {
            cli::validate_args(&args);
            let profile = user::init_profile().unwrap();

            let input_path = PathBuf::from(args.input.clone().unwrap());
            let filename = input_path.file_name().unwrap().to_str().unwrap();
            let filename_bytes = filename.as_bytes();
            let filename_len = filename_bytes.len() as u16;

            // === Read and prepare plaintext ===
            let mut plaintext = read_file(input_path.to_str().unwrap()).unwrap();
            plaintext.extend_from_slice(filename_bytes); // Append filename for recovery

            // === Determine output path ===
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

            match args.asym {
                true => {
                    // === Asymmetric encryption ===
                    let input_key_id = args
                        .input_key
                        .clone()
                        .expect("Missing input key ID for asymmetric encryption");

                    let keypair: key_storage::AsymKeyPair = key_storage::get_key(&input_key_id)
                        .unwrap()
                        .ok_or("Key ID not found in keystore")
                        .unwrap();

                    let sym_alg_id = match args.aead {
                        Some(ref a) => utils::alg_name_to_id(a).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let alg_id = keypair.key_type;
                    let pub_key = &keypair.public_key;

                    let ciphertext = asymmetric_crypto::id_asym_enc(
                        alg_id,
                        pub_key,
                        &plaintext,
                        Some(sym_alg_id),
                    )
                    .unwrap();

                    let mut f = File::create(&out_path).expect("Failed to create output file");

                    // === Write header: MAGIC | ALG_ID | SYM_ALG_ID | KEY_ID_LEN | KEY_ID | FILENAME_LEN ===
                    let key_id_bytes = keypair.id.as_bytes();
                    let key_id_len = key_id_bytes.len() as u16;

                    f.write_all(b"ENC2").expect("Failed to write magic");
                    f.write_all(&[alg_id]).expect("Failed to write alg_id");
                    f.write_all(&[sym_alg_id])
                        .expect("Failed to write sym_alg_id");

                    f.write_all(&key_id_len.to_be_bytes())
                        .expect("Failed to write key ID length");
                    f.write_all(key_id_bytes).expect("Failed to write key ID");

                    f.write_all(&filename_len.to_be_bytes())
                        .expect("Failed to write filename length");

                    f.write_all(&ciphertext)
                        .expect("Failed to write ciphertext");

                    println!(
                        "Asymmetric encrypted file written to {}",
                        out_path.display()
                    );
                }

                false => {
                    // === Symmetric encryption ===
                    let key_info = match args.input_key {
                        Some(ref input_key_id) => {
                            let mut sym_key: key_storage::SymKey =
                                key_storage::get_key(input_key_id)
                                    .unwrap()
                                    .ok_or("Key ID not found")
                                    .unwrap();

                            let password = get_password(false).expect("Failed to get password");
                            derive_key_from_stored(&mut sym_key, password)
                                .expect("Failed to derive key from stored key")
                        }
                        None => generate_key_from_args(&args, &profile),
                    };

                    let key_ref = &key_info.key;
                    let kdf_id = key_info.kdf_id;
                    let salt = &key_info.salt;
                    let params = &key_info.params;

                    let aead_id = match args.aead {
                        Some(ref s) => utils::alg_name_to_id(s).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let nonce = random::get_nonce();

                    // === Construct header in memory
                    let mut header = Vec::new();
                    header.extend_from_slice(b"ENC1");
                    header.extend_from_slice(&[kdf_id, aead_id]);
                    header.extend_from_slice(&(salt.len() as u32).to_be_bytes());
                    header.extend_from_slice(salt);

                    match kdf_id {
                        ARGON2_ID => {
                            header.extend_from_slice(&params["memory_cost"].to_be_bytes());
                            header.extend_from_slice(&params["time_cost"].to_be_bytes());
                            header.extend_from_slice(&params["parallelism"].to_be_bytes());
                        }
                        PBKDF2_ID => {
                            header.extend_from_slice(&params["iterations"].to_be_bytes());
                        }
                        _ => panic!("Unknown KDF"),
                    }

                    header.extend_from_slice(&filename_len.to_be_bytes());

                    // === Encrypt with header as AAD
                    let ciphertext = symmetric_encryption::id_encrypt(
                        aead_id,
                        key_ref.expose_secret(),
                        &nonce,
                        &plaintext,
                        Some(&header),
                    )
                    .unwrap();

                    // === Write output file
                    let mut f = File::create(&out_path).expect("Failed to create output file");

                    f.write_all(&header).unwrap();
                    f.write_all(&ciphertext).unwrap();

                    println!("Symmetric encrypted file written to {}", out_path.display());
                }
            };
        }

        cli::Command::Decrypt(args) => {
            cli::validate_args(&args);
            let in_path = PathBuf::from(args.input.clone().unwrap());
            let mut f = File::open(&in_path).expect("Failed to open encrypted file");

            // === Read magic header ===
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic)
                .expect("Failed to read magic bytes");

            match &magic {
                b"ENC1" => {
                    // === Symmetric decryption ===
                    let mut kdf_id_buf = [0u8; 1];
                    f.read_exact(&mut kdf_id_buf)
                        .expect("Failed to read kdf_id");
                    let kdf_id = kdf_id_buf[0];

                    let mut aead_id_buf = [0u8; 1];
                    f.read_exact(&mut aead_id_buf)
                        .expect("Failed to read aead_id");
                    let aead_id = aead_id_buf[0];

                    let mut salt_len_buf = [0u8; 4];
                    f.read_exact(&mut salt_len_buf)
                        .expect("Failed to read salt length");
                    let salt_len = u32::from_be_bytes(salt_len_buf) as usize;

                    let mut salt = vec![0u8; salt_len];
                    f.read_exact(&mut salt).expect("Failed to read salt");

                    // === KDF parameters ===
                    let mut params = HashMap::new();
                    let mut param_bytes = Vec::new(); // Accumulate bytes for AAD
                    match kdf_id {
                        ARGON2_ID => {
                            let mut buf = [0u8; 4];

                            f.read_exact(&mut buf).expect("Failed to read memory_cost");
                            param_bytes.extend_from_slice(&buf);
                            params.insert("memory_cost".to_string(), u32::from_be_bytes(buf));

                            f.read_exact(&mut buf).expect("Failed to read time_cost");
                            param_bytes.extend_from_slice(&buf);
                            params.insert("time_cost".to_string(), u32::from_be_bytes(buf));

                            f.read_exact(&mut buf).expect("Failed to read parallelism");
                            param_bytes.extend_from_slice(&buf);
                            params.insert("parallelism".to_string(), u32::from_be_bytes(buf));
                        }
                        PBKDF2_ID => {
                            let mut buf = [0u8; 4];
                            f.read_exact(&mut buf).expect("Failed to read iterations");
                            param_bytes.extend_from_slice(&buf);
                            params.insert("iterations".to_string(), u32::from_be_bytes(buf));
                        }
                        _ => panic!("Unknown KDF ID: {}", kdf_id),
                    }

                    let mut filename_len_buf = [0u8; 2];
                    f.read_exact(&mut filename_len_buf)
                        .expect("Failed to read filename length");
                    let filename_len = u16::from_be_bytes(filename_len_buf) as usize;

                    // === Read ciphertext after header
                    let mut ciphertext = Vec::new();
                    f.read_to_end(&mut ciphertext)
                        .expect("Failed to read ciphertext");

                    // === Reconstruct header AAD
                    let mut aad = Vec::new();
                    aad.extend_from_slice(b"ENC1");
                    aad.push(kdf_id);
                    aad.push(aead_id);
                    aad.extend_from_slice(&salt_len_buf);
                    aad.extend_from_slice(&salt);
                    aad.extend_from_slice(&param_bytes);
                    aad.extend_from_slice(&filename_len_buf);

                    // === Derive key and decrypt
                    let password = get_password(false).expect("Failed to get password");
                    let key = key_derivation::id_derive_key(
                        kdf_id,
                        password,
                        &salt,
                        SYM_KEY_LEN,
                        &params,
                    );

                    let plaintext_with_filename = symmetric_encryption::id_decrypt(
                        aead_id,
                        &key.expose_secret(),
                        &ciphertext,
                        Some(&aad), // <- pass AAD
                    )
                    .expect("Decryption failed");

                    let total_len = plaintext_with_filename.len();
                    if filename_len > total_len {
                        panic!("Corrupted data: filename length exceeds decrypted content size");
                    }

                    let filename_start = total_len - filename_len;
                    let file_data = &plaintext_with_filename[..filename_start];
                    let original_filename =
                        String::from_utf8_lossy(&plaintext_with_filename[filename_start..]);

                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(original_filename.to_string()),
                    };

                    let mut out_file =
                        File::create(&out_path).expect("Failed to create output file");
                    out_file
                        .write_all(file_data)
                        .expect("Failed to write decrypted data");

                    println!(
                        "Decryption complete. Output written to {}",
                        out_path.display()
                    );
                }
                b"ENC2" => {
                    // === Asymmetric decryption ===
                    let mut alg_id_buf = [0u8; 1];
                    f.read_exact(&mut alg_id_buf)
                        .expect("Failed to read alg_id");
                    let alg_id = alg_id_buf[0];

                    let mut sym_alg_id_buf = [0u8; 1];
                    f.read_exact(&mut sym_alg_id_buf)
                        .expect("Failed to read sym_alg_id");
                    let sym_alg_id = sym_alg_id_buf[0];

                    let mut key_id_len_buf = [0u8; 2];
                    f.read_exact(&mut key_id_len_buf)
                        .expect("Failed to read key ID length");
                    let key_id_len = u16::from_be_bytes(key_id_len_buf) as usize;

                    let mut key_id_buf = vec![0u8; key_id_len];
                    f.read_exact(&mut key_id_buf)
                        .expect("Failed to read key ID");
                    let key_id = String::from_utf8_lossy(&key_id_buf).to_string();

                    let mut filename_len_buf = [0u8; 2];
                    f.read_exact(&mut filename_len_buf)
                        .expect("Failed to read filename length");
                    let filename_len = u16::from_be_bytes(filename_len_buf) as usize;

                    let mut ciphertext = Vec::new();
                    f.read_to_end(&mut ciphertext)
                        .expect("Failed to read ciphertext");

                    // === Retrieve key from keystore ===
                    let keypair: key_storage::AsymKeyPair = key_storage::get_key(&key_id)
                        .unwrap()
                        .ok_or("Key ID not found in keystore")
                        .unwrap();

                    // === Prompt for password and derive KEK ===
                    let kek_password = get_password(false).expect("Failed to get password");
                    let kek = key_derivation::id_derive_key(
                        keypair.kek_kdf,
                        kek_password,
                        &keypair.kek_salt,
                        SYM_KEY_LEN,
                        &keypair.kek_params,
                    );

                    // === Decrypt the stored private key ===
                    let decrypted_priv_key = Secret::new(
                        symmetric_encryption::id_decrypt(
                            keypair.kek_aead,
                            &kek.expose_secret(),
                            &keypair.private_key,
                            None,
                        )
                        .expect("Failed to decrypt private key"),
                    );

                    // === Proceed with asymmetric decryption ===
                    let plaintext_with_filename = asymmetric_crypto::id_asym_dec(
                        alg_id,
                        &decrypted_priv_key.expose_secret(),
                        &ciphertext,
                        Some(sym_alg_id),
                    )
                    .expect("Decryption failed");

                    let total_len = plaintext_with_filename.len();
                    if filename_len > total_len {
                        panic!("Corrupted data: filename length exceeds decrypted content size");
                    }

                    let filename_start = total_len - filename_len;
                    let file_data = &plaintext_with_filename[..filename_start];
                    let original_filename =
                        String::from_utf8_lossy(&plaintext_with_filename[filename_start..]);

                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(original_filename.to_string()),
                    };

                    let mut out_file =
                        File::create(&out_path).expect("Failed to create output file");
                    out_file
                        .write_all(file_data)
                        .expect("Failed to write decrypted data");

                    println!(
                        "Decryption complete. Output written to {}",
                        out_path.display()
                    );
                }

                _ => panic!("Unknown encryption format"),
            }
        }

        cli::Command::Profile(args) => {
            cli::validate_args(&args);
            let id = args
                .profile
                .clone()
                .unwrap_or_else(|| "Default".to_string());

            let mut profile = match user::get_profile(&id).unwrap() {
                Some(p) => p,
                None => user::get_new_profile(id.clone()),
            };

            match args.update_field.as_str() {
                "aead_alg_id" => match utils::alg_name_to_id(&args.value) {
                    Ok(id) => profile.aead_alg_id = id,
                    Err(e) => {
                        eprintln!("Invalid aead_alg_id: {}", e);
                        std::process::exit(1);
                    }
                },

                "kdf_id" => match utils::alg_name_to_id(&args.value) {
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

            user::set_profile(&profile).expect("Failed to save updated profile");
            println!("Updated profile '{}': {:#?}", profile.id, profile);
        }

        cli::Command::ListProfiles => {
            user::init_profile().expect("Failed to set a default profile");
            user::list_profiles().expect("Failed to list profiles");
        }

        cli::Command::KeyGen(args) => {
            cli::validate_args(&args);

            if does_key_exist(args.id.clone()).unwrap() {
                print!(
                    "There is already a key with the id: {}. Overwrite? [y/N]: ",
                    args.id
                );
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Key generation cancelled.");
                    exit(0);
                }
            }

            // Proceed with key generation
            let password = get_password(true).expect("Failed to get password.");

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
        cli::Command::ListKeys => {
            key_storage::list_keys().expect("Failed to list keys");
        }
        cli::Command::Wipe(mut args) => {
            if !args.wipe_keys && !args.wipe_profiles {
                args.wipe_keys = true;
                args.wipe_profiles = true;
            }
            if args.wipe_keys && args.wipe_profiles {
                print!(
                    "Are you sure you want to wipe all data? This action cannot be undone. [y/N]: "
                );
            } else if args.wipe_keys {
                print!(
                    "Are you sure you want to wipe all keys? This action cannot be undone. [y/N]: "
                );
            } else {
                print!(
                    "Are you sure you want to wipe all profiles? This action cannot be undone. [y/N]: "
                );
            }
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().eq_ignore_ascii_case("y") {
                if args.wipe_profiles {
                    user::wipe_profiles().unwrap();
                }
                if args.wipe_keys {
                    key_storage::wipe_keystore().unwrap();
                }
                println!("Wipe successfull.");
            } else {
                println!("Wipe cancelled.");
            }
        }

        cli::Command::DeleteKey(args) => {
            if does_key_exist(args.id.clone()).unwrap() {
                key_storage::delete_key(args.id.as_str()).expect("Failed to delete key.");
                println!("Key has been deleted.")
            } else {
                println!("Key does not exist.")
            }
        }

        cli::Command::Sign(args) => {
            cli::validate_args(&args);

            let input_path = PathBuf::from(&args.input);
            let filename = input_path.file_name().unwrap().to_str().unwrap();
            let data = read_file(input_path.to_str().unwrap()).unwrap();

            // … load & decrypt private key exactly as before …
            let keypair: key_storage::AsymKeyPair = key_storage::get_key(&args.key_id)
                .unwrap()
                .ok_or("Key ID not found in keystore")
                .unwrap();
            let kek_password = get_password(false).unwrap();
            let kek = key_derivation::id_derive_key(
                keypair.kek_kdf,
                kek_password,
                &keypair.kek_salt,
                SYM_KEY_LEN,
                &keypair.kek_params,
            );
            let decrypted_priv = Secret::new(
                symmetric_encryption::id_decrypt(
                    keypair.kek_aead,
                    &kek.expose_secret(),
                    &keypair.private_key,
                    None,
                )
                .unwrap(),
            );

            let alg_id = keypair.key_type;
            let key_id_bytes = args.key_id.as_bytes();
            let filename_bytes = filename.as_bytes();

            // === Build header ===
            let mut header = Vec::new();
            header.extend_from_slice(b"SIG1");
            header.push(alg_id);
            header.push(key_id_bytes.len() as u8);
            header.extend_from_slice(key_id_bytes);
            header.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());
            header.extend_from_slice(filename_bytes);
            header.extend_from_slice(&(data.len() as u64).to_be_bytes()); // DATA_LEN

            // === Sign header+data ===
            let mut signed_blob = header.clone();
            signed_blob.extend_from_slice(&data);
            let data_hash = hash(&signed_blob);
            let signature =
                asymmetric_crypto::id_sign(alg_id, &decrypted_priv.expose_secret(), &data_hash)
                    .expect("Signing failed");

            // === Write out: header, data, then signature ===
            let sig_path = input_path.with_extension("sig");
            let mut f = File::create(&sig_path).expect("Failed to create output file");
            f.write_all(&header).unwrap();
            f.write_all(&data).unwrap();
            f.write_all(&signature).unwrap();

            println!("Signed file written to '{}'", sig_path.display());
        }
        cli::Command::Verify(args) => {
            cli::validate_args(&args);

            let sig_path = PathBuf::from(&args.input);
            let raw = read_file(sig_path.to_str().unwrap()).unwrap();
            let mut cursor = std::io::Cursor::new(&raw);

            // === Parse header ===
            let mut magic = [0u8; 4];
            cursor.read_exact(&mut magic).unwrap();
            if &magic != b"SIG1" {
                panic!("Bad magic");
            }

            let mut buf1 = [0u8; 1];
            cursor.read_exact(&mut buf1).unwrap();
            let alg_id = buf1[0];

            cursor.read_exact(&mut buf1).unwrap();
            let key_id_len = buf1[0] as usize;
            let mut key_id_bytes = vec![0u8; key_id_len];
            cursor.read_exact(&mut key_id_bytes).unwrap();
            let key_id = String::from_utf8_lossy(&key_id_bytes);

            let mut buf2 = [0u8; 2];
            cursor.read_exact(&mut buf2).unwrap();
            let filename_len = u16::from_be_bytes(buf2) as usize;
            let mut filename_bytes = vec![0u8; filename_len];
            cursor.read_exact(&mut filename_bytes).unwrap();
            let original_filename = String::from_utf8_lossy(&filename_bytes);

            let mut buf8 = [0u8; 8];
            cursor.read_exact(&mut buf8).unwrap();
            let data_len = u64::from_be_bytes(buf8) as usize;

            let header_len = 4 + 1 + 1 + key_id_len + 2 + filename_len + 8;

            // === Extract data & signature ===
            let data_start = header_len;
            let data_end = data_start + data_len;
            if raw.len() < data_end {
                panic!("File too short for declared data length");
            }
            let data = &raw[data_start..data_end];
            let signature = &raw[data_end..];

            // === Reconstruct signed blob ===
            let signed_blob = &raw[..data_end];
            let data_hash = hash(&signed_blob);

            // === Load public key ===
            let keypair: key_storage::AsymKeyPair = key_storage::get_key(&key_id)
                .unwrap()
                .ok_or("Key ID not found")
                .unwrap();
            let pub_key = keypair.public_key;

            // === Verify ===
            asymmetric_crypto::id_verify(alg_id, &pub_key, &data_hash, signature)
                .expect("Signature verification failed");

            println!("Signature verified.");

            // optionally write unsigned file:
            if !args.only_verify {
                let out = sig_path.with_file_name(original_filename.to_string());
                let mut f = File::create(&out).unwrap();
                f.write_all(data).unwrap();
                println!("Unsigned data written to '{}'", out.display());
            }
        }
    }
}
