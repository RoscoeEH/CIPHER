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
// time handling, parsing helpers, wrappers for interpretting user inputs, etc...

use crate::asymmetric_crypto::{id_asym_dec, id_asym_enc, id_keypair_gen, id_sign, id_verify};
use crate::cli::EncryptArgs;
use crate::constants::*;
use crate::key_derivation::id_derive_key;
use crate::key_storage::{
    get_key, get_unowned_public_key, store_key, AsymKeyPair, SymKey, UnownedPublicKey,
};
use crate::random::{get_nonce, get_salt};
use crate::symmetric_encryption::{id_decrypt, id_encrypt};
use crate::user::{get_profile, init_profile, UserProfile};

use chrono::{DateTime, Utc};
use rpassword::read_password;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};

// === String/int convertions ===

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

/// Parses a string into a `u32`, returning an error if parsing fails.
///
/// # Arguments
/// - `field`: The name of the field being parsed, included in the error message.
/// - `value`: The string value to parse into a `u32`.
///
/// # Returns
/// - `Ok(u32)` containing the parsed value if successful.
/// - `Err(Box<dyn Error>)` with a descriptive message if parsing fails.
///
/// # Errors
/// Returns an error if the input string cannot be parsed into a valid `u32`.
pub fn parse_u32(field: &str, value: &str) -> Result<u32, Box<dyn Error>> {
    value
        .parse::<u32>()
        .map_err(|e| format!("Invalid number for '{}': {}", field, e).into())
}

// === Time helpers ===

/// Returns the current time as a UNIX timestamp (seconds since epoch).
pub fn now_as_u64() -> u64 {
    Utc::now().timestamp() as u64
}

/// Converts a DateTime<Utc> to a UNIX timestamp (u64).
pub fn datetime_to_u64(datetime: DateTime<Utc>) -> u64 {
    datetime.timestamp() as u64
}

/// Converts a UNIX timestamp (u64) to a DateTime<Utc>.
pub fn u64_to_datetime(ts: u64) -> Result<DateTime<Utc>, String> {
    DateTime::<Utc>::from_timestamp(ts as i64, 0)
        .ok_or_else(|| format!("Invalid UNIX timestamp: {ts}"))
}
// === flow and input helpers ===

/// Prompts the user for a password, optionally verifying it by re-entry.
///
/// Displays a context-specific prompt depending on whether the key is symmetric,
/// asymmetric, or unspecified. Reads the password securely from standard input.
/// If verification is enabled, prompts the user to re-enter the password and
/// checks that both entries match.
///
/// # Arguments
/// - `verify`: Whether to prompt the user for password verification by re-entry.
/// - `is_sym_key`: Optional flag indicating key type:
///    - `Some(true)`: symmetric key
///    - `Some(false)`: asymmetric key
///    - `None`: unspecified key type
///
/// # Returns
/// - `Ok(Secret<String>)`: The securely wrapped password if input succeeds and matches (if verifying).
/// - `Err(Box<dyn Error>)`: If reading input fails or verification fails.
///
/// # Panics
/// Panics if reading the password encounters an I/O error.
///
/// # Exits
/// Exits the process with an error if the password verification fails.
pub fn get_password(
    verify: bool,
    is_sym_key: Option<bool>,
) -> Result<Secret<String>, Box<dyn Error>> {
    // If TESTING env var is set, return "password" directly
    if env::var("TESTING").is_ok() {
        return Ok(Secret::new("password".to_string()));
    }

    match is_sym_key {
        Some(true) => println!("Enter password for symmetric key: "),
        Some(false) => println!("Enter password for asymmetric key: "),
        None => println!("Enter password: "),
    };

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

/// Reads the entire contents of a file into a byte vector.
///
/// Opens the file at the given path and reads all bytes into memory,
/// returning the data as a vector of bytes. Suitable for reading both
/// binary and text files as raw bytes.
///
/// # Arguments
/// - `path`: A string slice specifying the file path to read.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The full contents of the file as bytes on success.
/// - `Err(Box<dyn Error>)`: An error if the file cannot be opened or read.
pub fn read_file(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

/// Displays a warning message and prompts the user for confirmation before continuing.
///
/// This function prints the given warning message followed by a `[y/N]` prompt. If the user
/// enters anything other than `"y"` (case-insensitive), it prints a cancellation message
/// and exits the operation by returning an error.
///
/// # Arguments
/// - `message`: The warning message to show before the confirmation prompt.
///
/// # Returns
/// - `Ok(())` if the user confirms with `"y"`.
/// - `Err` if the user cancels or an I/O error occurs.
///
/// # Exits
/// Exits the process with status 0 if the user does not confirm with `"y"`.
///
/// # Panics
/// Panics if writing to stdout or reading from stdin fails.
pub fn warn_user(message: &str) -> Result<(), Box<dyn Error>> {
    print!("{} [y/N]: ", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled");
        return Err("Operation cancelled by user.".into());
    }

    Ok(())
}

// === Key use helpers ===

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
/// This function determines which key derivation function (KDF) to use based on the
/// provided CLI arguments or defaults to the user's profile KDF. It securely prompts
/// the user for a password (with verification), generates a random salt, and derives
/// the key using the specified KDF and profile parameters.
///
/// # Arguments
/// - `args`: Command-line arguments which may specify a custom KDF name.
/// - `profile`: The user profile containing default KDF ID and parameter settings.
///
/// # Returns
/// - `Ok(DerivedKeyInfo)`: Contains the derived key bytes, salt, KDF ID, and parameters.
/// - `Err`: If an unsupported KDF ID is specified, password input fails, or derivation fails.
pub fn generate_key_from_args(
    args: &EncryptArgs,
    profile: &UserProfile,
) -> Result<DerivedKeyInfo, Box<dyn Error>> {
    let kdf_id = match args.kdf {
        Some(ref s) => alg_name_to_id(s.as_str())?,
        None => profile.kdf_id,
    };

    let password = get_password(true, Some(true))?;
    let salt = get_salt()?; // Vec<u8>

    let key = match kdf_id {
        ARGON2_ID => id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &profile.params),
        PBKDF2_ID => id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &profile.params),
        _ => {
            return Err(format!("Unsupported KDF algorithm ID: {}", kdf_id).into());
        }
    }?;

    Ok(DerivedKeyInfo {
        kdf_id,
        key,
        salt,
        params: profile.params.clone(),
    })
}

/// Derives a symmetric encryption key from stored metadata and a user-provided password.
///
/// This function uses stored key metadata—including the KDF ID, salt, and derivation parameters—
/// to derive a symmetric key from the given password. It verifies the correctness of the
/// derived key by comparing its hash against a stored verification hash. Upon successful
/// verification, the function increments the key's usage count and updates the stored metadata.
///
/// # Arguments
/// - `sym_key`: Mutable reference to the stored symmetric key metadata.
/// - `password`: The user’s password securely wrapped in a `Secret`.
///
/// # Returns
/// - `Ok(DerivedKeyInfo)`: Contains the derived key, KDF ID, salt, and parameters on success.
/// - `Err`: If key verification fails or storing the updated key metadata fails.
///
/// # Errors
/// Returns an error if key verification fails, if persisting the updated key metadata fails,
/// or if the specified KDF ID is unsupported.
pub fn derive_key_from_stored(
    sym_key: &mut SymKey,
    password: Secret<String>,
) -> Result<DerivedKeyInfo, Box<dyn Error>> {
    let derived = id_derive_key(
        sym_key.derivation_method_id,
        password,
        &sym_key.salt,
        SYM_KEY_LEN,
        &sym_key.derivation_params,
    )?;

    let derived_hash = hash(&derived.expose_secret())?;
    if derived_hash[..] != sym_key.verification_hash[..] {
        return Err("Key verification failed".into());
    }

    sym_key.use_count += 1;
    store_key(sym_key).map_err(|e| format!("Store error: {e}"))?;

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
/// resolves the algorithm ID from the provided name, and generates a new asymmetric keypair
/// using that algorithm. It then derives a Key Encryption Key (KEK) from the user's password
/// and profile's key derivation settings, which is used to encrypt the private key. The encrypted
/// private key, public key, and related metadata are stored securely in the keystore.
///
/// # Arguments
/// - `asym_id`: The name of the asymmetric algorithm (e.g., `"rsa"` or `"ecc"`).
/// - `password`: The user-supplied password used to derive the KEK.
/// - `profile_id`: The user profile ID specifying AEAD and KDF parameters.
/// - `name`: A unique identifier to associate with the stored keypair.
/// - `bits`: The key size or curve size in bits (algorithm-dependent).
///
/// # Returns
/// - `Ok(())` if the keypair is successfully generated and stored.
/// - `Err` if any step in profile retrieval, key generation, key derivation, encryption, or storage fails.
///
/// # Errors
/// Returns an error if profile lookup, algorithm ID resolution, key derivation, encryption, or storage fails.
pub fn gen_asym_key(
    asym_id: String,
    password: Secret<String>,
    profile_id: String,
    name: String,
    bits: usize,
) -> Result<(), Box<dyn Error>> {
    let profile = match get_profile(profile_id.as_str())? {
        Some(p) => p,
        None => init_profile()?,
    };
    let alg_id = alg_name_to_id(asym_id.as_str())?;

    let (priv_key, pub_key) = id_keypair_gen(alg_id, Some(bits))?;

    let kek_salt_bytes = get_salt()?;
    // Fix how profiles store params first
    let kek = id_derive_key(
        profile.kdf_id,
        password,
        &kek_salt_bytes,
        SYM_KEY_LEN,
        &profile.params,
    )?;

    let keypair_to_store = AsymKeyPair {
        id: name,
        key_type: alg_id,
        public_key: pub_key,
        private_key: id_encrypt(
            profile.aead_alg_id,
            &kek.expose_secret(),
            &get_nonce()?,
            &priv_key.expose_secret(),
            None,
        )?,
        kek_salt: kek_salt_bytes,
        kek_kdf: profile.kdf_id,
        kek_params: profile.params,
        kek_aead: profile.aead_alg_id,
        created: now_as_u64(),
    };
    store_key(&keypair_to_store)?;
    Ok(())
}

/// Generates a new symmetric key by deriving it from the provided password and profile settings.
///
/// This function generates a random salt and uses the provided password to derive the key.
/// The derived key itself is not stored; instead, a hash of the key is saved for future verification,
/// along with KDF parameters, salt, and related metadata.
///
/// # Arguments
/// - `password`: The user-provided password, securely wrapped in a `Secret<String>`.
/// - `profile_id`: The ID of the user profile defining the KDF method and its parameters.
/// - `name`: A unique name to associate with the stored symmetric key.
///
/// # Returns
/// - `Ok(())` if the key is successfully derived and stored.
/// - `Err` if profile retrieval, key derivation, hashing, or storage fails.
///
/// # Errors
/// Returns an error if the profile cannot be retrieved or initialized, if key derivation fails,
/// or if storing the key metadata fails.
pub fn gen_sym_key(
    password: Secret<String>,
    profile_id: String,
    name: String,
) -> Result<(), Box<dyn Error>> {
    let salt_vec = get_salt()?;
    let profile = match get_profile(profile_id.as_str())? {
        Some(p) => p,
        None => init_profile()?,
    };
    let params: HashMap<String, u32> = profile.params;
    let key = id_derive_key(profile.kdf_id, password, &salt_vec, SYM_KEY_LEN, &params)?;
    let key_to_store = SymKey {
        id: name,
        salt: salt_vec,
        derivation_method_id: profile.kdf_id,
        derivation_params: params.clone(),
        verification_hash: hash(&key.expose_secret())?,
        created: now_as_u64(),
        use_count: 0,
    };

    store_key(&key_to_store)?;
    Ok(())
}

/// Represents a public key entry that may be either owned or unowned by the user.
///
/// This enum abstracts over both unowned public keys (e.g., imported from external sources)
/// and fully owned asymmetric key pairs. It provides unified access to common key metadata
/// such as the key ID, type, and public key bytes.
pub enum PublicKeyEntry {
    Unowned(UnownedPublicKey),
    Owned(AsymKeyPair),
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

/// Attempts to retrieve a public key by ID from unowned keys first, then optionally from owned keys.
///
/// This function first tries to find an unowned public key with the given `key_id`.
/// If found, it returns the key wrapped as `PublicKeyEntry::Unowned`.
///
/// If no unowned key is found, and if `quiet` is `false`, it proceeds to attempt loading
/// an owned asymmetric keypair with the same ID without prompting the user.
/// If the user prompt was part of an earlier version, it is now removed.
///
/// If the owned keypair is found and matches the expected type (`AsymKeyPair`), it is returned
/// wrapped as `PublicKeyEntry::Owned`. If no owned key is found or the type does not match,
/// returns `Ok(None)`.
///
/// # Arguments
/// * `key_id` - The identifier of the key to look up.
/// * `quiet` - If `true`, suppresses any user interaction or warnings (currently no prompts).
///
/// # Returns
/// * `Ok(Some(PublicKeyEntry))` if a matching unowned or owned key is found.
/// * `Ok(None)` if no matching key is found or if the owned key type is incompatible.
/// * `Err` if an unexpected error occurs during retrieval.
pub fn get_unowned_or_owned_public_key(
    key_id: &str,
    quiet: bool,
) -> Result<Option<PublicKeyEntry>, Box<dyn Error>> {
    let public_key = get_unowned_public_key(&key_id)?;

    let key_entry = match public_key {
        Some(k) => PublicKeyEntry::Unowned(k),
        None => {
            if !quiet {
                warn_user(&format!(
                    "Could not find unowned public key with ID: {}. Would you like to try an owned key?",
                    key_id
                ))?;
            }

            match get_key::<AsymKeyPair>(&key_id) {
                Ok(Some(keypair)) => PublicKeyEntry::Owned(keypair),
                Ok(None) => return Ok(None), // Key not found
                Err(e) => {
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
pub fn decrypt_private_key(keypair: &AsymKeyPair) -> Result<Secret<Vec<u8>>, Box<dyn Error>> {
    // Prompt for password
    let kek_password = get_password(false, Some(false))?;

    // Derive KEK using stored parameters
    let kek = id_derive_key(
        keypair.kek_kdf,
        kek_password,
        &keypair.kek_salt,
        SYM_KEY_LEN,
        &keypair.kek_params,
    )?;

    // Decrypt the stored private key
    let decrypted = id_decrypt(
        keypair.kek_aead,
        &kek.expose_secret(),
        &keypair.private_key,
        None,
    )?;

    Ok(Secret::new(decrypted))
}

// === Encryption helpers ===

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
/// * `Result<Vec<u8>, Box<dyn Error>>` - A result containing the encrypted blob as a `Vec<u8>`. The blob includes:
///    - A header consisting of magic bytes, algorithm IDs, key ID length, key ID, and filename length.
///    - The encrypted content (ciphertext).
///
/// # Errors
/// Returns an error if the encryption process fails, such as an invalid public key or encryption algorithm error.
pub fn build_asym_encrypted_blob(
    alg_id: u8,
    sym_alg_id: u8,
    key: &PublicKeyEntry,
    filename: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let pub_key = key.public_key();

    let data_to_encrypt = plaintext.to_vec();

    // encrypt the data
    let ciphertext = id_asym_enc(alg_id, &pub_key, &data_to_encrypt, Some(sym_alg_id))?;

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
/// * `Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>` - A tuple containing:
///   - `Vec<u8>` representing the filename bytes (in UTF-8),
///   - `Vec<u8>` representing the decrypted plaintext data.
///
/// # Errors
/// Returns an error in the following cases:
///   - Invalid magic value in the header (should be `ENC2`),
///   - Error reading the algorithm IDs or key ID,
///   - Failure to retrieve the private key from the key storage,
///   - Decryption failure, including if the filename length exceeds the decrypted content size.
pub fn decrypt_asym_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
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
    let keypair = get_key(&key_id)?.ok_or("Key entry is None")?;

    let decrypted_priv_key = decrypt_private_key(&keypair)?;

    let plaintext_with_filename = id_asym_dec(
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
/// * `Result<(Vec<u8>, String), Box<dyn Error>>` - A tuple containing:
///   - `Vec<u8>` representing the decrypted file data,
///   - `String` representing the filename (UTF-8 encoded).
///
/// # Errors
/// Returns an error in the following cases:
///   - Invalid magic value in the header (should be `ENC1`),
///   - Failure in reading or processing KDF parameters or salt,
///   - Decryption failure,
///   - Corrupted data, where the filename length exceeds the size of the decrypted content.
pub fn decrypt_sym_blob(blob: &[u8]) -> Result<(Vec<u8>, String), Box<dyn Error>> {
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
    let password = get_password(false, Some(true))?;
    let key = id_derive_key(kdf_id, password, &salt, SYM_KEY_LEN, &params)?;

    let plaintext_with_filename =
        id_decrypt(aead_id, &key.expose_secret(), &ciphertext, Some(&aad))?;

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
pub fn encrypt_sym_blob(
    key_info: &DerivedKeyInfo,
    aead_id: u8,
    plaintext: &[u8],
    filename_len: u16,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let nonce = get_nonce()?;

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

    // Encrypt with header as AAD
    let ciphertext = id_encrypt(
        aead_id,
        key_info.key.expose_secret(),
        &nonce,
        plaintext,
        Some(&header),
    )?;

    // Return blob: header || ciphertext
    let mut blob = header;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

// === Signature helpers ===

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
/// # Errors
/// Returns an error if the signing operation encounters an issue, such as key mismatch or cryptographic failure.
pub fn build_signed_blob(
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
    let data_hash = hash(&signed_blob)?;
    let signature = id_sign(alg_id, decrypted_priv.expose_secret(), &data_hash)?;

    // Output full blob
    signed_blob.extend_from_slice(&signature);
    Ok(signed_blob)
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
/// * `Result<bool, Box<dyn Error>>` - A result containing a boolean:
///   - `true` if the signature is successfully verified,
///   - `false` if no matching public key is found or signature verification fails.
///
/// # Errors
/// Returns an error if the blob's magic is invalid, the header is not properly formatted, or there is an issue during signature verification.
/// Possible errors include:
///   - Invalid magic value in the header,
///   - Inconsistent blob length compared to the header's data length,
///   - Failure to find or verify the public key for the signature.
pub fn verify_signature(raw: &[u8]) -> Result<bool, Box<dyn Error>> {
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
    let data_hash = hash(signed_blob)?;

    let pub_key_option = get_unowned_or_owned_public_key(&key_id, false);
    match pub_key_option {
        Ok(pub_key) => {
            id_verify(
                alg_id,
                &pub_key
                    .ok_or_else(|| "Signature verification failed.")?
                    .public_key(),
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
/// * `Result<(Vec<u8>, Vec<u8>), Box<dyn Error>>` - A tuple containing:
///   - `Vec<u8>` representing the filename bytes (in the form of UTF-8),
///   - `Vec<u8>` representing the actual signed data.
///
/// # Errors
/// Returns an error if the blob has an invalid magic, malformed header, or the data length doesn't match the expected size of the blob.
/// Possible errors include:
///   - Invalid magic value in the header (should be either `SIG1` or `SIG2`),
///   - Inconsistent blob length compared to the header's data length.
pub fn strip_signature_blob(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
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

// === Other ===

/// Computes the SHA-256 hash of the input data.
///
/// # Arguments
/// * `data` - A byte slice containing the data to hash.
///
/// # Returns
/// * A `Vec<u8>` containing the 32-byte SHA-256 digest.
pub fn hash(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}
