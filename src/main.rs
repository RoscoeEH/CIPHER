use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use zeroize::Zeroize;

/// Generate a random salt of the given length (default 16 bytes).
fn generate_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random nonce for AES-GCM (default 12 bytes).
fn generate_nonce(length: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; length];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a cryptographic key from a password and salt using Argon2.
///
/// # Arguments
/// * `password` - The password as a string slice.
/// * `salt` - The salt as a byte slice.
/// * `dklen` - Desired key length in bytes (default: 32).
///
/// # Returns
/// A vector containing the derived key bytes.
fn derive_key(password: &str, salt: &[u8], dklen: usize) -> Vec<u8> {
    let params = Params::new(
        256 * 1024, // memory_cost (kibibytes)
        8,          // time_cost (iterations)
        4,          // parallelism (lanes)
        Some(dklen),
    )
    .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; dklen];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 hashing failed");
    key
}

/// Encrypt data using AES-GCM mode.
///
/// Args:
///     data: The data to encrypt (bytes or string).
///     key: The encryption key (32 bytes, mutable for zeroization).
///     nonce: The nonce to use for encryption (12 bytes recommended).
///
/// Returns:
///     ciphertext_with_tag: Encrypted data with authentication tag appended.
fn encrypt_data(
    data: impl AsRef<[u8]>,
    key: &mut [u8],
    nonce: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    // Ensure key is 32 bytes (AES-256-GCM)
    assert_eq!(key.len(), 32, "Key must be 32 bytes");
    assert_eq!(nonce.len(), 12, "Nonce must be 12 bytes");

    // Create key and nonce types
    let key_obj = Key::<Aes256Gcm>::from_slice(key);
    let nonce_obj = Nonce::from_slice(nonce);

    // Create AESGCM cipher
    let cipher = Aes256Gcm::new(key_obj);

    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce_obj, data.as_ref())?;

    // After using the key, zeroize it
    key.zeroize();

    Ok(ciphertext)
}

/// Decrypt data using AES-GCM mode.
///
/// Args:
///     ciphertext: The encrypted data with authentication tag appended.
///     key: The encryption key (32 bytes, mutable for zeroization).
///     nonce: The nonce used for encryption (12 bytes).
///
/// Returns:
///     The decrypted plaintext as bytes, or an error if authentication fails.
fn decrypt_data(
    ciphertext: &[u8],
    key: &mut [u8],
    nonce: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    // Ensure key is 32 bytes (AES-256-GCM)
    assert_eq!(key.len(), 32, "Key must be 32 bytes");
    assert_eq!(nonce.len(), 12, "Nonce must be 12 bytes");

    // Create key and nonce types
    let key_obj = Key::<Aes256Gcm>::from_slice(key);
    let nonce_obj = Nonce::from_slice(nonce);

    // Create AESGCM cipher
    let cipher = Aes256Gcm::new(key_obj);

    // Decrypt the data
    let plaintext = cipher.decrypt(nonce_obj, ciphertext)?;

    // After using the key, zeroize it
    key.zeroize();

    Ok(plaintext)
}

fn encrypt_file_to_dir(plaintext_path: &str) -> Result<(), Box<dyn Error>> {
    // Read plaintext
    let mut file = File::open(plaintext_path)?;
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext)?;

    // Prompt for password twice
    println!("Enter password for encryption: ");
    let password1 = read_password()?;
    println!("Re-enter password to verify: ");
    let password2 = read_password()?;

    if password1 != password2 {
        eprintln!("Passwords do not match. Aborting.");
        return Err("Passwords do not match.".into());
    }
    let password = password1;

    // Generate salt, key, and nonce
    let salt = generate_salt(16);
    let mut key = derive_key(&password, &salt, 32);
    let nonce = generate_nonce(12);
    let ciphertext = encrypt_data(&plaintext, &mut key, &nonce)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Zeroize key
    key.zeroize();

    let path = Path::new(plaintext_path);
    let filename_lossy = path.file_name().unwrap().to_string_lossy();
    let filename = filename_lossy.as_bytes();
    let filename_len = filename.len() as u16;

    // Write everything to a single file
    let out_path = path.with_extension("enc");
    let mut f = File::create(&out_path)?;

    // Optional: magic bytes
    f.write_all(b"ENC1")?;
    // Salt
    f.write_all(&salt)?;
    // Nonce
    f.write_all(&nonce)?;
    // Filename length (big-endian)
    f.write_all(&(filename_len.to_be_bytes()))?;
    // Filename
    f.write_all(filename)?;
    // Ciphertext
    f.write_all(&ciphertext)?;

    println!("Encrypted file written to: {}", out_path.display());
    Ok(())
}

fn decrypt_file_from_enc(enc_file_path: &str) -> Result<(), Box<dyn Error>> {
    let mut f = File::open(enc_file_path)?;

    // Read and check magic bytes
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic != b"ENC1" {
        return Err("Invalid file format or magic bytes".into());
    }

    // Read salt (16 bytes)
    let mut salt = [0u8; 16];
    f.read_exact(&mut salt)?;

    // Read nonce (12 bytes)
    let mut nonce = [0u8; 12];
    f.read_exact(&mut nonce)?;

    // Read filename length (2 bytes, big-endian)
    let mut filename_len_bytes = [0u8; 2];
    f.read_exact(&mut filename_len_bytes)?;
    let filename_len = u16::from_be_bytes(filename_len_bytes) as usize;

    // Read filename
    let mut filename_bytes = vec![0u8; filename_len];
    f.read_exact(&mut filename_bytes)?;
    let filename = String::from_utf8(filename_bytes)?;

    // Read the rest as ciphertext
    let mut ciphertext = Vec::new();
    f.read_to_end(&mut ciphertext)?;

    // Prompt for password
    println!("Enter password for decryption: ");
    let password = read_password()?;

    // Derive key
    let mut key = derive_key(&password, &salt, 32);

    // Decrypt
    let plaintext = decrypt_data(&ciphertext, &mut key, &nonce)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    // Zeroize key
    key.zeroize();

    // Write decrypted file
    let out_path = Path::new(enc_file_path).with_file_name(filename);
    let mut out_f = File::create(&out_path)?;
    out_f.write_all(&plaintext)?;

    println!("Decrypted file written to: {}", out_path.display());
    Ok(())
}

// Command line parsing setup
#[derive(Parser)]
#[command(
    name = "File Encryption",
    about = "Encrypt or decrypt files using AES-GCM and PBKDF2."
)]
struct Cli {
    #[arg(value_parser = ["encrypt", "decrypt", "e", "d"])]
    mode: String,
    path: String,
}

fn main() {
    let args = Cli::parse();

    let result = match args.mode.as_str() {
        "encrypt" | "e" => encrypt_file_to_dir(&args.path),
        "decrypt" | "d" => decrypt_file_from_enc(&args.path),
        _ => {
            eprintln!("Unknown mode. Use 'encrypt', 'decrypt', 'e', or 'd'.");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}
