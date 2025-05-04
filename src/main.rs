use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use clap::Parser;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword::read_password;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
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
    let argon2 = Argon2::default();
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

    // Encrypt
    let ciphertext = encrypt_data(&plaintext, &mut key, &nonce)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Zeroize key
    key.zeroize();

    // Prepare output directory: same name as file, no extension
    let path = Path::new(plaintext_path);
    let base = path.file_stem().unwrap();
    let out_dir = path.parent().unwrap_or_else(|| Path::new("")).join(base);
    fs::create_dir_all(&out_dir)?;

    // Write encrypted data, salt, and nonce
    let mut f = File::create(out_dir.join("ciphertext.bin"))?;
    f.write_all(&ciphertext)?;
    let mut f = File::create(out_dir.join("salt.bin"))?;
    f.write_all(&salt)?;
    let mut f = File::create(out_dir.join("nonce.bin"))?;
    f.write_all(&nonce)?;
    // Save the original filename
    let mut f = File::create(out_dir.join("original_filename.txt"))?;
    f.write_all(path.file_name().unwrap().to_string_lossy().as_bytes())?;

    println!(
        "Encrypted data, salt, and nonce saved in directory: {}",
        out_dir.display()
    );
    Ok(())
}

fn decrypt_dir_to_file(encrypted_dir: &str) -> Result<(), Box<dyn Error>> {
    // Prepare paths
    let dir_path = Path::new(encrypted_dir);
    let ciphertext_path = dir_path.join("ciphertext.bin");
    let salt_path = dir_path.join("salt.bin");
    let nonce_path = dir_path.join("nonce.bin");

    // Read encrypted data, salt, and nonce
    let mut ciphertext = Vec::new();
    File::open(&ciphertext_path)?.read_to_end(&mut ciphertext)?;
    let mut salt = Vec::new();
    File::open(&salt_path)?.read_to_end(&mut salt)?;
    let mut nonce = Vec::new();
    File::open(&nonce_path)?.read_to_end(&mut nonce)?;

    // Prompt for password
    println!("Enter password for decryption: ");
    let password = read_password()?;

    // Generate key
    let mut key = derive_key(&password, &salt, 32);

    // Decrypt
    let plaintext = match decrypt_data(&ciphertext, &mut key, &nonce) {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("Decryption failed: {e}");
            key.zeroize();
            return Ok(());
        }
    };

    // Zeroize key
    key.zeroize();

    // Get original filename
    let original_filename_path = dir_path.join("original_filename.txt");
    let original_filename = if original_filename_path.exists() {
        let mut s = String::new();
        File::open(&original_filename_path)?.read_to_string(&mut s)?;
        s.trim().to_string()
    } else {
        "decrypted.txt".to_string()
    };

    // Write decrypted file
    let decrypted_path = dir_path.join(&original_filename);
    let mut f = File::create(&decrypted_path)?;
    f.write_all(&plaintext)?;

    println!("Decrypted file written to: {}", decrypted_path.display());
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
        "decrypt" | "d" => decrypt_dir_to_file(&args.path),
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
