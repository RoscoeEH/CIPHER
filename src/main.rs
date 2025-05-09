use rpassword::read_password;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub mod asymmetric_crypto;
pub mod constants;
use crate::constants::*;
mod cli;
pub mod key_derivation;
pub mod key_storage;
pub mod random;
pub mod symmetric_encryption;
pub mod user;

use clap::Parser;

fn alg_name_to_id(name: &str) -> Result<u8, Box<dyn Error>> {
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

fn get_password(verify: bool) -> Result<String, Box<dyn Error>> {
    println!("Enter password: ");
    let password = read_password()?;

    if verify {
        println!("Re-enter password: ");
        let verify_password = read_password()?;
        if verify_password != password {
            return Err("The passwords did not match.".into());
        }
    }

    Ok(password)
}

pub struct DerivedKeyInfo {
    pub kdf_id: u8,
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub params: HashMap<&'static str, u32>,
}
pub fn generate_key_from_args(
    args: cli::EncryptArgs,
    profile: user::UserProfile,
) -> DerivedKeyInfo {
    let kdf_id = match args.kdf {
        Some(ref s) => alg_name_to_id(s.as_str()).unwrap(),
        None => profile.kdf_id,
    };

    let password = get_password(true).unwrap();
    let salt = random::get_salt(); // Vec<u8>

    let mut params: HashMap<&'static str, u32> = HashMap::new();

    let key = match kdf_id {
        ARGON2_ID => {
            params.insert(
                "memory_cost",
                args.memory_cost.unwrap_or(profile.memory_cost),
            );
            params.insert("time_cost", args.time_cost.unwrap_or(profile.time_cost));
            params.insert(
                "parallelism",
                args.parallelism.unwrap_or(profile.parallelism),
            );

            key_derivation::id_derive_key(
                kdf_id,
                password.as_str(),
                &salt,
                SYM_KEY_LEN,
                params.clone(),
            )
        }
        PBKDF2_ID => {
            params.insert("iterations", args.iterations.unwrap_or(profile.iterations));

            key_derivation::id_derive_key(
                kdf_id,
                password.as_str(),
                &salt,
                SYM_KEY_LEN,
                params.clone(),
            )
        }
        _ => {
            panic!("Unsupported KDF algorithm ID: {}", kdf_id);
        }
    };

    DerivedKeyInfo {
        kdf_id,
        key,
        salt,
        params,
    }
}

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
            if let Err(err) = args.validate() {
                eprintln!("Argument error: {}", err);
                std::process::exit(1);
            }

            let profile = user::init_profile().unwrap();
            let DerivedKeyInfo {
                kdf_id,
                key,
                salt,
                params,
            } = generate_key_from_args(args.clone(), profile.clone());
            let key_ref = &key;

            let aead_id = match args.aead {
                Some(s) => alg_name_to_id(s.as_str()).unwrap(),
                None => profile.aead_alg_id,
            };

            let input_path = PathBuf::from(args.input.clone().unwrap());
            let original_filename = input_path.file_name().unwrap().to_str().unwrap();
            let filename_bytes = original_filename.as_bytes();
            let filename_len = filename_bytes.len() as u16;

            let mut plaintext_vec = read_file(input_path.to_str().unwrap()).unwrap();
            plaintext_vec.extend_from_slice(filename_bytes);

            let nonce = random::get_nonce();
            let ciphertext =
                symmetric_encryption::id_encrypt(aead_id, key_ref, &nonce, &plaintext_vec)
                    .expect("Encryption failed");

            let out_path = match args.output {
                Some(ref path) => {
                    let mut p = PathBuf::from(path);
                    p.set_extension("enc");
                    p
                }
                None => {
                    let input_path = PathBuf::from(args.input.clone().unwrap());
                    let mut p = input_path.clone();
                    p.set_extension("enc");
                    p
                }
            };
            let mut f = File::create(&out_path).expect("Failed to create output file");

            // === Header: MAGIC | KDF_ID | AEAD_ID | SALT_LEN | SALT | KDF PARAMS ===
            f.write_all(b"ENC1").expect("Failed to write magic bytes");
            f.write_all(&[kdf_id]).expect("Failed to write kdf_id");
            f.write_all(&[aead_id]).expect("Failed to write aead_id");

            f.write_all(&(salt.len() as u32).to_be_bytes())
                .expect("Failed to write salt length");
            f.write_all(&salt).expect("Failed to write salt");

            // === KDF-specific params ===
            match kdf_id {
                ARGON2_ID => {
                    f.write_all(&params["memory_cost"].to_be_bytes())
                        .expect("Failed to write Argon2 memory cost");
                    f.write_all(&params["time_cost"].to_be_bytes())
                        .expect("Failed to write Argon2 time cost");
                    f.write_all(&params["parallelism"].to_be_bytes())
                        .expect("Failed to write Argon2 parallelism");
                }
                PBKDF2_ID => {
                    f.write_all(&params["iterations"].to_be_bytes())
                        .expect("Failed to write PBKDF2 iterations");
                }
                _ => panic!("Unknown KDF ID: {}", kdf_id),
            }
            // === Filename length ===
            f.write_all(&filename_len.to_be_bytes())
                .expect("Failed to write filename length");

            // === Ciphertext (with nonce already included) ===
            f.write_all(&ciphertext)
                .expect("Failed to write ciphertext");
            println!("Encrypted file written to {}", out_path.display());
        }

        cli::Command::Decrypt(args) => {
            if let Err(err) = args.validate() {
                eprintln!("Argument error: {}", err);
                std::process::exit(1);
            }

            let in_path = PathBuf::from(args.input.clone().unwrap());
            let mut f = File::open(&in_path).expect("Failed to open encrypted file");

            // === Read header ===
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic)
                .expect("Failed to read magic bytes");
            if &magic != b"ENC1" {
                panic!("Invalid file format or magic bytes");
            }

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

            // === Read KDF params ===
            let mut params = HashMap::new();
            match kdf_id {
                ARGON2_ID => {
                    let mut buf = [0u8; 4];
                    f.read_exact(&mut buf).expect("Failed to read memory_cost");
                    params.insert("memory_cost", u32::from_be_bytes(buf));

                    f.read_exact(&mut buf).expect("Failed to read time_cost");
                    params.insert("time_cost", u32::from_be_bytes(buf));

                    f.read_exact(&mut buf).expect("Failed to read parallelism");
                    params.insert("parallelism", u32::from_be_bytes(buf));
                }
                PBKDF2_ID => {
                    let mut buf = [0u8; 4];
                    f.read_exact(&mut buf).expect("Failed to read iterations");
                    params.insert("iterations", u32::from_be_bytes(buf));
                }
                _ => panic!("Unknown KDF ID: {}", kdf_id),
            }

            // === Read original filename length ===
            let mut filename_len_buf = [0u8; 2];
            f.read_exact(&mut filename_len_buf)
                .expect("Failed to read filename length");
            let filename_len = u16::from_be_bytes(filename_len_buf) as usize;

            // === Read ciphertext ===
            let mut ciphertext = Vec::new();
            f.read_to_end(&mut ciphertext)
                .expect("Failed to read ciphertext");

            // === Derive key ===
            let password = get_password(false).expect("Failed to get password");
            let key = key_derivation::id_derive_key(
                kdf_id,
                &password,
                &salt,
                SYM_KEY_LEN,
                params.clone(),
            );

            // === Decrypt ===
            let plaintext_with_filename =
                symmetric_encryption::id_decrypt(aead_id, &key, &ciphertext)
                    .expect("Decryption failed");

            // === Extract original filename and file contents ===
            let total_len = plaintext_with_filename.len();
            if filename_len > total_len {
                panic!("Corrupted data: filename length exceeds decrypted content size");
            }

            let filename_start = total_len - filename_len;
            let file_data = &plaintext_with_filename[..filename_start];
            let original_filename =
                String::from_utf8_lossy(&plaintext_with_filename[filename_start..]);

            // === Determine output path ===
            let out_path = match args.output {
                Some(ref path) => PathBuf::from(path),
                None => PathBuf::from(original_filename.to_string()),
            };

            let mut out_file = File::create(&out_path).expect("Failed to create output file");
            out_file
                .write_all(file_data)
                .expect("Failed to write decrypted data");

            println!(
                "Decryption complete. Output written to {}",
                out_path.display()
            );
        }
    }
}
