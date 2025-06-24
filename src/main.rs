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

use secrecy::{ExposeSecret, Secret};
use std::fs::File;
use std::io::{Read, Write};
use std::panic;
use std::path::PathBuf;

pub mod asymmetric_crypto;
pub mod constants;
use crate::constants::*;
pub mod cli;
pub mod key_derivation;
pub mod key_storage;
pub mod random;
pub mod symmetric_encryption;
pub mod user;
pub mod utils;

use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simpler panics for production
    if !cfg!(debug_assertions) {
        panic::set_hook(Box::new(|_info| {
            eprintln!("Something went wrong, please check your inputs.");
        }));
    }
    let cli = cli::Cli::parse();

    match cli.command {
        // Handles all symmetric and asymmetric encryption; also can sign encrypted blobs
        cli::Command::Encrypt(args) => {
            cli::validate_args(&args)?;

            // Checks id the user provided a profile
            let profile = match args.profile.as_str() {
                "Default" => user::init_profile()?,
                other => match user::get_profile(other)? {
                    Some(p) => p,
                    None => {
                        return Err(format!("No profile found matching: {}", other).into());
                    }
                },
            };

            let input_path_str = args
                .input
                .clone()
                .ok_or("Could not find input path".to_string())?;
            let input_path = PathBuf::from(input_path_str);
            let filename = input_path
                .file_name()
                .ok_or_else(|| format!("Input path has no filename: {}", input_path.display()))?
                .to_str()
                .ok_or_else(|| format!("Filename is not valid UTF-8: {}", input_path.display()))?;
            let filename_bytes = filename.as_bytes();
            let filename_len = filename_bytes.len() as u16;

            // Read plaintext
            let mut plaintext = utils::read_file(
                input_path
                    .to_str()
                    .ok_or_else(|| format!("Failed to read file: {}", input_path.display()))?,
            )?;
            plaintext.extend_from_slice(filename_bytes); // Append filename for recovery

            // Determine output path
            let out_path = match args.output {
                Some(ref path) => {
                    let mut p = PathBuf::from(path);
                    p.set_extension("enc");
                    p
                }
                // No output path specified, make one based on input
                None => {
                    let out_path_str = args
                        .input
                        .clone()
                        .ok_or("Could not find input path".to_string())?;
                    let mut p = PathBuf::from(out_path_str);
                    p.set_extension("enc");
                    p
                }
            };

            // Determines if the given key is sym or asym; no key routes to sym
            let asym = match &args.input_key {
                Some(k_id) => utils::get_unowned_or_owned_public_key(&k_id, true).is_ok(),
                None => false,
            };

            match asym {
                true => {
                    // Asymmetric encryption
                    let input_key_id = args.input_key.clone().ok_or_else(|| {
                        "Missing input key ID for asymmetric encryption".to_string()
                    })?;

                    let key = utils::get_unowned_or_owned_public_key(&input_key_id, false)?
                        .ok_or_else(|| format!("Could not find key: {}", input_key_id))?;

                    let sym_alg_id = match args.aead {
                        Some(ref a) => utils::alg_name_to_id(a)?,
                        None => profile.aead_alg_id,
                    };

                    let alg_id = key.key_type();

                    let mut blob = utils::build_asym_encrypted_blob(
                        alg_id, sym_alg_id, &key, filename, &plaintext,
                    )?;

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair = match key_storage::get_key(
                            args.sign_key
                                .ok_or_else(|| "Invalid or no sign key".to_string())?
                                .as_str(),
                        )? {
                            Some(k) => k,
                            None => return Err("Signing key not found.".into()),
                        };
                        let sign_private_key = utils::decrypt_private_key(&sign_key)?;
                        blob = utils::build_signed_blob(
                            b"SIG2",
                            sign_key.key_type,
                            &sign_key.id,
                            "verified.enc",
                            &blob,
                            &sign_private_key,
                        )?;
                    }
                    let mut f = File::create(&out_path)?;
                    f.write_all(&blob)?;

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
                                key_storage::get_key(input_key_id)?.ok_or("Key ID not found")?;

                            let password = utils::get_password(false, Some(true))?;
                            utils::derive_key_from_stored(&mut sym_key, password)?
                        }
                        None => utils::generate_key_from_args(&args, &profile)?,
                    };

                    let aead_id = match args.aead {
                        Some(ref s) => utils::alg_name_to_id(s)?,
                        None => profile.aead_alg_id,
                    };

                    let mut blob =
                        utils::encrypt_sym_blob(&key_info, aead_id, &plaintext, filename_len)?;

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair = match key_storage::get_key(
                            args.sign_key
                                .ok_or_else(|| "No signing key.".to_string())?
                                .as_str(),
                        )? {
                            Some(k) => k,
                            None => panic!("Signing key not found."),
                        };
                        let sign_private_key = utils::decrypt_private_key(&sign_key)?;
                        blob = utils::build_signed_blob(
                            b"SIG2",
                            sign_key.key_type,
                            &sign_key.id,
                            "verified.enc",
                            &blob,
                            &sign_private_key,
                        )?;
                    }
                    let mut f = File::create(&out_path)?;
                    f.write_all(&blob)?;

                    println!("Symmetric encrypted file written to {}", out_path.display());
                }
            };
        }

        cli::Command::Decrypt(args) => {
            cli::validate_args(&args)?;
            let in_path = PathBuf::from(
                args.input
                    .clone()
                    .ok_or_else(|| "No input path.".to_string())?,
            );
            let mut f = File::open(&in_path)?;

            // Read blob and magic
            let mut blob = Vec::new();
            f.read_to_end(&mut blob)?;

            let mut magic: [u8; 4] = blob[..4].try_into()?;

            // Check if data is signed and encrypted
            // if it is => verify/strip the signature
            if &magic == b"SIG2" {
                let valid_sig = utils::verify_signature(&blob)?;
                if valid_sig {
                    println!("Signature verified!")
                } else {
                    utils::warn_user("Unrecognized signature. Would you like to decrypt anyway?")?;
                }
                let (_, encrypted_unsigned_data) = utils::strip_signature_blob(&blob)?;
                blob = encrypted_unsigned_data;
                magic = blob[..4].try_into()?;
            }

            match &magic {
                b"ENC2" => {
                    // Asymmetric decryption
                    let (filename_bytes, plaintext) = utils::decrypt_asym_blob(&blob)?;
                    let original_filename = String::from_utf8_lossy(&filename_bytes);

                    // Get out path and write to file
                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(original_filename.to_string()),
                    };

                    let mut out_file = File::create(&out_path)?;
                    out_file.write_all(&plaintext)?;

                    println!(
                        "Decryption complete. Output written to {}",
                        out_path.display()
                    );
                }
                b"ENC1" => {
                    // Symmetric decryption
                    let (file_data, filename) = utils::decrypt_sym_blob(&blob)?;
                    // Get out path and write file
                    let out_path = match args.output {
                        Some(ref path) => PathBuf::from(path),
                        None => PathBuf::from(filename),
                    };

                    let mut out_file = File::create(&out_path)?;
                    out_file.write_all(&file_data)?;

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
            cli::validate_args(&args)?;
            let id = args
                .profile
                .clone()
                .unwrap_or_else(|| "Default".to_string());

            // Either make a new profile or get the existing one to edit
            let mut profile = match user::get_profile(&id)? {
                Some(p) => p,
                None => user::get_new_profile(id.clone())?,
            };

            // find the thing to update
            match args.update_field.as_str() {
                "aead" => {
                    let id = utils::alg_name_to_id(&args.value)
                        .map_err(|e| format!("Invalid aead_alg_id: {}", e))?;
                    profile.aead_alg_id = id;
                }

                "kdf" => {
                    let id = utils::alg_name_to_id(&args.value)
                        .map_err(|e| format!("Invalid kdf_id: {}", e))?;
                    profile.kdf_id = id;
                }

                "memory_cost" | "time_cost" | "parallelism" | "iterations" => {
                    let number =
                        utils::parse_u32(&args.update_field, &args.value).map_err(|e| {
                            format!("Invalid value for '{}': {}", &args.update_field, e)
                        })?;
                    profile.params.insert(args.update_field.clone(), number);
                }

                field => {
                    return Err(format!("Unknown field '{}'. No changes made.", field).into());
                }
            }

            // Set the new profile
            user::set_profile(&profile)?;
            println!("Updated profile '{}': {:#?}", profile.id, profile);
        }

        cli::Command::ListProfiles => {
            user::init_profile()?;
            user::list_profiles()?;
        }

        cli::Command::KeyGen(args) => {
            cli::validate_args(&args)?;

            // Avoid overwriting keys
            if key_storage::does_key_exist(&args.id)? {
                utils::warn_user(&format!(
                    "There is already a key with the id: {}. Overwrite?",
                    args.id
                ))?;
            }

            // Proceed with key generation
            let password = utils::get_password(true, None)?;

            match &args.asymmetric {
                Some(alg) => {
                    utils::gen_asym_key(
                        alg.clone(),
                        password,
                        args.profile.clone(),
                        args.id.clone(),
                        args.bits,
                    )?;
                }
                None => utils::gen_sym_key(password, args.profile.clone(), args.id.clone())?,
            }
        }
        cli::Command::ListKeys(args) => {
            if !args.unowned {
                key_storage::list_keys()?;
            } else {
                // Can list keys from others
                key_storage::list_unowned_public_keys()?
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
            utils::warn_user(
                "Are you sure you want to wipe all data? This action cannot be undone.",
            )?;

            if args.wipe_profiles {
                user::wipe_profiles()?;
            }
            if args.wipe_keys {
                key_storage::wipe_keystore()?;
            }
            if args.wipe_unowned_keys {
                key_storage::wipe_public_keystore()?
            }
        }

        cli::Command::DeleteKey(args) => {
            if args.unowned {
                if key_storage::does_public_key_exist(&args.id)? {
                    key_storage::delete_public_key(args.id.as_str())?;
                    println!("Key has been deleted.")
                } else {
                    println!("Key does not exist.")
                }
            } else {
                if key_storage::does_key_exist(&args.id)? {
                    key_storage::delete_key(args.id.as_str())?;
                    println!("Key has been deleted.")
                } else {
                    println!("Key does not exist.")
                }
            }
        }

        // signs any data and creates a .sig file
        cli::Command::Sign(args) => {
            cli::validate_args(&args)?;

            let input_path = PathBuf::from(&args.input);
            let filename = input_path
                .file_name()
                .ok_or_else(|| "Invalid or no input filename".to_string())?
                .to_str()
                .ok_or_else(|| "Invalid or no input filename".to_string())?;

            let data = utils::read_file(
                input_path
                    .to_str()
                    .ok_or_else(|| "Invalid or no filename".to_string())?,
            )?;

            // load/decrypt private key
            let keypair: key_storage::AsymKeyPair =
                key_storage::get_key(&args.key_id)?.ok_or("Key ID not found in keystore")?;
            // Compute the kek
            let kek_password = utils::get_password(false, Some(false))?;
            let kek = key_derivation::id_derive_key(
                keypair.kek_kdf,
                kek_password,
                &keypair.kek_salt,
                SYM_KEY_LEN,
                &keypair.kek_params,
            )?;
            let decrypted_private_key = Secret::new(
                symmetric_encryption::id_decrypt(
                    keypair.kek_aead,
                    &kek.expose_secret(),
                    &keypair.private_key,
                    None,
                )
                .map_err(|e| format!("Decryption failed: {:?}", e))?,
            );

            // sign the blob
            let blob = utils::build_signed_blob(
                b"SIG1",
                keypair.key_type,
                args.key_id.as_str(),
                filename,
                &data,
                &decrypted_private_key,
            )?;

            // Write out blob
            let sig_path = input_path.with_extension("sig");
            let mut f = File::create(&sig_path)?;
            f.write_all(&blob)?;

            println!("Signed file written to '{}'", sig_path.display());
        }
        // Verify .sig files and optionally strip the sig data
        cli::Command::Verify(args) => {
            cli::validate_args(&args)?;
            let sig_path = PathBuf::from(&args.input);
            let raw = utils::read_file(
                sig_path
                    .to_str()
                    .ok_or_else(|| "Invalid or no filename".to_string())?,
            )?;

            if !utils::verify_signature(&raw)? {
                return Err("Signature verification failed".into());
            }

            println!("Signature verified.");

            // Stip blob and create new file
            if !args.only_verify {
                let (filename_bytes, data) = utils::strip_signature_blob(&raw)?;
                let original_filename = String::from_utf8_lossy(&filename_bytes);
                let out = sig_path.with_file_name(original_filename.to_string());
                let mut f = File::create(&out)?;
                f.write_all(&data)?;
                println!("Unsigned data written to '{}'", out.display());
            }
        }
        // Creates a .pub of one of your keypairs that others can import
        cli::Command::ExportKey(args) => {
            let key = key_storage::export_key(args.key_id.as_str())?;
            let mut key_file = Vec::new();
            key_file.extend_from_slice(b"KEY1");
            key_file.extend_from_slice(&key);

            let file_name = match args.name {
                Some(s) => s,
                None => String::from("Public_key"),
            };
            let output_path = PathBuf::from(&file_name).with_extension("pub");
            let mut f = File::create(&output_path)?;
            f.write_all(&key_file)?;
            println!("Public key written to '{}'", output_path.display());
        }

        // Reads in .pub files into your key store
        cli::Command::ImportKey(args) => {
            cli::validate_args(&args)?;
            let key_path = PathBuf::from(&args.input_file);
            let raw = utils::read_file(
                key_path
                    .to_str()
                    .ok_or_else(|| "Invalid or no filename".to_string())?,
            )?;
            let mut cursor = std::io::Cursor::new(&raw);

            // Parse header
            let mut magic = [0u8; 4];
            cursor.read_exact(&mut magic)?;
            if &magic != b"KEY1" {
                panic!("Bad magic");
            }

            let key = raw[4..].to_vec();
            let key_id = key_storage::get_id_from_serialized_public_key(&key)?;

            // Avoid overwriting
            if key_storage::does_public_key_exist(&key_id)? {
                utils::warn_user(
                    format!(
                        "There is already a key with ID: {}. Would you like to overwrite?",
                        key_id
                    )
                    .as_str(),
                )?
            }
            key_storage::import_key(&key, args.name)?;
            println!("Public key imported successfully");
        }
    }
    Ok(())
}
