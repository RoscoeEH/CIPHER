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
use std::process::exit;

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

fn main() {
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

            // Read plaintext
            let mut plaintext = utils::read_file(input_path.to_str().unwrap()).unwrap();
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
                Some(k_id) => utils::get_unowned_or_owned_public_key(&k_id, true).is_ok(),
                None => false,
            };

            match asym {
                true => {
                    // Asymmetric encryption
                    let input_key_id = args
                        .input_key
                        .clone()
                        .expect("Missing input key ID for asymmetric encryption");

                    let key = utils::get_unowned_or_owned_public_key(&input_key_id, false)
                        .unwrap()
                        .expect("No key found.");

                    let sym_alg_id = match args.aead {
                        Some(ref a) => utils::alg_name_to_id(a).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let alg_id = key.key_type();

                    let mut blob = utils::build_asym_encrypted_blob(
                        alg_id, sym_alg_id, &key, filename, &plaintext,
                    )
                    .expect("Failed to encrypt");

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair =
                            match key_storage::get_key(args.sign_key.unwrap().as_str()).unwrap() {
                                Some(k) => k,
                                None => panic!("Signing key not found."),
                            };
                        let sign_private_key = utils::decrypt_private_key(&sign_key).unwrap();
                        blob = utils::build_signed_blob(
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

                            let password = utils::get_password(false, Some(true));
                            utils::derive_key_from_stored(&mut sym_key, password)
                                .expect("Failed to derive key from stored key")
                        }
                        None => utils::generate_key_from_args(&args, &profile),
                    };

                    let aead_id = match args.aead {
                        Some(ref s) => utils::alg_name_to_id(s).unwrap(),
                        None => profile.aead_alg_id,
                    };

                    let mut blob =
                        utils::encrypt_sym_blob(&key_info, aead_id, &plaintext, filename_len)
                            .expect("Failed to construct encrypted blob");

                    // If there is a signing key, sign the data
                    if args.sign_key.is_some() {
                        let sign_key: key_storage::AsymKeyPair =
                            match key_storage::get_key(args.sign_key.unwrap().as_str()).unwrap() {
                                Some(k) => k,
                                None => panic!("Signing key not found."),
                            };
                        let sign_private_key = utils::decrypt_private_key(&sign_key).unwrap();
                        blob = utils::build_signed_blob(
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
                let valid_sig =
                    utils::verify_signature(&blob).expect("signature verfication failed.");
                if valid_sig {
                    println!("Signature verified!")
                } else {
                    utils::warn_user_or_exit(
                        "Unrecognized signature. Would you like to decrypt anyway?",
                    );
                }
                let (_, encrypted_unsigned_data) = utils::strip_signature_blob(&blob).unwrap();
                blob = encrypted_unsigned_data;
                magic = blob[..4]
                    .try_into()
                    .expect("Blob too short to contain magic");
            }

            match &magic {
                b"ENC2" => {
                    // Asymmetric decryption
                    let (filename_bytes, plaintext) = utils::decrypt_asym_blob(&blob).unwrap();
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
                    let (file_data, filename) =
                        utils::decrypt_sym_blob(&blob).expect("Decryption failed");
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
                    let number = utils::parse_u32_or_exit(&args.update_field, &args.value);
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
            if key_storage::does_key_exist(&args.id).unwrap() {
                utils::warn_user_or_exit(&format!(
                    "There is already a key with the id: {}. Overwrite?",
                    args.id
                ));
            }

            // Proceed with key generation
            let password = utils::get_password(true, None);

            match &args.asymmetric {
                Some(alg) => {
                    utils::gen_asym_key(
                        alg.clone(),
                        password,
                        args.profile.clone(),
                        args.id.clone(),
                        args.bits,
                    )
                    .expect("Failed to generate new key.");
                }
                None => {
                    utils::gen_sym_key(password, args.profile.clone(), args.id.clone())
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
            utils::warn_user_or_exit(
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
                if key_storage::does_public_key_exist(&args.id).unwrap() {
                    key_storage::delete_public_key(args.id.as_str())
                        .expect("Failed to delete key.");
                    println!("Key has been deleted.")
                } else {
                    println!("Key does not exist.")
                }
            } else {
                if key_storage::does_key_exist(&args.id).unwrap() {
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
            let data = utils::read_file(input_path.to_str().unwrap()).unwrap();

            // load/decrypt private key
            let keypair: key_storage::AsymKeyPair = key_storage::get_key(&args.key_id)
                .unwrap()
                .ok_or("Key ID not found in keystore")
                .unwrap();
            // Compute the kek
            let kek_password = utils::get_password(false, Some(false));
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
            let blob = utils::build_signed_blob(
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
            let raw = utils::read_file(sig_path.to_str().unwrap()).unwrap();

            if !utils::verify_signature(&raw).unwrap() {
                println!("Signature verification failed");
                exit(0);
            }

            println!("Signature verified.");

            // Stip blob and create new file
            if !args.only_verify {
                let (filename_bytes, data) = utils::strip_signature_blob(&raw).unwrap();
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
            let raw = utils::read_file(key_path.to_str().unwrap()).unwrap();
            let mut cursor = std::io::Cursor::new(&raw);

            // Parse header
            let mut magic = [0u8; 4];
            cursor.read_exact(&mut magic).unwrap();
            if &magic != b"KEY1" {
                panic!("Bad magic");
            }

            let key = raw[4..].to_vec();
            let key_id = key_storage::get_id_from_serialized_public_key(&key).unwrap();

            // Avoid overwriting
            if key_storage::does_public_key_exist(&key_id).unwrap() {
                utils::warn_user_or_exit(
                    format!(
                        "There is already a key with ID: {}. Would you like to overwrite?",
                        key_id
                    )
                    .as_str(),
                )
            }
            key_storage::import_key(&key, args.name).expect("Failed to import key");
            println!("Public key imported successfully")
        }
    }
}
