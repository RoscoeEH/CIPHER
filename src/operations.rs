// operations.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Implements high-level cryptographic workflows including encryption, decryption,
// signing, verification, and key import/export operations. This module coordinates
// lower-level crypto primitives and utility functions into complete routines
// used by the CLI interface and other components.

use secrecy::{ExposeSecret, Secret};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::cli::*;
use crate::constants::*;
use crate::key_derivation::*;
use crate::key_storage::*;
use crate::symmetric_encryption::*;
use crate::user::*;
use crate::utils::*;

pub fn encrypt_op(args: EncryptArgs) -> Result<(), Box<dyn Error>> {
    // Checks id the user provided a profile
    let profile = match args.profile.as_str() {
        "Default" => init_profile()?,
        other => match get_profile(other)? {
            Some(p) => p,
            None => {
                return Err(format!("No profile found matching: {}", other).into());
            }
        },
    };
    let mut plaintext = Vec::<u8>::new();
    let mut filename = String::from("file.txt");

    // Read in plaintext either from the input file or the clipboard
    match args.from_clip {
        true => {
            plaintext.extend_from_slice(&read_clipboard()?);
            plaintext.extend_from_slice(&filename.as_bytes())
        }
        false => {
            let input_path_str = args
                .input
                .clone()
                .ok_or("Could not find input path".to_string())?;
            let input_path = PathBuf::from(input_path_str);
            filename = input_path
                .file_name()
                .ok_or_else(|| format!("Input path has no filename: {}", input_path.display()))?
                .to_str()
                .ok_or_else(|| format!("Filename is not valid UTF-8: {}", input_path.display()))?
                .to_string();
            let filename_bytes = filename.as_bytes();
            let file_bytes = read_file(
                input_path
                    .to_str()
                    .ok_or_else(|| format!("Failed to read file: {}", input_path.display()))?,
            )?;
            // Read plaintext
            plaintext.extend_from_slice(&file_bytes);
            plaintext.extend_from_slice(filename_bytes);
        }
    }

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
                .ok_or_else(|| "Missing input key ID for asymmetric encryption".to_string())?;

            let key = get_unowned_or_owned_public_key(&input_key_id, false)?
                .ok_or_else(|| format!("Could not find key: {}", input_key_id))?;

            let sym_alg_id = match args.aead {
                Some(ref a) => alg_name_to_id(a)?,
                None => profile.aead_alg_id,
            };

            let alg_id = key.key_type();

            let mut blob =
                build_asym_encrypted_blob(alg_id, sym_alg_id, &key, &filename, &plaintext)?;

            // If there is a signing key, sign the data
            if args.sign_key.is_some() {
                let sign_key: AsymKeyPair = match get_key(
                    args.sign_key
                        .ok_or_else(|| "Invalid or no sign key".to_string())?
                        .as_str(),
                )? {
                    Some(k) => k,
                    None => return Err("Signing key not found.".into()),
                };
                let sign_private_key = decrypt_private_key(&sign_key)?;
                blob = build_signed_blob(
                    b"SIG2",
                    sign_key.key_type,
                    &sign_key.id,
                    "verified.enc",
                    &blob,
                    &sign_private_key,
                )?;
            }
            match args.to_clip {
                true => {
                    write_clipboard(blob)?;
                    println!("Asymmetric encrypted text copied to clipboard");
                }
                false => {
                    let out_path = get_output_path(args.output, args.input)?;
                    let mut f = File::create(&out_path)?;
                    f.write_all(&blob)?;

                    println!(
                        "Asymmetric encrypted file written to {}",
                        out_path.display()
                    );
                }
            }
        }

        false => {
            // Symmetric encryption

            // Either get a key from the store or generate a single use one
            let key_info = match args.input_key {
                Some(ref input_key_id) => {
                    let mut sym_key: SymKey = get_key(input_key_id)?.ok_or("Key ID not found")?;

                    let password = get_password(false, Some(true))?;
                    derive_key_from_stored(&mut sym_key, password)?
                }
                None => generate_key_from_args(&args, &profile)?,
            };

            let aead_id = match args.aead {
                Some(ref s) => alg_name_to_id(s)?,
                None => profile.aead_alg_id,
            };

            let filename_len = filename.len() as u16;

            let mut blob = encrypt_sym_blob(&key_info, aead_id, &plaintext, &filename_len)?;

            // If there is a signing key, sign the data
            if args.sign_key.is_some() {
                let sign_key: AsymKeyPair = match get_key(
                    args.sign_key
                        .ok_or_else(|| "No signing key.".to_string())?
                        .as_str(),
                )? {
                    Some(k) => k,
                    None => return Err("Signing key not found".into()),
                };
                let sign_private_key = decrypt_private_key(&sign_key)?;
                blob = build_signed_blob(
                    b"SIG2",
                    sign_key.key_type,
                    &sign_key.id,
                    "verified.enc",
                    &blob,
                    &sign_private_key,
                )?;
            }

            match args.to_clip {
                true => {
                    write_clipboard(blob)?;
                    println!("Symmetric encrypted text copied to clipboard");
                }
                false => {
                    let out_path = get_output_path(args.output, args.input)?;
                    let mut f = File::create(&out_path)?;
                    f.write_all(&blob)?;

                    println!("Symmetric encrypted file written to {}", out_path.display());
                }
            }
        }
    };
    Ok(())
}

pub fn decrypt_op(args: DecryptArgs) -> Result<(), Box<dyn Error>> {
    // Read blob and magic
    let mut blob = Vec::new();

    match args.from_clip {
        true => blob.extend_from_slice(&read_clipboard()?),
        false => {
            let in_path = PathBuf::from(
                args.input
                    .clone()
                    .ok_or_else(|| "No input path.".to_string())?,
            );
            let mut f = File::open(&in_path)?;
            f.read_to_end(&mut blob)?;
        }
    }

    let mut magic: [u8; 4] = blob[..4].try_into()?;

    // Check if data is signed and encrypted
    // if it is => verify/strip the signature
    if &magic == b"SIG2" {
        let valid_sig = verify_signature(&blob)?;
        if valid_sig {
            println!("Signature verified!")
        } else {
            warn_user("Unrecognized signature. Would you like to decrypt anyway?")?;
        }
        let (_, encrypted_unsigned_data) = strip_signature_blob(&blob)?;
        blob = encrypted_unsigned_data;
        magic = blob[..4].try_into()?;
    }

    // Decrypt the text
    let (plaintext, filename) = match &magic {
        b"ENC1" => decrypt_sym_blob(&blob)?,
        b"ENC2" => decrypt_asym_blob(&blob)?,
        _ => return Err("Unknown encryption format".into()),
    };

    if args.to_clip {
        write_clipboard(plaintext)?;
        println!("Decryption complete. Output copied to clipboard");
    } else {
        let out_path = match args.output {
            Some(ref path) => PathBuf::from(path),
            None => PathBuf::from(filename.to_string()),
        };

        let mut out_file = File::create(&out_path)?;
        out_file.write_all(&plaintext)?;

        println!(
            "Decryption complete. Output written to {}",
            out_path.display()
        );
    }
    Ok(())
}

pub fn update_profile_op(args: ProfileArgs) -> Result<(), Box<dyn Error>> {
    let id = args
        .profile
        .clone()
        .unwrap_or_else(|| "Default".to_string());

    // Either make a new profile or get the existing one to edit
    let mut profile = match get_profile(&id)? {
        Some(p) => p,
        None => get_new_profile(id.clone())?,
    };

    // find the thing to update
    match args.update_field.as_str() {
        "aead" => {
            let id = alg_name_to_id(&args.value)?;
            profile.aead_alg_id = id;
        }

        "kdf" => {
            let id = alg_name_to_id(&args.value)?;
            profile.kdf_id = id;
        }

        "memory_cost" | "time_cost" | "parallelism" | "iterations" => {
            let number = parse_u32(&args.update_field, &args.value)?;
            profile.params.insert(args.update_field.clone(), number);
        }

        field => {
            return Err(format!("Unknown field '{}'. No changes made.", field).into());
        }
    }

    // Set the new profile
    set_profile(&profile)?;
    println!("Updated profile '{}': {:#?}", profile.id, profile);
    Ok(())
}

pub fn key_gen_op(args: KeyGenArgs) -> Result<(), Box<dyn Error>> {
    // Avoid overwriting keys
    if does_key_exist(&args.id)? {
        warn_user(&format!(
            "There is already a key with the id: {}. Overwrite?",
            args.id
        ))?;
    }

    // Proceed with key generation
    let password = get_password(true, None)?;

    match &args.asymmetric {
        Some(alg) => {
            gen_asym_key(
                alg.clone(),
                password,
                args.profile.clone(),
                args.id.clone(),
                args.bits,
            )?;
        }
        None => gen_sym_key(password, args.profile.clone(), args.id.clone())?,
    }

    Ok(())
}

pub fn list_keys_op(args: ListKeyArgs) -> Result<(), Box<dyn Error>> {
    if !args.unowned {
        list_keys()?;
    } else {
        // Can list keys from others
        list_unowned_public_keys()?
    }

    Ok(())
}

pub fn wipe_op(mut args: WipeArgs) -> Result<(), Box<dyn Error>> {
    // if none were specified wipe all
    if !args.wipe_keys && !args.wipe_profiles && !args.wipe_unowned_keys {
        args.wipe_keys = true;
        args.wipe_profiles = true;
        args.wipe_unowned_keys = true;
    }
    warn_user("Are you sure you want to wipe all data? This action cannot be undone.")?;

    if args.wipe_profiles {
        wipe_profiles()?;
    }
    if args.wipe_keys {
        wipe_keystore()?;
    }
    if args.wipe_unowned_keys {
        wipe_public_keystore()?;
    }
    Ok(())
}

pub fn delete_keys_op(args: DeleteKeyArgs) -> Result<(), Box<dyn Error>> {
    if args.unowned {
        if does_public_key_exist(&args.id)? {
            delete_public_key(args.id.as_str())?;
            println!("Key has been deleted.")
        } else {
            println!("Key does not exist.")
        }
    } else {
        if does_key_exist(&args.id)? {
            delete_key(args.id.as_str())?;
            println!("Key has been deleted.")
        } else {
            println!("Key does not exist.")
        }
    }
    Ok(())
}

pub fn sign_op(args: SignArgs) -> Result<(), Box<dyn Error>> {
    let input_path = PathBuf::from(&args.input);
    let filename = input_path
        .file_name()
        .ok_or_else(|| "Invalid or no input filename".to_string())?
        .to_str()
        .ok_or_else(|| "Invalid or no input filename".to_string())?;

    let data = read_file(
        input_path
            .to_str()
            .ok_or_else(|| "Invalid or no filename".to_string())?,
    )?;

    // load/decrypt private key
    let keypair: AsymKeyPair = get_key(&args.key_id)?.ok_or("Key ID not found in keystore")?;
    // Compute the kek
    let kek_password = get_password(false, Some(false))?;
    let kek = id_derive_key(
        keypair.kek_kdf,
        kek_password,
        &keypair.kek_salt,
        SYM_KEY_LEN,
        &keypair.kek_params,
    )?;
    let decrypted_private_key = Secret::new(id_decrypt(
        keypair.kek_aead,
        &kek.expose_secret(),
        &keypair.private_key,
        None,
    )?);

    // sign the blob
    let blob = build_signed_blob(
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
    Ok(())
}

pub fn verify_op(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    let sig_path = PathBuf::from(&args.input);
    let raw = read_file(
        sig_path
            .to_str()
            .ok_or_else(|| "Invalid or no filename".to_string())?,
    )?;

    if !verify_signature(&raw)? {
        return Err("Signature verification failed".into());
    }

    println!("Signature verified.");

    // Stip blob and create new file
    if !args.only_verify {
        let (filename_bytes, data) = strip_signature_blob(&raw)?;
        let original_filename = String::from_utf8_lossy(&filename_bytes);
        let out = sig_path.with_file_name(original_filename.to_string());
        let mut f = File::create(&out)?;
        f.write_all(&data)?;
        println!("Unsigned data written to '{}'", out.display());
    }
    Ok(())
}

pub fn export_key_op(args: ExportKeyArgs) -> Result<(), Box<dyn Error>> {
    let key = export_key(args.key_id.as_str())?;
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
    Ok(())
}

pub fn import_key_op(args: ImportKeyArgs) -> Result<(), Box<dyn Error>> {
    let key_path = PathBuf::from(&args.input_file);
    let raw = read_file(
        key_path
            .to_str()
            .ok_or_else(|| "Invalid or no filename".to_string())?,
    )?;
    let mut cursor = std::io::Cursor::new(&raw);

    // Parse header
    let mut magic = [0u8; 4];
    cursor.read_exact(&mut magic)?;
    if &magic != b"KEY1" {
        return Err("Bad magic".into());
    }

    let key = raw[4..].to_vec();
    let key_id = get_id_from_serialized_public_key(&key)?;

    // Avoid overwriting
    if does_public_key_exist(&key_id)? {
        warn_user(
            format!(
                "There is already a key with ID: {}. Would you like to overwrite?",
                key_id
            )
            .as_str(),
        )?
    }
    import_key(&key, args.name)?;
    println!("Public key imported successfully");
    Ok(())
}
