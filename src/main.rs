use rpassword::read_password;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::exit;
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
pub mod utils;

use clap::Parser;

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

fn parse_u32_or_exit(field: &str, value: &str) -> u32 {
    value.parse::<u32>().unwrap_or_else(|_| {
        eprintln!("Invalid number for '{}'", field);
        std::process::exit(1);
    })
}

fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub struct DerivedKeyInfo {
    pub kdf_id: u8,
    pub key: Vec<u8>,
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
        ARGON2_ID => key_derivation::id_derive_key(
            kdf_id,
            password.as_str(),
            &salt,
            SYM_KEY_LEN,
            &profile.params,
        ),
        PBKDF2_ID => key_derivation::id_derive_key(
            kdf_id,
            password.as_str(),
            &salt,
            SYM_KEY_LEN,
            &profile.params,
        ),
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

pub fn derive_key_from_stored(
    sym_key: &mut key_storage::SymKey,
    password: &str,
) -> Result<DerivedKeyInfo, String> {
    let derived = key_derivation::id_derive_key(
        sym_key.derivation_method_id,
        password,
        &sym_key.salt,
        SYM_KEY_LEN,
        &sym_key.derivation_params,
    );

    let derived_hash = Sha256::digest(&derived);
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

fn gen_asym_key(
    asym_id: String,
    password: String,
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
        password.as_str(),
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
            &kek,
            &random::get_nonce(),
            &priv_key,
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

fn gen_sym_key(password: String, profile_id: String, name: String) -> Result<(), Box<dyn Error>> {
    let salt_vec = random::get_salt();
    let profile = match user::get_profile(profile_id.as_str()).unwrap() {
        Some(p) => p,
        None => user::init_profile().unwrap(),
    };
    let params: HashMap<String, u32> = profile.params;
    let key = key_derivation::id_derive_key(
        profile.kdf_id,
        password.as_str(),
        &salt_vec,
        SYM_KEY_LEN,
        &params,
    );
    let key_to_store = key_storage::SymKey {
        id: name,
        salt: salt_vec,
        derivation_method_id: profile.kdf_id,
        derivation_params: params.clone(),
        verification_hash: hash(&key),
        created: utils::now_as_u64(),
        use_count: 0,
    };

    key_storage::store_key(&key_to_store).expect("Failed to store key");
    Ok(())
}

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
                            derive_key_from_stored(&mut sym_key, &password)
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
                    let ciphertext =
                        symmetric_encryption::id_encrypt(aead_id, key_ref, &nonce, &plaintext)
                            .unwrap();

                    let mut f = File::create(&out_path).expect("Failed to create output file");

                    // === Header: MAGIC | KDF_ID | AEAD_ID | SALT_LEN | SALT | KDF PARAMS | FILENAME_LEN
                    f.write_all(b"ENC1").unwrap();
                    f.write_all(&[kdf_id, aead_id]).unwrap();
                    f.write_all(&(salt.len() as u32).to_be_bytes()).unwrap();
                    f.write_all(salt).unwrap();

                    match kdf_id {
                        ARGON2_ID => {
                            f.write_all(&params["memory_cost"].to_be_bytes()).unwrap();
                            f.write_all(&params["time_cost"].to_be_bytes()).unwrap();
                            f.write_all(&params["parallelism"].to_be_bytes()).unwrap();
                        }
                        PBKDF2_ID => {
                            f.write_all(&params["iterations"].to_be_bytes()).unwrap();
                        }
                        _ => panic!("Unknown KDF"),
                    }

                    f.write_all(&filename_len.to_be_bytes()).unwrap();
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
                    match kdf_id {
                        ARGON2_ID => {
                            let mut buf = [0u8; 4];
                            f.read_exact(&mut buf).expect("Failed to read memory_cost");
                            params.insert("memory_cost".to_string(), u32::from_be_bytes(buf));

                            f.read_exact(&mut buf).expect("Failed to read time_cost");
                            params.insert("time_cost".to_string(), u32::from_be_bytes(buf));

                            f.read_exact(&mut buf).expect("Failed to read parallelism");
                            params.insert("parallelism".to_string(), u32::from_be_bytes(buf));
                        }
                        PBKDF2_ID => {
                            let mut buf = [0u8; 4];
                            f.read_exact(&mut buf).expect("Failed to read iterations");
                            params.insert("iterations".to_string(), u32::from_be_bytes(buf));
                        }
                        _ => panic!("Unknown KDF ID: {}", kdf_id),
                    }

                    let mut filename_len_buf = [0u8; 2];
                    f.read_exact(&mut filename_len_buf)
                        .expect("Failed to read filename length");
                    let filename_len = u16::from_be_bytes(filename_len_buf) as usize;

                    let mut ciphertext = Vec::new();
                    f.read_to_end(&mut ciphertext)
                        .expect("Failed to read ciphertext");

                    let password = get_password(false).expect("Failed to get password");
                    let key = key_derivation::id_derive_key(
                        kdf_id,
                        &password,
                        &salt,
                        SYM_KEY_LEN,
                        &params,
                    );

                    let plaintext_with_filename =
                        symmetric_encryption::id_decrypt(aead_id, &key, &ciphertext)
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
                        &kek_password,
                        &keypair.kek_salt,
                        SYM_KEY_LEN,
                        &keypair.kek_params,
                    );

                    // === Decrypt the stored private key ===
                    let decrypted_priv_key = symmetric_encryption::id_decrypt(
                        keypair.kek_aead,
                        &kek,
                        &keypair.private_key,
                    )
                    .expect("Failed to decrypt private key");

                    // === Proceed with asymmetric decryption ===
                    let plaintext_with_filename = asymmetric_crypto::id_asym_dec(
                        alg_id,
                        &decrypted_priv_key,
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
        cli::Command::Wipe => {
            print!("Are you sure you want to wipe all data? This action cannot be undone. [y/N]: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();

            if input.trim().eq_ignore_ascii_case("y") {
                user::wipe_profiles().unwrap();
                key_storage::wipe_keystore().unwrap();
                println!("All data wiped successfully.");
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
    }
}
