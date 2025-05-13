// cli.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Defines and handles the command-line interface, including parsing commands,
// validating arguments, and routing user input to the appropriate functions.

use crate::constants::*;
use crate::user::*;
use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::path::Path;

// === Validation checks ===

/// Validates that a given file system path exists.
///
/// This function checks whether the path represented by the input string exists
/// in the file system. It returns an error if the path is not found.
///
/// # Arguments
///
/// * `path_str` - A string slice representing the file system path to validate.
///
/// # Returns
///
/// * `Ok(())` - If the path exists.
/// * `Err(Box<dyn Error>)` - If the path does not exist.
///
/// # Errors
///
/// Returns an error with a message indicating the path was not found if `path_str`
/// does not correspond to an existing file or directory.
fn validate_path(path_str: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(path_str);
    if path.exists() {
        Ok(())
    } else {
        Err(format!("Path does not exist: {}", path_str).into())
    }
}

/// Validates that the provided key derivation function (KDF) name is supported.
///
/// This function checks whether the given KDF name exists in the predefined list
/// of supported KDF algorithms (`KDF_NAMES`). The comparison is case-insensitive.
///
/// # Arguments
///
/// * `kdf` - A reference to a `String` representing the name of the KDF algorithm.
///
/// # Returns
///
/// * `Ok(())` - If the KDF name is recognized.
/// * `Err(Box<dyn Error>)` - If the KDF name is not supported.
///
/// # Errors
///
/// Returns an error with a message if the provided KDF name is not in `KDF_NAMES`.
fn valid_kdf(kdf: &String) -> Result<(), Box<dyn Error>> {
    if !KDF_NAMES.contains(&kdf.to_lowercase().as_str()) {
        return Err(format!("Did not recognize KDF: {}", kdf).into());
    }
    Ok(())
}

/// Validates that the provided AEAD (Authenticated Encryption with Associated Data) algorithm name is supported.
///
/// This function checks whether the given AEAD algorithm name exists in the predefined list
/// of supported AEAD algorithms (`AEAD_NAMES`). The check is case-insensitive.
///
/// # Arguments
///
/// * `aead` - A reference to a `String` representing the AEAD algorithm name.
///
/// # Returns
///
/// * `Ok(())` - If the AEAD name is recognized.
/// * `Err(Box<dyn Error>)` - If the AEAD name is not supported.
///
/// # Errors
///
/// Returns an error with a message if the provided AEAD name is not in `AEAD_NAMES`.
fn valid_aead(aead: &String) -> Result<(), Box<dyn Error>> {
    if !AEAD_NAMES.contains(&aead.to_lowercase().as_str()) {
        return Err(format!("Did not recognize aead: {}", aead).into());
    }
    Ok(())
}

/// Validates that the provided asymmetric algorithm name is supported.
///
/// This function checks whether the given asymmetric algorithm name exists in the predefined
/// list of supported algorithms (`ASYM_NAMES`). The comparison is case-insensitive.
///
/// # Arguments
///
/// * `asym` - A reference to a `String` representing the asymmetric algorithm name.
///
/// # Returns
///
/// * `Ok(())` - If the asymmetric algorithm name is recognized.
/// * `Err(Box<dyn Error>)` - If the name is not supported.
///
/// # Errors
///
/// Returns an error with a message if the provided name is not in `ASYM_NAMES`.
fn valid_asym(asym: &String) -> Result<(), Box<dyn Error>> {
    if !ASYM_NAMES.contains(&asym.to_lowercase().as_str()) {
        return Err(format!("Did not recognize asym: {}", asym).into());
    }
    Ok(())
}

// Supports validate_args
pub trait Validatable {
    fn validate(&self) -> Result<(), Box<dyn Error>>;
}

/// Validates command-line arguments by calling the `validate` method on a `Validatable` type.
///
/// This function is intended to be used in CLI applications. It calls the `validate`
/// method on the given arguments object. If validation fails, it prints an error message
/// to stderr (including the source of the error, if available) and exits the process with code 1.
///
/// # Type Parameters
///
/// * `T` - A type that implements the `Validatable` trait.
///
/// # Arguments
///
/// * `args` - A reference to a struct implementing `Validatable`, representing parsed CLI arguments.
///
/// # Behavior
///
/// * Prints an error and exits the program if validation fails.
/// * Continues execution silently if validation succeeds.
pub fn validate_args<T: Validatable>(args: &T) {
    if let Err(e) = args.validate() {
        eprintln!("Invalid input: {}", e);
        if let Some(source) = e.source() {
            eprintln!("Caused by: {}", source);
        }
        std::process::exit(1);
    }
}

// Command-line interface definition for the `cipher` application.
#[derive(Parser)]
#[command(
    name = "cipher",
    version,
    about = "Simple and modern command line cryptography."
)]
/// The top-level command to execute.
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Enum representing all supported subcommands for the `cipher` CLI.
///
/// Each variant corresponds to a specific operation, such as encryption,
/// decryption, key management, or profile manipulation.
#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a file with advanced options
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted file
    Decrypt(DecryptArgs),

    /// Change profile preference
    Profile(ProfileArgs),

    /// List all existing profiles
    #[clap(name = "list-profiles")]
    ListProfiles,

    KeyGen(KeyGenArgs),

    /// List all existing profiles
    #[clap(name = "list-keys")]
    ListKeys(ListKeyArgs),

    /// Clear all existing keys and profiles
    Wipe(WipeArgs),

    /// Delete a singluar key
    #[clap(name = "delete-key")]
    DeleteKey(DeleteKeyArgs),

    Sign(SignArgs),

    Verify(VerifyArgs),

    #[clap(name = "export")]
    ExportKey(ExportKeyArgs),

    #[clap(name = "import")]
    ImportKey(ImportKeyArgs),
}

// Handles encyption command
#[derive(Args, Clone)]
pub struct EncryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,

    #[arg(short = 'p', long = "profile", default_value_t = String::from("Default"))]
    pub profile: String,

    #[arg(long = "kdf")]
    pub kdf: Option<String>,

    #[arg(long = "mem-cost")]
    pub memory_cost: Option<u32>,

    #[arg(long = "time-cost")]
    pub time_cost: Option<u32>,

    #[arg(long = "parallelism")]
    pub parallelism: Option<u32>,

    #[arg(long = "iters")]
    pub iterations: Option<u32>,

    #[arg(long = "aead")]
    pub aead: Option<String>,

    #[arg(short = 'k', long = "key")]
    pub input_key: Option<String>,

    #[arg(short = 's', long = "sign")]
    pub sign_key: Option<String>,
}

impl Validatable for EncryptArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        match &self.input {
            Some(path) => validate_path(path)?,
            None => return Err("No input file found.".into()),
        }
        // Does not need kdf and input key
        if self.input_key.is_some() && self.kdf.is_some() {
            return Err("Cannot provide both an input key and a KDF — choose one.".into());
        }
        match &self.kdf {
            Some(s) => valid_kdf(s)?,
            None => {}
        }
        match &self.aead {
            Some(s) => valid_aead(s)?,
            None => {}
        }
        // If a profile is listed ensure it exists, otherwise make sure a default profile exists
        match get_profile(self.profile.as_str()) {
            Ok(Some(_profile)) => {}
            Ok(None) => {
                if self.profile.as_str() == "Default" {
                    init_profile()
                        .map_err(|e| format!("Failed to initialize default profile: {e}"))?;
                } else {
                    return Err(format!("Could not find profile: {}", self.profile).into());
                }
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }
}

// Handles Decyption Command
#[derive(Args)]
pub struct DecryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,
}

impl Validatable for DecryptArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        match &self.input {
            Some(path) => validate_path(path)?,
            None => return Err("No input file found.".into()),
        }
        Ok(())
    }
}

// Handles commands to update profiles
#[derive(Args)]
pub struct ProfileArgs {
    #[arg(short = 'p', long = "profile")]
    pub profile: Option<String>,
    // Profile would be better with a default
    pub update_field: String,
    pub value: String,
}

impl Validatable for ProfileArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        let id = self
            .profile
            .clone()
            .unwrap_or_else(|| "Default".to_string());

        let profile = match get_profile(&id)? {
            Some(p) => p,
            None => get_new_profile(id.clone()),
        };

        // Checks appropriate values for parameters
        match self.update_field.as_str() {
            "memory_cost" => {
                let value = self
                    .value
                    .parse::<u32>()
                    .map_err(|_| "Invalid memory_cost value")?;
                let min = 8 * profile.params.get("parallelism").unwrap();
                let max = if cfg!(target_pointer_width = "64") {
                    u32::min(u32::MAX, 4 * 1024 * 1024)
                } else {
                    u32::min(u32::MAX, 2 * 1024 * 1024)
                };

                if value < min {
                    Err(format!("memory_cost must be at least 8 × parallelism ({}).", min).into())
                } else if value > max {
                    Err(format!("memory_cost must not exceed {} KiB.", max).into())
                } else {
                    Ok(())
                }
            }

            "time_cost" => {
                let value = self
                    .value
                    .parse::<u32>()
                    .map_err(|_| "Invalid time_cost value")?;
                if value < 1 {
                    Err("time_cost must be at least 1.".into())
                } else {
                    Ok(())
                }
            }

            "parallelism" => {
                let value = self
                    .value
                    .parse::<u32>()
                    .map_err(|_| "Invalid parallelism value")?;
                if value < 1 {
                    Err("parallelism must be at least 1.".into())
                } else if value > (1 << 24) - 1 {
                    Err("parallelism must not exceed 16,777,215 (2^24 - 1).".into())
                } else {
                    Ok(())
                }
            }

            "iterations" => {
                self.value
                    .parse::<u32>()
                    .map_err(|_| "Invalid iterations value")?;
                Ok(())
            }

            "kdf_id" => {
                if KDF_NAMES.contains(&self.value.as_str()) {
                    Ok(())
                } else {
                    Err(format!("Invalid kdf_id: must be one of {:?}", KDF_NAMES).into())
                }
            }

            "aead_alg_id" => {
                if AEAD_NAMES.contains(&self.value.as_str()) {
                    Ok(())
                } else {
                    Err(format!("Invalid aead_alg_id: must be one of {:?}", AEAD_NAMES).into())
                }
            }

            "id" => Err("'id' cannot be updated.".into()),

            other => Err(format!("'{}' is not a valid field for update.", other).into()),
        }
    }
}

// Handles commands to generate new keys
#[derive(Args)]
pub struct KeyGenArgs {
    pub id: String,

    #[arg(short = 's', long = "symmetric", default_value_t = false)]
    pub symmetric: bool,

    #[arg(short = 'a', long = "asymmetric-alg")]
    pub asymmetric: Option<String>,

    // Only relevant for rsa currently
    #[arg(short = 'b', long = "bits", default_value_t = 4096)]
    pub bits: usize,

    #[arg(short = 'p', long = "profile", default_value_t = String::from("Default"))]
    pub profile: String,
}

impl Validatable for KeyGenArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        // Ensure there is a single key type
        match &self.asymmetric {
            Some(s) => {
                if self.symmetric {
                    return Err("Must specify symmetric or aymmetric key, not both.".into());
                }
                valid_asym(&s)?
            }
            None => {
                if !self.symmetric {
                    return Err("No key type found.".into());
                }
            }
        }
        // check that the number of bits is valid
        match self.bits {
            2048 | 3072 | 4096 => {}
            _ => {
                return Err(format!(
                    "Invalid number of bits: {}. Must be 2048, 3072, or 4096",
                    self.bits
                )
                .into())
            }
        }
        // If a profile is listed ensure it exists, otherwise make sure a default profile exists
        match get_profile(self.profile.as_str()) {
            Ok(Some(_profile)) => {}
            Ok(None) => {
                if self.profile.as_str() == "Default" {
                    init_profile()
                        .map_err(|e| format!("Failed to initialize default profile: {e}"))?;
                } else {
                    return Err(format!("Could not find profile: {}", self.profile).into());
                }
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }
}

#[derive(Args)]
pub struct ListKeyArgs {
    #[arg(short = 'u', long = "unowned", default_value_t = false)]
    pub unowned: bool,
}

// Allows for all profiles and keys to be wiped
#[derive(Args)]
pub struct WipeArgs {
    #[arg(short = 'k', long = "keys", default_value_t = false)]
    pub wipe_keys: bool,
    #[arg(short = 'p', long = "profiles", default_value_t = false)]
    pub wipe_profiles: bool,
    #[arg(short = 'u', long = "unowned", default_value_t = false)]
    pub wipe_unowned_keys: bool,
}

// Delete an individul key
#[derive(Args)]
pub struct DeleteKeyArgs {
    pub id: String,
    #[arg(short = 'u', long = "unowned", default_value_t = false)]
    pub unowned: bool,
}

// Handles commands to sign data
#[derive(Args)]
pub struct SignArgs {
    pub input: String,
    #[arg(short = 'k', long = "key")]
    pub key_id: String,
}
impl Validatable for SignArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        validate_path(self.input.as_str())?;
        Ok(())
    }
}

// Handles commands to verify data
#[derive(Args)]
pub struct VerifyArgs {
    pub input: String,
    #[arg(short = 'o', long = "only-verify", default_value_t = false)]
    pub only_verify: bool,
}
impl Validatable for VerifyArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        validate_path(self.input.as_str())?;
        Ok(())
    }
}

#[derive(Args)]
pub struct ExportKeyArgs {
    pub key_id: String,
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,
}

#[derive(Args)]
pub struct ImportKeyArgs {
    pub input_file: String,
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,
}
impl Validatable for ImportKeyArgs {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        validate_path(self.input_file.as_str())?;
        if !self.input_file.ends_with(".pub") {
            return Err("Input file must have a .pub extension".into());
        }
        Ok(())
    }
}
