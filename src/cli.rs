use crate::constants::*;
use crate::user::*;
use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::path::Path;
use std::str::FromStr;

// Validation checks
fn validate_path(path_str: &str) -> Result<(), Box<dyn Error>> {
    let path = Path::new(path_str);
    if path.exists() {
        Ok(())
    } else {
        Err(format!("Path does not exist: {}", path_str).into())
    }
}

fn valid_kdf(kdf: &String) -> Result<(), Box<dyn Error>> {
    if !KDF_NAMES.contains(&kdf.to_lowercase().as_str()) {
        return Err(format!("Did not recognize KDF: {}", kdf).into());
    }
    Ok(())
}

fn valid_aead(aead: &String) -> Result<(), Box<dyn Error>> {
    if !AEAD_NAMES.contains(&aead.to_lowercase().as_str()) {
        return Err(format!("Did not recognize aead: {}", aead).into());
    }
    Ok(())
}

#[derive(Parser)]
#[command(
    name = "cipher",
    version,
    about = "Simple and modern command line cryptography."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
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
}

#[derive(Args, Clone)]
pub struct EncryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,

    #[arg(short = 'k', long = "kdf")]
    pub kdf: Option<String>,

    #[arg(short = 'm', long = "mem-cost")]
    pub memory_cost: Option<u32>,

    #[arg(short = 't', long = "time-cost")]
    pub time_cost: Option<u32>,

    #[arg(short = 'p', long = "parallelism")]
    pub parallelism: Option<u32>,

    #[arg(short = 'i', long = "iters")]
    pub iterations: Option<u32>,

    #[arg(short = 'a', long = "aead")]
    pub aead: Option<String>,

    #[arg(long = "key")]
    pub input_key: Option<u32>,

    // if you want the output copied to clipboard
    #[arg(long = "to-clipboard", default_value_t = false)]
    pub to_clipboard: bool,

    // if you want the input pasted from clipboard
    #[arg(long = "from-clipboard", default_value_t = false)]
    pub from_clipboard: bool,
}

impl EncryptArgs {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        match &self.input {
            Some(path) => {
                validate_path(path)?;
            }
            None => {
                if !self.from_clipboard {
                    return Err("No input file found.".into());
                }
            }
        }
        match &self.kdf {
            Some(s) => valid_kdf(s)?,
            None => {}
        }
        match &self.aead {
            Some(s) => valid_aead(s)?,
            None => {}
        }
        if self.from_clipboard && self.input.is_some() {
            return Err("Cannot have multiple sources of input.".into());
        }

        Ok(())
    }
}

#[derive(Args)]
pub struct DecryptArgs {
    pub input: Option<String>,
    pub output: Option<String>,

    // if you want the output copied to clipboard
    #[arg(long = "to-clipboard", default_value_t = false)]
    pub to_clipboard: bool,

    // if you want the input pasted from clipboard
    #[arg(long = "from-clipboard", default_value_t = false)]
    pub from_clipboard: bool,
}

impl DecryptArgs {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        match &self.input {
            Some(path) => {
                validate_path(path)?;
            }
            None => {
                if !self.from_clipboard {
                    return Err("No input file found.".into());
                }
            }
        }
        if self.from_clipboard && self.input.is_some() {
            return Err("Cannot have multiple sources of input.".into());
        }

        Ok(())
    }
}

#[derive(Args)]
pub struct ProfileArgs {
    pub update_field: String,
    pub value: String,
    pub profile: Option<String>,
}

impl ProfileArgs {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        let id = self
            .profile
            .clone()
            .unwrap_or_else(|| "Default".to_string());

        let profile = match get_profile(&id)? {
            Some(p) => p,
            None => get_new_profile(id.clone()),
        };

        match self.update_field.as_str() {
            "memory_cost" => {
                let value = self
                    .value
                    .parse::<u32>()
                    .map_err(|_| "Invalid memory_cost value")?;
                let min = 8 * profile.parallelism;
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
