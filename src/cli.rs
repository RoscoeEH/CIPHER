use crate::constants::*;
use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::path::Path;

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
    // TODO: invalidate commands for irelevant parameters
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
    // TODO: invalidate commands for irelevant parameters
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
