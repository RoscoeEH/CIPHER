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

use std::error::Error;

pub mod asymmetric_crypto;
pub mod cli;
pub mod constants;
pub mod key_derivation;
pub mod key_storage;
pub mod operations;
pub mod random;
pub mod symmetric_encryption;
pub mod user;
pub mod utils;

use clap::Parser;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = cli::Cli::parse();

    match cli.command {
        // Handles all symmetric and asymmetric encryption; also can sign encrypted blobs
        cli::Command::Encrypt(args) => {
            cli::validate_args(&args)?;
            operations::encrypt_op(args)?
        }

        cli::Command::Decrypt(args) => {
            cli::validate_args(&args)?;
            operations::decrypt_op(args)?;
        }
        // Handles changed to default parameters
        cli::Command::Profile(args) => {
            cli::validate_args(&args)?;
            operations::update_profile_op(args)?;
        }

        cli::Command::ListProfiles => {
            user::init_profile()?;
            user::list_profiles()?;
        }

        cli::Command::KeyGen(args) => {
            cli::validate_args(&args)?;
            operations::key_gen_op(args)?;
        }
        cli::Command::ListKeys(args) => {
            operations::list_keys_op(args)?;
        }
        // Erases option to erase all keys and data
        cli::Command::Wipe(args) => {
            operations::wipe_op(args)?;
        }

        cli::Command::DeleteKey(args) => {
            operations::delete_keys_op(args)?;
        }

        // signs any data and creates a .sig file
        cli::Command::Sign(args) => {
            cli::validate_args(&args)?;
            operations::sign_op(args)?;
        }
        // Verify .sig files and optionally strip the sig data
        cli::Command::Verify(args) => {
            cli::validate_args(&args)?;
            operations::verify_op(args)?;
        }
        // Creates a .pub of one of your keypairs that others can import
        cli::Command::ExportKey(args) => {
            operations::export_key_op(args)?;
        }

        // Reads in .pub files into your key store
        cli::Command::ImportKey(args) => {
            cli::validate_args(&args)?;
            operations::import_key_op(args)?;
        }
    }
    Ok(())
}
