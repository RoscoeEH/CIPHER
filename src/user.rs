// user.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Manages user profiles, including serialization and RocksDB storage.
// User profiles contain preferred encryption parameters (KDF, AEAD, and their configuration).

use bincode;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::constants::*;
use crate::utils::alg_id_to_name;

// Enables storage of profiles in the application
fn get_db_path() -> Result<PathBuf, Box<dyn Error>> {
    let db_dir = if cfg!(debug_assertions) {
        PathBuf::from("./profiles")
    } else {
        let project_dirs = ProjectDirs::from("com", "cipher", "cipher")
            .ok_or_else(|| "Could not determine project directories".to_string())?;
        project_dirs.data_local_dir().join("profiles")
    };

    std::fs::create_dir_all(&db_dir)?;
    Ok(db_dir)
}

lazy_static! {
    static ref PROFILES_DB: Mutex<DB> = {
        let path = get_db_path().expect("Failed to get DB path");
        let db = DB::open_default(path).expect("Failed to open RocksDB");
        Mutex::new(db)
    };
}

/// Represents a cryptographic user profile with preferences for encryption and key derivation.
///
/// This struct stores user-specific configuration for encryption and KDF settings,
/// allowing reusable and consistent cryptographic operations across the application.
///
/// # Fields
/// - `id`: A unique identifier for the profile.
/// - `aead_alg_id`: Identifier for the AEAD algorithm to use (e.g., AES-GCM, ChaCha20-Poly1305).
/// - `kdf_id`: Identifier for the key derivation function (e.g., Argon2, PBKDF2).
/// - `params`: A map of algorithm-specific parameters (e.g., memory, iterations, parallelism).
///
/// # Notes
/// These profiles can be used to drive encryption/decryption and key derivation
/// operations according to the user’s preferred settings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub id: String,
    pub aead_alg_id: u8,
    pub kdf_id: u8,
    pub params: HashMap<String, u32>,
}

/// Stores a `UserProfile` in the profiles database.
///
/// This function serializes the provided `UserProfile` and saves it to the
/// key-value store using the profile's `id` as the key. This enables future
/// retrieval and use of the profile for cryptographic or identity operations.
///
/// # Arguments
/// - `profile`: A reference to the `UserProfile` to store.
///
/// # Returns
/// - `Ok(())` if the profile is successfully serialized and stored.
/// - `Err(Box<dyn Error>)` if serialization or database storage fails.
///
/// # Errors
/// Returns an error if:
/// - Serialization of the `UserProfile` fails.
/// - The underlying database operation (put) fails.
pub fn set_profile(profile: &UserProfile) -> Result<(), Box<dyn Error>> {
    let db = PROFILES_DB.lock()?;

    let serialized = bincode::serialize(profile)?;
    db.put(profile.id.as_bytes(), serialized)?;
    Ok(())
}

/// Retrieves a `UserProfile` by its ID from the profiles database.
///
/// This function looks up the profile associated with the given `id` in the
/// key-value store and attempts to deserialize it. If the profile is not found,
/// it returns `Ok(None)`.
///
/// # Arguments
/// - `id`: The string identifier of the profile to retrieve.
///
/// # Returns
/// - `Ok(Some(UserProfile))` if a profile with the given ID exists and deserialization succeeds.
/// - `Ok(None)` if no profile is found for the provided ID.
/// - `Err(Box<dyn Error>)` if a database read or deserialization error occurs.
///
/// # Errors
/// Returns an error if:
/// - The database retrieval operation fails.
/// - The stored data cannot be deserialized into a `UserProfile`.
pub fn get_profile(id: &str) -> Result<Option<UserProfile>, Box<dyn Error>> {
    let db = PROFILES_DB.lock()?;

    if let Some(data) = db.get(id.as_bytes())? {
        let profile: UserProfile = bincode::deserialize(&data)?;
        Ok(Some(profile))
    } else {
        Ok(None)
    }
}

/// Initializes and returns the default `UserProfile`.
///
/// This function checks if a profile with the ID `"Default"` already exists in the
/// profile store. If found, it returns the existing profile. Otherwise, it creates
/// a new default profile with predefined cryptographic parameters and saves it.
///
/// The default profile uses:
/// - AEAD algorithm ID: `CHA_CHA_20_POLY_1305_ID`
/// - Key derivation function ID: `ARGON2_ID`
/// - Standard parameters for Argon2 and PBKDF2 to ensure compatibility and security.
///
/// # Returns
/// - `Ok(UserProfile)` containing either the existing or newly created default profile.
/// - `Err(Box<dyn Error>)` if reading from or writing to the profile store fails.
///
/// # Errors
/// Returns an error if:
/// - The attempt to read the existing default profile from the database fails.
/// - Serialization or database write operations fail when storing a new profile.
pub fn init_profile() -> Result<UserProfile, Box<dyn Error>> {
    let default_id = "Default";

    if let Some(profile) = get_profile(default_id)? {
        Ok(profile)
    } else {
        let params: HashMap<String, u32> = [
            ("memory_cost".to_string(), 256 * 1024),
            ("time_cost".to_string(), 8),
            ("parallelism".to_string(), 4),
            ("iterations".to_string(), 600_000),
        ]
        .into_iter()
        .collect();

        let default_profile = UserProfile {
            id: default_id.to_string(),
            aead_alg_id: CHA_CHA_20_POLY_1305_ID,
            kdf_id: ARGON2_ID,
            params,
        };

        set_profile(&default_profile)?;
        Ok(default_profile)
    }
}

/// Creates a new `UserProfile` by cloning the default profile with a new ID.
///
/// This function initializes the default profile using `init_profile()`, then
/// clones it by assigning the provided `new_id` to the profile's ID field. The
/// new profile is then stored in the profile store.
///
/// # Arguments
/// - `new_id`: The unique identifier for the new profile.
///
/// # Returns
/// - `Ok(UserProfile)`: The newly created profile with the updated ID.
/// - `Err(Box<dyn Error>)`: If initializing the default profile or storing the
///   new profile fails.
///
/// # Errors
/// Returns an error if:
/// - The default profile cannot be initialized.
/// - Serialization or database write operations fail when saving the new profile.
pub fn get_new_profile(new_id: String) -> Result<UserProfile, Box<dyn Error>> {
    let mut base_profile = init_profile()?;
    base_profile.id = new_id;
    set_profile(&base_profile)?;
    Ok(base_profile)
}

/// Lists all stored user profiles from the profile database.
///
/// Iterates over all entries in the profile store, deserializes each `UserProfile`,
/// and prints a summary of each profile including:
/// - ID
/// - AEAD algorithm name
/// - KDF algorithm name
/// - Key derivation parameters such as memory cost, time cost, parallelism, and iterations
///
/// # Returns
/// - `Ok(())` if all profiles are successfully listed.
/// - `Err(Box<dyn Error>)` if a database read or deserialization error occurs.
///
/// # Errors
/// Returns an error if:
/// - Accessing the RocksDB iterator fails.
/// - A profile entry fails to deserialize.
/// - Key bytes cannot be converted to UTF-8 string.
pub fn list_profiles() -> Result<(), Box<dyn Error>> {
    let db = PROFILES_DB.lock()?;

    println!("Stored user profiles:\n");

    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let (key, value) = entry?; // Result from RocksDB
        let id = String::from_utf8(key.to_vec())?;
        let profile: UserProfile = bincode::deserialize(&value)?;

        // Replace numeric IDs with names for display
        let aead_name = alg_id_to_name(profile.aead_alg_id);
        let kdf_name = alg_id_to_name(profile.kdf_id);

        // Helper to get params or fallback to 0
        let get_param = |key: &str| profile.params.get(key).copied().unwrap_or(0);

        println!(
            "ID: {}\n\
             AEAD Algorithm: {}\n\
             KDF: {}\n\
             Memory Cost: {}\n\
             Time Cost: {}\n\
             Parallelism: {}\n\
             Iterations: {}\n",
            id,
            aead_name,
            kdf_name,
            get_param("memory_cost"),
            get_param("time_cost"),
            get_param("parallelism"),
            get_param("iterations"),
        );
    }

    Ok(())
}

/// Completely removes all stored user profiles from the profile database.
///
/// This function permanently deletes the RocksDB instance located at the profile
/// database path, erasing all stored profiles. After destruction, it recreates
/// a new empty database at the same location to ensure the profile store is usable.
///
/// # Returns
/// - `Ok(())` if the database was successfully destroyed and recreated.
/// - `Err(Box<dyn Error>)` if destroying or reopening the database fails.
///
/// # Errors
/// Returns an error if:
/// - The database cannot be destroyed (e.g., due to file permission issues).
/// - The database cannot be reopened after destruction.
pub fn wipe_profiles() -> Result<(), Box<dyn Error>> {
    let db_path = get_db_path()?;

    DB::destroy(&Options::default(), &db_path)?;
    DB::open_default(&db_path)?;

    Ok(())
}
