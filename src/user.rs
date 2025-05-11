use crate::constants::*;
use crate::utils::alg_id_to_name;
use bincode;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Mutex;

// Enables storage of profiles in the application
fn get_db_path() -> PathBuf {
    let db_dir = if cfg!(debug_assertions) {
        // Dev path
        PathBuf::from("./profiles")
    } else {
        // Production path
        let project_dirs = ProjectDirs::from("com", "cipher", "cipher")
            .expect("Could not determine project directories");
        project_dirs.data_local_dir().join("profiles")
    };

    std::fs::create_dir_all(&db_dir).expect("Failed to create DB directory");
    db_dir
}

// RocksDB database for storing profiles
lazy_static! {
    static ref PROFILES_DB: Mutex<DB> = {
        let path = get_db_path();
        Mutex::new(DB::open_default(path).unwrap())
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
/// Serializes the provided profile and saves it to the key-value store under its `id`.
/// This allows the profile to be retrieved later for cryptographic operations.
///
/// # Arguments
/// - `profile`: A reference to the `UserProfile` to store.
///
/// # Errors
/// Returns an error if serialization fails or if the database operation encounters an issue.
pub fn set_profile(profile: &UserProfile) -> Result<(), Box<dyn std::error::Error>> {
    let db = PROFILES_DB.lock().unwrap();

    let serialized = bincode::serialize(profile)?;
    db.put(profile.id.as_bytes(), serialized)?;
    Ok(())
}

/// Retrieves a `UserProfile` by its ID from the profiles database.
///
/// Attempts to fetch and deserialize the profile associated with the given ID from the
/// key-value store. If no profile is found, returns `Ok(None)`.
///
/// # Arguments
/// - `id`: The ID of the profile to retrieve.
///
/// # Returns
/// - `Ok(Some(UserProfile))` if the profile exists and is successfully deserialized.
/// - `Ok(None)` if no profile is found with the given ID.
/// - An error if the database read or deserialization fails.
pub fn get_profile(id: &str) -> Result<Option<UserProfile>, Box<dyn std::error::Error>> {
    let db = PROFILES_DB.lock().unwrap();

    if let Some(data) = db.get(id.as_bytes())? {
        let profile: UserProfile = bincode::deserialize(&data)?;
        Ok(Some(profile))
    } else {
        Ok(None)
    }
}

/// Initializes and returns the default `UserProfile`.
///
/// Checks if a profile with the ID `"Default"` exists in the profile store. If it does,
/// the existing profile is returned. If not, a new default profile is created with
/// sensible cryptographic defaults and stored in the database.
///
/// The default profile uses:
/// - `CHA_CHA_20_POLY_1305_ID` for AEAD
/// - `ARGON2_ID` for key derivation
/// - Standard parameters for both Argon2 and PBKDF2 to ensure compatibility
///
/// # Returns
/// - `Ok(UserProfile)` containing the default or newly created profile.
/// - An error if reading or writing the profile fails.
pub fn init_profile() -> Result<UserProfile, Box<dyn std::error::Error>> {
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
/// Loads the default profile using `init_profile`, assigns it the provided `new_id`,
/// and stores the new profile in the profile store.
///
/// # Arguments
/// * `new_id` - The unique identifier for the new profile.
///
/// # Returns
/// * `UserProfile` with the updated ID.
///
/// # Panics
/// Panics if the default profile cannot be initialized or if storing the new profile fails.
pub fn get_new_profile(new_id: String) -> UserProfile {
    let mut base_profile = init_profile().unwrap();
    base_profile.id = new_id;
    set_profile(&base_profile).expect("Failed to save profile");
    base_profile
}

/// Lists all stored user profiles from the profile database.
///
/// Iterates through all entries in the profile store, deserializes each `UserProfile`,
/// and prints a summary including ID, AEAD algorithm, KDF, and key derivation parameters.
///
/// # Returns
/// * `Ok(())` if listing succeeds.
/// * `Err` if there is a database or deserialization error.
pub fn list_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let db = PROFILES_DB.lock().unwrap();

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
/// This function destroys the existing database at the profile storage path,
/// removing all data. It then recreates an empty database to ensure
/// the system remains in a usable state.
///
/// # Returns
/// * `Ok(())` on successful wipe and reinitialization.
/// * `Err` if there is an error destroying or reopening the database.
pub fn wipe_profiles() -> Result<(), Box<dyn Error>> {
    let db_path = get_db_path();

    DB::destroy(&Options::default(), &db_path)?;
    DB::open_default(&db_path)?;

    Ok(())
}
