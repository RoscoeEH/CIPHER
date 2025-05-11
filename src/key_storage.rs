// key_storage.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Provides logic for serializing, storing, retrieving, and managing
// symmetric and asymmetric keys in a RocksDB-backed keystore.

use crate::utils::*;
use bincode;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use rocksdb::{Options, DB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Mutex;

// Enables storage of the keys within the application instead of where you run the program
fn get_keystore_path() -> PathBuf {
    let base_dir = if cfg!(debug_assertions) {
        // Dev path
        PathBuf::from("./keystore")
    } else {
        // Production path
        let project_dirs = ProjectDirs::from("com", "cipher", "cipher")
            .expect("Could not determine project directories");
        project_dirs.data_local_dir().join("keystore")
    };

    std::fs::create_dir_all(&base_dir).expect("Failed to create keystore directory");
    base_dir
}

// Rocksdb database for storing keys
lazy_static! {
    static ref KEY_STORE: Mutex<DB> = {
        let path = get_keystore_path();
        Mutex::new(DB::open_default(path).unwrap())
    };
}

// Allows for simplifictaion of storing function
pub trait HasId {
    fn id(&self) -> &str;
}

/// Represents an asymmetric key pair along with metadata and encryption context.
///
/// This struct stores a public/private keypair, where the private key is intended to be
/// stored in encrypted form using a key-encryption key (KEK) derived from a user secret.
///
/// # Fields
///
/// * `id` - A unique identifier for the key pair.
/// * `key_type` - The type of asymmetric key (e.g., `RSA_ID`, `ECC_ID`).
/// * `public_key` - The public key bytes, typically in DER or SEC1 format.
/// * `private_key` - The encrypted private key bytes (encrypted with KEK).
/// * `kek_salt` - Salt used for deriving the KEK from a password.
/// * `kek_kdf` - Identifier for the key derivation function (e.g., `ARGON2_ID`, `PBKDF2_ID`).
/// * `kek_params` - Parameters used for KEK derivation (e.g., memory cost, iterations).
/// * `kek_aead` - Identifier for the AEAD algorithm used to encrypt the private key.
/// * `created` - UNIX timestamp (in seconds) marking when the key pair was created.
#[derive(Serialize, Deserialize, Debug)]
pub struct AsymKeyPair {
    pub id: String,
    pub key_type: u8,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // Store encrypted
    pub kek_salt: Vec<u8>,
    pub kek_kdf: u8,
    pub kek_params: HashMap<String, u32>,
    pub kek_aead: u8,
    pub created: u64,
}

impl HasId for AsymKeyPair {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Represents a symmetric key configuration derived from a password or secret.
///
/// This struct stores metadata necessary to re-derive the symmetric key, verify it,
/// and track its usage over time.
///
/// # Fields
///
/// * `id` - A unique identifier for the symmetric key.
/// * `salt` - Salt used in the key derivation process.
/// * `derivation_method_id` - Identifier for the key derivation algorithm (e.g., `ARGON2_ID`, `PBKDF2_ID`).
/// * `derivation_params` - Parameters specific to the KDF (e.g., iterations, memory cost).
/// * `verification_hash` - A truncated or full hash used to verify correctness of derived keys.
/// * `created` - UNIX timestamp indicating when the key configuration was created.
/// * `use_count` - Number of times the key has been used for encryption or decryption.
#[derive(Serialize, Deserialize, Debug)]
pub struct SymKey {
    pub id: String,
    pub salt: Vec<u8>,
    pub derivation_method_id: u8,
    pub derivation_params: HashMap<String, u32>,
    pub verification_hash: Vec<u8>,
    pub created: u64,
    pub use_count: u32,
}
impl HasId for SymKey {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Serializes and stores a key object in the key store.
///
/// This function takes key objects, serializes it using `bincode`,
/// and stores it in a global key store using its identifier as the key.
///
/// # Arguments
/// - `key`: A reference to the object to be stored.
///
/// # Returns
/// - `Ok(())` if the key was successfully serialized and stored.
/// - `Err(Box<dyn std::error::Error>)` if serialization or database insertion fails.
///
/// # Errors
/// This function returns an error if:
/// - Serialization using `bincode` fails.
/// - The key store (`KEY_STORE`) fails to insert the serialized data.
///
/// # Panics
/// - This function will panic if locking the global `KEY_STORE` mutex fails.
pub fn store_key<T: Serialize + HasId>(key: &T) -> Result<(), Box<dyn std::error::Error>> {
    let serialized =
        bincode::serialize(key).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    let id = key.id();

    let db = KEY_STORE.lock().unwrap();
    db.put(id, serialized)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(())
}

/// Retrieves and deserializes a key object from the key store by ID.
///
/// This function looks up a key by its identifier, deserializes it using `bincode`,
/// and returns it if found.
///
/// # Arguments
/// - `id`: The identifier of the key to retrieve.
///
/// # Returns
/// - `Ok(Some(T))` if the key is found and successfully deserialized.
/// - `Ok(None)` if no key with the given ID exists.
/// - `Err(Box<dyn std::error::Error>)` if deserialization or database access fails.
///
/// # Errors
/// This function returns an error if:
/// - Deserialization using `bincode` fails.
/// - The key store (`KEY_STORE`) fails to retrieve the data.
///
/// # Panics
/// This function will panic if locking the global `KEY_STORE` mutex fails.
pub fn get_key<T: DeserializeOwned>(id: &str) -> Result<Option<T>, Box<dyn std::error::Error>> {
    let db = KEY_STORE.lock().unwrap();
    match db.get(id) {
        Ok(Some(serialized)) => match bincode::deserialize::<T>(&serialized) {
            Ok(deserialized) => Ok(Some(deserialized)),
            Err(e) => Err(Box::new(e)),
        },
        Ok(None) => Ok(None),
        Err(e) => Err(Box::new(e)),
    }
}

/// Lists all stored keys from the key store.
///
/// This function iterates through all entries in the global `KEY_STORE`, attempts to
/// deserialize each value as either an `AsymKeyPair` or `SymKey`, and prints human-readable
/// metadata for each recognized key.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err` if any key retrieval or deserialization operation fails.
///
/// # Output
/// Prints:
/// - Key ID
/// - Key type (asymmetric with algorithm name or symmetric with KDF ID)
/// - Creation timestamp
/// - Additional metadata like public key length or use count.
///
/// # Errors
/// Returns an error if:
/// - Iteration over the key store fails.
/// - A value in the key store cannot be read.
pub fn list_keys() -> Result<(), Box<dyn Error>> {
    let db = KEY_STORE.lock().unwrap();
    let iter = db.iterator(rocksdb::IteratorMode::Start);

    println!("Stored Keys:");
    for result in iter {
        let (_key, value) = result?;

        // Try to deserialize as AsymKeyPair
        if let Ok(asym) = bincode::deserialize::<AsymKeyPair>(&value) {
            let datetime = u64_to_datetime(asym.created);
            println!(
                "- ID: {}\n  Type: {}\n  Created: {}\n  Public Key Length: {}\n",
                asym.id,
                alg_id_to_name(asym.key_type),
                datetime,
                asym.public_key.len(),
            );
            continue;
        }

        // Try to deserialize as SymKey
        if let Ok(sym) = bincode::deserialize::<SymKey>(&value) {
            let datetime = u64_to_datetime(sym.created);
            println!(
                "- ID: {}\n  Type: Symmetric (KDF ID {})\n  Created: {}\n  Use Count: {}\n",
                sym.id, sym.derivation_method_id, datetime, sym.use_count,
            );
            continue;
        }

        println!("- Warning: Unknown key format encountered.");
    }

    Ok(())
}

/// Wipes all data from the key store by deleting and recreating the underlying database.
///
/// This function permanently deletes the RocksDB instance at the configured key store path,
/// removing all stored keys. It then reinitializes the database to ensure it's ready for reuse.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err` if the database cannot be destroyed or recreated.
///
/// # Side Effects
/// - Permanently deletes all keys.
/// - Reinitializes an empty key store at the same location.
///
/// # Errors
/// Returns an error if:
/// - The key store cannot be destroyed (e.g., path permissions issues (may implement this)).
/// - The key store cannot be recreated.
pub fn wipe_keystore() -> Result<(), Box<dyn Error>> {
    let keystore_path = get_keystore_path();

    // Delete the existing keystore database
    DB::destroy(&Options::default(), &keystore_path)?;

    // Recreate the database to ensure it exists for future use
    DB::open_default(&keystore_path)?;

    Ok(())
}

/// Deletes a single key by its ID from the keystore.
///
/// # Arguments
/// * `id` – the identifier of the key to remove
///
/// # Returns
/// * `Ok(())` if the delete succeeded (even if the key didn't exist)
/// * `Err(_)` if the underlying RocksDB delete failed
pub fn delete_key(id: &str) -> Result<(), Box<dyn Error>> {
    let db = KEY_STORE.lock().unwrap();
    db.delete(id.as_bytes())
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    Ok(())
}
