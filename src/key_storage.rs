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

/// Represents an asymmetric key pair used in cryptographic operations.
///
/// This structure holds both the public and private keys, along with metadata
/// such as an identifier, key type, and creation timestamp.
///
/// Fields:
/// - `id`: A unique identifier for the key pair.
/// - `key_type`: An unsigned integer indicating the type of the key (e.g., RSA, ECC).
/// - `public_key`: The public portion of the key pair, used for encryption or signature verification.
/// - `private_key`: The private portion of the key pair, used for decryption or signing. Should be handled securely.
/// - `created`: A UNIX timestamp indicating when the key pair was generated.
///
/// This struct derives `Serialize`, `Deserialize`, and `Debug` for convenient
/// serialization and debugging support. Ensure the `private_key` is protected
/// when serialized or logged.
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

/// Represents an symmetric key pair used in cryptographic operations.
///
/// This structure holds the salt so the key can be re-derived, along with metadata
/// such as an identifier, the derivation algorithm used, hash of the key, creation timestamp, and number of times it has been used.
///
/// Fields:
/// - `id`: A unique identifier for the key.
/// - `salt`: The salt used in generating the key.
/// - `derivation_method_id`: The KDF algorithm used to derive the key.
/// - `verification_hash`: A hash of the resulting key for verifying correctness.
/// - `created`: A UNIX timestamp indicating when the key pair was generated.
/// = `use_count`: A count of the number of things the key has been used to avoid nonce collisions.
///
/// This struct derives `Serialize`, `Deserialize`, and `Debug` for convenient
/// serialization and debugging support.
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
                    "- ID: {}\n  Type: Asymmetric (type ID {})\n  Created: {}\n  Public Key Length: {}\n",
                    asym.id,
                    asym.key_type,
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
