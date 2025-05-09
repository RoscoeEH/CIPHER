use bincode;
use lazy_static::lazy_static;
use rocksdb::{IteratorMode, DB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::VecDeque;
use std::error::Error;
use std::sync::Mutex;

// Rocksdb database for storing keys
lazy_static! {
    static ref KEY_STORE: Mutex<DB> = Mutex::new(DB::open_default("./cipher_keystore").unwrap());
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
    pub private_key: Vec<u8>,
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

    match db.get(id)? {
        Some(serialized) => {
            let deserialized: T = bincode::deserialize(&serialized)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            Ok(Some(deserialized))
        }
        None => Ok(None),
    }
}

/// Retrieves and deserializes all key objects from the key store.
///
/// This function iterates over all entries in the global key store,
/// deserializes each one using `bincode`, and returns them as a list.
///
/// # Returns
/// - `Ok(Vec<T>)` containing all successfully deserialized key objects.
/// - `Err(Box<dyn std::error::Error>)` if any deserialization or database access fails.
///
/// # Errors
/// This function returns an error if:
/// - Deserialization using `bincode` fails for any entry.
/// - Iteration over the key store (`KEY_STORE`) fails.
///
/// # Panics
/// This function will panic if locking the global `KEY_STORE` mutex fails.
pub fn get_key_list<T: DeserializeOwned>() -> Result<Vec<T>, Box<dyn Error>> {
    let mut keys: VecDeque<T> = VecDeque::new();

    let db = KEY_STORE.lock().unwrap();

    let iter = db.iterator(IteratorMode::Start);

    for result in iter {
        match result {
            Ok((_, value)) => {
                let deserialized: T = bincode::deserialize(&value)?;
                keys.push_back(deserialized);
            }
            Err(e) => return Err(Box::new(e)), // Convert rocksdb::Error to Box<dyn Error>
        }
    }

    Ok(keys.into()) // Return a Vec
}
