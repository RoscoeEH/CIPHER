use crate::constants::*;
use crate::utils::alg_id_to_name;
use bincode;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

// This function returns the *full path* to the RocksDB directory
fn get_db_path() -> PathBuf {
    let project_dirs = ProjectDirs::from("com", "cipher", "cipher")
        .expect("Could not determine project directories");

    let db_dir = project_dirs.data_local_dir().join("db");

    std::fs::create_dir_all(&db_dir).expect("Failed to create DB directory");

    db_dir
}

// Only initialize DB *after* we have the correct path
lazy_static! {
    static ref PROFILES_DB: Mutex<DB> = {
        let path = get_db_path();
        Mutex::new(DB::open_default(path).unwrap())
    };
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub id: String,
    pub aead_alg_id: u8,
    pub kdf_id: u8,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub iterations: u32,
}

pub fn set_profile(profile: &UserProfile) -> Result<(), Box<dyn std::error::Error>> {
    let db = PROFILES_DB.lock().unwrap();

    let serialized = bincode::serialize(profile)?;
    db.put(profile.id.as_bytes(), serialized)?;
    Ok(())
}

pub fn get_profile(id: &str) -> Result<Option<UserProfile>, Box<dyn std::error::Error>> {
    let db = PROFILES_DB.lock().unwrap();

    if let Some(data) = db.get(id.as_bytes())? {
        let profile: UserProfile = bincode::deserialize(&data)?;
        Ok(Some(profile))
    } else {
        Ok(None)
    }
}

pub fn init_profile() -> Result<UserProfile, Box<dyn std::error::Error>> {
    let default_id = "Default";

    if let Some(profile) = get_profile(default_id)? {
        Ok(profile)
    } else {
        let default_profile = UserProfile {
            id: default_id.to_string(),
            aead_alg_id: CHA_CHA_20_POLY_1305_ID,
            kdf_id: ARGON2_ID,
            memory_cost: 256 * 10244,
            time_cost: 8,
            parallelism: 4,
            iterations: 600_000,
        };

        set_profile(&default_profile)?;
        Ok(default_profile)
    }
}

pub fn get_new_profile(new_id: String) -> UserProfile {
    let mut base_profile = init_profile().unwrap();
    base_profile.id = new_id;
    set_profile(&base_profile).expect("Failed to save profile");
    base_profile
}

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
            profile.memory_cost,
            profile.time_cost,
            profile.parallelism,
            profile.iterations,
        );
    }

    Ok(())
}
