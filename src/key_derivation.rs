use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroize;

use crate::constants::*;

fn argon2_derive_key(
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    mem_cost: Option<u32>,
    t_cost: Option<u32>,
    par: Option<u32>,
) -> Secret<Vec<u8>> {
    // Default values
    let memory_cost = match mem_cost {
        Some(n) => n,
        None => 256 * 1024,
    };
    let time_cost = match t_cost {
        Some(n) => n,
        None => 8,
    };
    let parallelism = match par {
        Some(n) => n,
        None => 4,
    };

    let params = Params::new(memory_cost, time_cost, parallelism, Some(dklen))
        .expect("Invalid Argon2 parameters");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; dklen];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .expect("Argon2 hashing failed");

    let secret_key = Secret::new(key.clone());
    key.zeroize();
    secret_key
}

fn pbkdf2_derive_key(
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    iters: Option<u32>,
) -> Secret<Vec<u8>> {
    let iterations = match iters {
        Some(n) => n,
        None => 100_000,
    };

    let mut key = vec![0u8; dklen];
    pbkdf2_hmac::<Sha256>(
        password.expose_secret().as_bytes(),
        salt,
        iterations,
        &mut key,
    );

    let secret_key = Secret::new(key.clone());
    key.zeroize();

    secret_key
}

pub fn id_derive_key(
    alg_id: u8,
    password: Secret<String>,
    salt: &[u8],
    dklen: usize,
    params: &HashMap<String, u32>,
) -> Secret<Vec<u8>> {
    match alg_id {
        ARGON2_ID => argon2_derive_key(
            password,
            salt,
            dklen,
            params.get("memory_cost").copied(),
            params.get("time_cost").copied(),
            params.get("parallelism").copied(),
        ),
        PBKDF2_ID => pbkdf2_derive_key(password, salt, dklen, params.get("iterations").copied()),
        _ => panic!(
            "Attempted key derivation with unknown algorithm ID: {}",
            alg_id
        ),
    }
}
