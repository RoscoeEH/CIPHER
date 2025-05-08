use rand::rngs::OsRng;
use rand::RngCore;

pub fn get_random_val(length: usize) -> Vec<u8> {
    let mut val = vec![0u8; length];
    OsRng.fill_bytes(&mut val);
    val
}

pub fn get_nonce() -> Vec<u8> {
    get_random_val(12)
}

pub fn get_salt() -> Vec<u8> {
    get_random_val(16)
}
