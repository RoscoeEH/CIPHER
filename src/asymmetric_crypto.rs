use elliptic_curve::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
};

use p256::{
    ecdh::{diffie_hellman, EphemeralSecret},
    ecdsa::{
        signature::{Signer as EcdsaSigner, Verifier as EcdsaVerifier},
        Signature as EcdsaSignature, SigningKey as EcdsaSigningKey,
        VerifyingKey as EcdsaVerifyingKey,
    },
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use rand::thread_rng;
use rand_core::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::{
        Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
    },
    signature::{RandomizedSigner, SignatureEncoding},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::Zeroize;

use crate::constants::*;
use crate::random::*;
use crate::symmetric_encryption::*;

// RSA
fn rsa_key_gen(bits: usize) -> (Secret<Vec<u8>>, Vec<u8>) {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("RSA key gen failed");
    let public_key = RsaPublicKey::from(&private_key);

    let keypair = (
        Secret::new(
            private_key
                .to_pkcs1_der()
                .expect("Failed to encode private key")
                .as_bytes()
                .to_vec(),
        ),
        public_key
            .to_pkcs1_der()
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec(),
    );
    drop(private_key);
    keypair
}

fn rsa_enc(pub_key: &[u8], data: &[u8]) -> Vec<u8> {
    let public_key = RsaPublicKey::from_pkcs1_der(pub_key).expect("Failed to parse DER public key");

    public_key
        .encrypt(&mut thread_rng(), Pkcs1v15Encrypt, data)
        .expect("RSA encryption failed")
}

fn rsa_dec(priv_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let private_key =
        RsaPrivateKey::from_pkcs1_der(priv_key).expect("Failed to parse DER private key");

    private_key
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .expect("RSA decryption failed")
}

fn rsa_sign(priv_key: &[u8], data: &[u8]) -> Vec<u8> {
    let private_key =
        RsaPrivateKey::from_pkcs1_der(priv_key).expect("Failed to parse DER private key");

    // Create a PKCS#1 v1.5 signing key
    let signing_key = RsaSigningKey::<sha2::Sha256>::new(private_key.clone());

    let mut rng = thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, data);

    signature.to_vec()
}

fn rsa_verify(pub_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), rsa::signature::Error> {
    let public_key = RsaPublicKey::from_pkcs1_der(pub_key).expect("Failed to parse DER public key");
    let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key.clone());
    let sig = RsaSignature::try_from(signature)?;

    // Returns Err(_) if the signature is invalid
    verifying_key.verify(data, &sig)
}

// ECC

fn ecc_key_gen() -> (Secret<Vec<u8>>, Vec<u8>) {
    // Generate a secret key
    let secret = P256SecretKey::random(&mut OsRng);

    // Derive public key from secret
    let public = P256PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

    // Serialize keys
    let private_key = Secret::new(secret.to_pkcs8_der().unwrap().as_bytes().to_vec());
    let public_key = public.to_encoded_point(false).as_bytes().to_vec();
    drop(secret);

    (private_key, public_key)
}

fn ecc_enc(pub_key: &[u8], data: &[u8], sym_alg_id: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded_point =
        EncodedPoint::<p256::NistP256>::from_bytes(pub_key).expect("Invalid SEC1 public key bytes");

    let public_key =
        P256PublicKey::from_encoded_point(&encoded_point).expect("Invalid encoded point for P256");

    // Ephemeral ECDH key exchange
    let ephemeral = EphemeralSecret::random(&mut OsRng); // Zeroizes on drop
    let shared_secret = ephemeral.diffie_hellman(&public_key); // Zeroizes on drop

    // Derive symmetric key securely
    let mut digest = Sha256::digest(shared_secret.raw_secret_bytes());

    // Convert the digest into a [u8; 32]
    let mut key_bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .expect("Digest output is not 32 bytes");

    let secret_key = Secret::new(key_bytes);
    digest.zeroize();
    key_bytes.zeroize();

    // Encrypt data
    let nonce = get_nonce();
    let ciphertext = id_encrypt(sym_alg_id, secret_key.expose_secret(), &nonce, data, None);

    // Prepend ephemeral public key
    let eph_pub = p256::PublicKey::from(&ephemeral);
    let mut result = eph_pub.to_encoded_point(false).as_bytes().to_vec();
    result.extend_from_slice(&ciphertext.unwrap());

    Ok(result)
}

fn ecc_dec(
    priv_key: &[u8],
    ciphertext: &[u8],
    sym_alg_id: u8,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use zeroize::Zeroize;

    // Load private key
    let private_key = P256SecretKey::from_pkcs8_der(priv_key)
        .map_err(|e| format!("invalid private key: {}", e))?;

    // Split out ephemeral pubkey (65 bytes for uncompressed)
    let eph_pub_bytes = &ciphertext[..65];
    let actual_ciphertext = &ciphertext[65..];

    let eph_pub = P256PublicKey::from_sec1_bytes(eph_pub_bytes)
        .map_err(|e| format!("invalid ephemeral pubkey: {}", e))?;

    // Perform ECDH
    let shared_secret = diffie_hellman(private_key.to_nonzero_scalar(), eph_pub.as_affine());

    // Derive symmetric key securely
    let raw_secret = shared_secret.raw_secret_bytes();
    let mut digest = Sha256::digest(&raw_secret);

    let mut key_bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .expect("Digest output is not 32 bytes");

    let secret_key = Secret::new(key_bytes);
    digest.zeroize();
    key_bytes.zeroize();

    // Decrypt
    id_decrypt(
        sym_alg_id,
        secret_key.expose_secret(),
        actual_ciphertext,
        None,
    )
    .map_err(|e| format!("decryption failed: {}", e).into())
}

fn ecdsa_sign(priv_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = P256SecretKey::from_pkcs8_der(priv_key)
        .map_err(|e| format!("invalid private key: {}", e))?;

    // Convert to signing key
    let signing_key = EcdsaSigningKey::from(private_key.clone());

    // RFC6979 deterministic signing
    let signature: EcdsaSignature = signing_key.sign(data);

    Ok(signature.to_der().as_bytes().to_vec())
}

fn ecdsa_verify(pub_key: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<(), p256::ecdsa::Error> {
    let encoded_point =
        EncodedPoint::<p256::NistP256>::from_bytes(pub_key).expect("Invalid SEC1 public key bytes");

    let public_key =
        P256PublicKey::from_encoded_point(&encoded_point).expect("Invalid encoded point for P256");

    // Convert to verifying key
    let verifying_key = EcdsaVerifyingKey::from(public_key.clone());

    let signature = EcdsaSignature::from_der(sig_bytes)?;

    verifying_key.verify(data, &signature)
}

pub fn id_keypair_gen(
    alg_id: u8,
    bits: Option<usize>,
) -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn std::error::Error>> {
    match alg_id {
        ECC_ID => Ok(ecc_key_gen()),
        RSA_ID => Ok(rsa_key_gen(bits.unwrap_or(4096))),
        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

pub fn id_asym_enc(
    alg_id: u8,
    pub_key: &[u8],
    data: &[u8],
    sym_alg_id: Option<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match alg_id {
        ECC_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for ECC encryption")?;
            ecc_enc(pub_key, data, sym_alg_id)
        }
        RSA_ID => Ok(rsa_enc(pub_key, data)),
        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

pub fn id_asym_dec(
    alg_id: u8,
    priv_key: &[u8],
    ciphertext: &[u8],
    sym_alg_id: Option<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match alg_id {
        ECC_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for ECC decryption")?;
            ecc_dec(priv_key, ciphertext, sym_alg_id)
        }
        RSA_ID => Ok(rsa_dec(priv_key, ciphertext)),
        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

pub fn id_sign(alg_id: u8, priv_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    match alg_id {
        RSA_ID => Ok(rsa_sign(priv_key, data)),
        ECC_ID => ecdsa_sign(priv_key, data),
        _ => Err(format!("Unsupported signature algorithm ID: {}", alg_id).into()),
    }
}

pub fn id_verify(
    alg_id: u8,
    pub_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    match alg_id {
        RSA_ID => rsa_verify(pub_key, data, signature).map_err(|e| e.into()),
        ECC_ID => ecdsa_verify(pub_key, data, signature).map_err(|e| e.into()),
        _ => Err(format!("Unsupported signature algorithm ID: {}", alg_id).into()),
    }
}

// Testing
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rsa_enc_dec_kat() {
        let plaintext = b"Test vector: RSA encryption works!";
        let key_bits = 2048;

        // Generate RSA keypair using your provided method
        let (priv_key, pub_key) = rsa_key_gen(key_bits);

        // Encrypt using public key
        let ciphertext = rsa_enc(&pub_key, plaintext);

        // Decrypt using private key
        let decrypted = rsa_dec(&priv_key.expose_secret(), &ciphertext);

        // Verify the output matches input
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data does not match original"
        );
    }
    #[test]
    fn test_rsa_sign_verify_kat() {
        let message = b"Test vector: RSA signing works!";
        let (priv_key_der, pub_key_der) = rsa_key_gen(2048); // Should return (Vec<u8>, Vec<u8>)

        // Sign
        let signature = rsa_sign(&priv_key_der.expose_secret(), message);

        // Verify
        let result = rsa_verify(&pub_key_der, message, &signature);
        assert!(result.is_ok(), "RSA signature verification failed");
    }

    #[test]
    fn test_ecc_enc_dec_kat() {
        let sym_alg_id = 1; // Replace with your actual symmetric algorithm ID (e.g. AES-GCM = 1)
        let plaintext = b"Test vector: ECC encryption works!";

        // Generate keypair using your provided method
        let (priv_key, pub_key) = ecc_key_gen();

        // Encrypt using public key
        let ciphertext = ecc_enc(&pub_key, plaintext, sym_alg_id).expect("ECC encryption failed");

        // Decrypt using private key
        let decrypted = ecc_dec(&priv_key.expose_secret(), &ciphertext, sym_alg_id)
            .expect("ECC decryption failed");

        // Verify the output matches input
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data does not match original"
        );
    }
    #[test]
    fn test_ecdsa_sign_verify_kat() {
        let message = b"Test vector: ECDSA signing works!";
        let (priv_key_der, pub_key_sec1) = ecc_key_gen(); // Should return (Vec<u8>, Vec<u8>)

        // Sign
        let signature =
            ecdsa_sign(&priv_key_der.expose_secret(), message).expect("ECDSA signing failed");

        // Verify
        let result = ecdsa_verify(&pub_key_sec1, message, &signature);
        assert!(result.is_ok(), "ECDSA signature verification failed");
    }
}
