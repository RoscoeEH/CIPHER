// asymmetric_crypto.rs
//
// Copyright (c) 2025 RoscoeEH
//
// This source code is licensed under the MIT License.
// See the LICENSE file in the project root for full license information.
//
// Author: RoscoeEH
//
// Description:
// Handles all asymmetric cryptographic operations, including key generation,
// encryption, decryption, signing, verification, and testing for asymmetric algorithms.

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

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{
    PublicKey as DilithiumPublicKeyTrait, SecretKey as DilithiumSecretKeyTrait,
    SignedMessage as DilithiumSignedMessageTrait,
};

use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::error::Error;
use zeroize::Zeroize;

use crate::constants::*;
use crate::random::get_nonce;
use crate::symmetric_encryption::{id_decrypt, id_encrypt};

// === RSA Related Algorithms ===
/// Generates a new RSA key pair with the given number of bits.
///
/// This function creates a new RSA private key and derives the corresponding
/// public key. Both keys are encoded in PKCS#1 DER format. The private key is
/// wrapped in a [`Secret<Vec<u8>>`] to help prevent accidental exposure.
///
/// # Arguments
///
/// * `bits` - The number of bits for the RSA key. Typical values are 2048 or 4096.
///
/// # Returns
///
/// A tuple containing:
/// - `Secret<Vec<u8>>`: The DER-encoded RSA private key wrapped in `Secret`.
/// - `Vec<u8>`: The DER-encoded RSA public key.
///
/// # Panics
///
/// This function will panic if:
/// - RSA key generation fails.
/// - DER encoding of the private or public key fails.
fn rsa_key_gen(bits: usize) -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn Error>> {
    let mut rng = thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_der = private_key.to_pkcs1_der()?.as_bytes().to_vec();

    let public_key_der = public_key.to_pkcs1_der()?.as_bytes().to_vec();

    Ok((Secret::new(private_key_der), public_key_der))
}

/// Encrypts data using an RSA public key with PKCS#1 v1.5 padding.
///
/// The provided public key must be in PKCS#1 DER format. This function
/// uses the `Pkcs1v15Encrypt` scheme to perform the encryption.
///
/// # Arguments
///
/// * `pub_key` - A byte slice containing the DER-encoded RSA public key.
/// * `data` - The plaintext data to encrypt.
///
/// # Returns
///
/// A `Vec<u8>` containing the encrypted ciphertext.
///
/// # Panics
///
/// This function will panic if:
/// - The public key cannot be parsed from DER format.
/// - The encryption operation fails.
fn rsa_enc(pub_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let public_key = RsaPublicKey::from_pkcs1_der(pub_key)?;
    let encrypted_data = public_key.encrypt(&mut thread_rng(), Pkcs1v15Encrypt, data)?;
    Ok(encrypted_data)
}

/// Decrypts RSA-encrypted data using a private key with PKCS#1 v1.5 padding.
///
/// The provided private key must be in PKCS#1 DER format. This function
/// uses the `Pkcs1v15Encrypt` scheme to perform the decryption.
///
/// # Arguments
///
/// * `priv_key` - A byte slice containing the DER-encoded RSA private key.
/// * `ciphertext` - The encrypted data to decrypt.
///
/// # Returns
///
/// A `Vec<u8>` containing the decrypted plaintext data.
///
/// # Panics
///
/// This function will panic if:
/// - The private key cannot be parsed from DER format.
/// - The decryption operation fails.
fn rsa_dec(priv_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(priv_key)?;
    let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, ciphertext)?;
    Ok(decrypted_data)
}

/// Signs data using an RSA private key with PKCS#1 v1.5 padding and SHA-256.
///
/// The private key must be provided in PKCS#1 DER format. This function uses
/// the `RsaSigningKey` with the SHA-256 hashing algorithm to produce the signature.
///
/// # Arguments
///
/// * `priv_key` - A byte slice containing the DER-encoded RSA private key.
/// * `data` - The message data to sign.
///
/// # Returns
///
/// A `Vec<u8>` containing the RSA signature.
///
/// # Panics
///
/// This function will panic if:
/// - The private key cannot be parsed from DER format.
/// - The signing operation fails (e.g., internal errors in RNG or key usage).
fn rsa_sign(priv_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(priv_key)?;

    let signing_key = RsaSigningKey::<sha2::Sha256>::new(private_key);
    let mut rng = thread_rng();

    let signature = signing_key.sign_with_rng(&mut rng, data);

    Ok(signature.to_vec())
}

/// Verifies an RSA signature using a public key with PKCS#1 v1.5 padding and SHA-256.
///
/// The public key must be provided in PKCS#1 DER format. This function checks
/// whether the given signature is valid for the provided message and public key,
/// using the `RsaVerifyingKey` and SHA-256 hashing algorithm.
///
/// # Arguments
///
/// * `pub_key` - A byte slice containing the DER-encoded RSA public key.
/// * `data` - The original message data that was signed.
/// * `signature` - The signature to verify.
///
/// # Returns
///
/// * `Ok(())` if the signature is valid.
/// * `Err(rsa::signature::Error)` if the signature is invalid or malformed.
///
/// # Panics
///
/// This function will panic if:
/// - The public key cannot be parsed from DER format.
fn rsa_verify(pub_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
    let public_key = RsaPublicKey::from_pkcs1_der(pub_key)?;
    let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
    let sig = RsaSignature::try_from(signature)?;

    verifying_key.verify(data, &sig)?;
    Ok(())
}

// === ECC Related Operations ===

/// Generates an ECC key pair using the NIST P-256 curve.
///
/// This function creates a new elliptic curve private key and derives the
/// corresponding public key. The private key is encoded in PKCS#8 DER format
/// and wrapped in a [`Secret<Vec<u8>>`] to help protect sensitive material.
/// The public key is returned as an uncompressed SEC1-encoded byte vector.
///
/// # Returns
///
/// A tuple containing:
/// - `Secret<Vec<u8>>`: The DER-encoded ECC private key wrapped in `Secret`.
/// - `Vec<u8>`: The SEC1-encoded ECC public key (uncompressed).
///
/// # Panics
///
/// This function will panic if:
/// - The private key fails to encode into PKCS#8 DER format.
fn ecc_key_gen() -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn Error>> {
    // Generate a secret key
    let secret = P256SecretKey::random(&mut OsRng);

    // Derive public key
    let public = P256PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

    // Serialize keys safely
    let private_der = secret.to_pkcs8_der()?.as_bytes().to_vec();
    let private_key = Secret::new(private_der);

    let public_key = public.to_encoded_point(false).as_bytes().to_vec();
    drop(secret);

    Ok((private_key, public_key))
}

/// Encrypts data using ECC-based hybrid encryption with the NIST P-256 curve.
///
/// This function performs an ephemeral ECDH key exchange using the recipient's
/// public key to derive a symmetric key via SHA-256. It then encrypts the data
/// using the derived symmetric key and a specified symmetric algorithm.
///
/// The final ciphertext includes the ephemeral public key (SEC1 uncompressed) prepended
/// to the encrypted data, allowing the recipient to perform key agreement during decryption.
///
/// # Arguments
///
/// * `pub_key` - A byte slice containing the recipient's SEC1-encoded uncompressed ECC public key.
/// * `data` - The plaintext data to encrypt.
/// * `sym_alg_id` - An identifier indicating which symmetric algorithm to use.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The encrypted payload, with the ephemeral public key prepended.
/// * `Err(Box<dyn Error>)` - If encryption fails due to algorithm issues or encoding errors.
///
/// # Panics
///
/// This function will panic if:
/// - The provided public key is not valid SEC1-encoded format.
/// - The key derivation digest output is not 32 bytes.
fn ecc_enc(pub_key: &[u8], data: &[u8], sym_alg_id: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded_point = EncodedPoint::<p256::NistP256>::from_bytes(pub_key)
        .map_err(|_| "Invalid SEC1 public key bytes")?;

    let public_key = P256PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or("Invalid encoded point for P256")?;

    // Ephemeral ECDH key exchange
    let ephemeral = EphemeralSecret::random(&mut OsRng); // Zeroizes on drop
    let shared_secret = ephemeral.diffie_hellman(&public_key); // Zeroizes on drop

    // Derive symmetric key securely
    let digest = Sha256::digest(shared_secret.raw_secret_bytes());

    // Convert digest to [u8; 32]
    let mut key_bytes: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| "Digest output is not 32 bytes")?;

    let secret_key = Secret::new(key_bytes);
    key_bytes.zeroize();

    // Encrypt data
    let nonce = get_nonce()?;
    let ciphertext = id_encrypt(sym_alg_id, secret_key.expose_secret(), &nonce, data, None)?;

    // Prepend ephemeral public key
    let eph_pub = p256::PublicKey::from(&ephemeral);
    let mut result = eph_pub.to_encoded_point(false).as_bytes().to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts data that was encrypted using ECC-based hybrid encryption with the NIST P-256 curve.
///
/// This function:
/// - Extracts the ephemeral public key from the ciphertext (first 65 bytes, SEC1 uncompressed format),
/// - Performs ECDH using the recipient's private key,
/// - Derives a 256-bit symmetric key using SHA-256,
/// - And decrypts the payload using the specified symmetric algorithm.
///
/// # Arguments
///
/// * `priv_key` - DER-encoded ECC private key in PKCS#8 format.
/// * `ciphertext` - The encrypted data, with the first 65 bytes containing the ephemeral public key.
/// * `sym_alg_id` - An identifier for the symmetric encryption algorithm used.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext.
/// * `Err(Box<dyn Error>)` - If decryption or any part of the key processing fails.
///
/// # Panics
///
/// This function panics if the SHA-256 digest output cannot be converted into a 32-byte array.
/// (This is unlikely and would indicate an internal logic error.)
fn ecc_dec(priv_key: &[u8], ciphertext: &[u8], sym_alg_id: u8) -> Result<Vec<u8>, Box<dyn Error>> {
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

    let mut key_bytes: [u8; 32] = digest.as_slice().try_into()?;

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
}

/// Signs data using ECDSA over the NIST P-256 curve with SHA-256 and deterministic (RFC 6979) signing.
///
/// This function loads a DER-encoded private key, creates an ECDSA signing key,
/// and produces a signature over the provided message using deterministic nonce generation.
///
/// # Arguments
///
/// * `priv_key` - A byte slice containing the PKCS#8 DER-encoded ECC private key.
/// * `data` - The message bytes to sign.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The DER-encoded ECDSA signature.
/// * `Err(Box<dyn Error>)` - If the private key is invalid or signing fails.
///
/// # Notes
///
/// - Uses deterministic signing as per [RFC 6979].
/// - The output signature is encoded in ASN.1 DER format.
fn ecdsa_sign(priv_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let private_key = P256SecretKey::from_pkcs8_der(priv_key)
        .map_err(|e| format!("invalid private key: {}", e))?;

    // Convert to signing key
    let signing_key = EcdsaSigningKey::from(private_key.clone());

    // RFC6979 deterministic signing
    let signature: EcdsaSignature = signing_key.sign(data);

    Ok(signature.to_der().as_bytes().to_vec())
}

/// Verifies an ECDSA signature using the NIST P-256 curve and SHA-256.
///
/// This function takes a SEC1-encoded public key, a message, and a DER-encoded signature.
/// It reconstructs the verifying key and checks the validity of the signature.
///
/// # Arguments
///
/// * `pub_key` - A byte slice containing the SEC1-encoded uncompressed ECC public key.
/// * `data` - The original message that was signed.
/// * `sig_bytes` - The DER-encoded ECDSA signature.
///
/// # Returns
///
/// * `Ok(())` - If the signature is valid.
/// * `Err(p256::ecdsa::Error)` - If the signature is malformed or invalid.
///
/// # Panics
///
/// This function panics if the public key bytes cannot be parsed into a valid SEC1 point.
fn ecdsa_verify(pub_key: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let encoded_point = EncodedPoint::<p256::NistP256>::from_bytes(pub_key)
        .map_err(|e| format!("Invalid SEC1 public key bytes: {e}"))?;

    let public_key = P256PublicKey::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or("Invalid encoded point for P256")?;

    let verifying_key = EcdsaVerifyingKey::from(public_key);

    let signature = EcdsaSignature::from_der(sig_bytes)
        .map_err(|e| format!("Failed to parse DER signature: {e}"))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|e| format!("Signature verification failed: {e}"))?;

    Ok(())
}
// === kyber ===

/// Generates a new Kyber512 public/private keypair.
///
/// # Returns
///
/// Returns a `Result` containing a tuple:
/// - `Secret<Vec<u8>>`: The private key wrapped in a `Secret` for secure memory handling.
/// - `Vec<u8>`: The public key as raw bytes.
///
/// # Errors
///
/// Returns an error if key generation fails (though `kyber512::keypair()` is infallible in this case).
fn kyber_key_gen() -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn Error>> {
    let (public_key, secret_key) = kyber512::keypair();

    let secret_key_bytes = Secret::new(secret_key.as_bytes().to_vec());
    let public_key_bytes = public_key.as_bytes().to_vec();

    Ok((secret_key_bytes, public_key_bytes))
}

/// Encrypts data using Kyber512 for key encapsulation and a symmetric cipher for payload encryption.
///
/// This function performs hybrid encryption by encapsulating a shared secret using the recipient's
/// Kyber512 public key, then deriving a 256-bit AES key from that secret using SHA-256. The actual data
/// is encrypted using the specified symmetric AEAD algorithm.
///
/// # Arguments
///
/// - `pub_key`: A byte slice containing the recipient's Kyber512 public key.
/// - `data`: The plaintext data to encrypt.
/// - `sym_alg_id`: The ID of the symmetric AEAD algorithm to use for encrypting the data.
///
/// # Returns
///
/// A `Result` containing the ciphertext, which includes:
/// - The Kyber encapsulation ciphertext (for deriving the shared secret on the recipient side).
/// - The AEAD-encrypted payload appended to it.
///
/// # Errors
///
/// Returns an error if:
/// - The public key is invalid or fails to deserialize.
/// - Symmetric encryption fails.
fn kyber_enc(pub_key: &[u8], data: &[u8], sym_alg_id: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    // Load the recipient's public key
    let public_key = kyber512::PublicKey::from_bytes(pub_key)?;

    // Encapsulate to get the ciphertext and shared secret
    let (shared_secret, ciphertext) = kyber512::encapsulate(&public_key);

    // Hash the shared secret to derive symmetric key
    let mut digest = Sha256::digest(shared_secret.as_bytes());

    let mut key_bytes: [u8; 32] = digest.as_slice().try_into()?;

    let secret_key = Secret::new(key_bytes);
    digest.zeroize();
    key_bytes.zeroize();

    // Encrypt the payload with symmetric encryption
    let nonce = get_nonce()?;
    let ciphertext_payload =
        id_encrypt(sym_alg_id, secret_key.expose_secret(), &nonce, data, None)?;

    // Output: Kyber ciphertext || encrypted payload
    let mut result = ciphertext.as_bytes().to_vec();
    result.extend_from_slice(&ciphertext_payload);

    Ok(result)
}

/// Decrypts data encrypted with Kyber512 hybrid encryption.
///
/// This function expects input that was encrypted using the `kyber_enc` function. It extracts the
/// Kyber ciphertext to recover the shared secret, derives a symmetric key using SHA-256, and
/// decrypts the AEAD-encrypted payload with the specified symmetric algorithm.
///
/// # Arguments
///
/// - `private_key_bytes`: A byte slice containing the Kyber512 private key used for decapsulation.
/// - `ciphertext`: The full ciphertext, consisting of the Kyber encapsulation followed by the encrypted payload.
/// - `sym_alg_id`: The ID of the symmetric AEAD algorithm used for the payload.
///
/// # Returns
///
/// A `Result` containing the decrypted plaintext.
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext is malformed or too short.
/// - Decapsulation or symmetric decryption fails.
/// - The private key or ciphertext cannot be deserialized.
fn kyber_dec(
    private_key_bytes: &[u8],
    ciphertext: &[u8],
    sym_alg_id: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let secret_key = kyber512::SecretKey::from_bytes(private_key_bytes)?;

    // Split out the Kyber ciphertext
    let kyber_ciphertext_len = kyber512::ciphertext_bytes();
    if ciphertext.len() < kyber_ciphertext_len {
        return Err("ciphertext too short".into());
    }

    let encapsulated_bytes = &ciphertext[..kyber_ciphertext_len];
    let encrypted_payload = &ciphertext[kyber_ciphertext_len..];

    // Load ciphertext and decapsulate
    let encapsulated = kyber512::Ciphertext::from_bytes(encapsulated_bytes)?;
    let shared_secret = kyber512::decapsulate(&encapsulated, &secret_key);

    // Derive symmetric key
    let mut digest = Sha256::digest(shared_secret.as_bytes());

    let mut key_bytes: [u8; 32] = digest.as_slice().try_into()?;

    let secret_key = Secret::new(key_bytes);
    digest.zeroize();
    key_bytes.zeroize();

    // Decrypt the symmetric ciphertext
    id_decrypt(
        sym_alg_id,
        secret_key.expose_secret(),
        encrypted_payload,
        None,
    )
}

// === dilithium ===

/// Generates a Dilithium2 public-private key pair for post-quantum digital signatures.
///
/// This function creates a new keypair using the Dilithium2 algorithm and returns the private key
/// securely wrapped in a [`Secret`] and the public key as a byte vector.
///
/// # Returns
///
/// A `Result` containing a tuple with:
/// - A `Secret<Vec<u8>>` holding the private key bytes.
/// - A `Vec<u8>` with the public key bytes.
///
/// # Errors
///
/// Returns an error if key generation fails, though this is unlikely under normal conditions.
fn dilithium_key_gen() -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn Error>> {
    let (public_key_struct, secret_key_struct) = dilithium2::keypair();

    let private_key_bytes = secret_key_struct.as_bytes().to_vec();
    let public_key_bytes = public_key_struct.as_bytes().to_vec();

    Ok((Secret::new(private_key_bytes), public_key_bytes))
}

/// Signs a message using a Dilithium2 private key.
///
/// This function uses the provided Dilithium2 private key bytes to sign the input message,
/// returning the detached signature as a byte vector.
///
/// # Arguments
///
/// * `message` - The message to be signed.
/// * `private_key_bytes` - Byte slice containing the Dilithium2 private key.
///
/// # Returns
///
/// A `Result` containing the signature as a `Vec<u8>`, or an error if signing fails.
///
/// # Errors
///
/// Returns an error if the private key is invalid or signing fails.
fn dilithium_sign(message: &[u8], private_key_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let secret_key = dilithium2::SecretKey::from_bytes(private_key_bytes)?;
    let signed_message = dilithium2::sign(message, &secret_key);

    // Extract the signature portion
    let signature_len = signed_message.as_bytes().len() - message.len();
    let signature = &signed_message.as_bytes()[..signature_len];

    Ok(signature.to_vec())
}

/// Verifies a Dilithium2 signature for a given message and public key.
///
/// This function reconstructs a signed message from the provided detached signature and message,
/// and verifies it using the given Dilithium2 public key.
///
/// # Arguments
///
/// * `public_key_bytes` - Byte slice containing the Dilithium2 public key.
/// * `message` - The original message that was signed.
/// * `signature` - The detached signature to verify.
///
/// # Returns
///
/// Returns `Ok(())` if the signature is valid, or an error if verification fails.
///
/// # Errors
///
/// Returns an error if the public key, signature, or verification fails.
fn dilithium_verify(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Box<dyn Error>> {
    let public_key = dilithium2::PublicKey::from_bytes(public_key_bytes)?;

    // Reconstruct a `SignedMessage` by prepending the signature to the message
    let mut signed_data = signature.to_vec();
    signed_data.extend_from_slice(message);

    let signed_message = dilithium2::SignedMessage::from_bytes(&signed_data)?;
    let _ = dilithium2::open(&signed_message, &public_key)?; // discard message

    Ok(())
}

// === id based functions ===

/// Generates a public/private keypair for a specified asymmetric algorithm.
///
/// Depending on the provided algorithm ID, this function delegates to the appropriate
/// key generation routine (e.g., RSA, ECC, etc...). RSA key length can be customized via `bits`.
///
/// # Arguments
///
/// * `alg_id` - An identifier specifying the type of asymmetric algorithm (e.g., ECC or RSA).
/// * `bits` - Optional RSA key size in bits; defaults to 4096 if not provided.
///
/// # Returns
///
/// * `Ok((Secret<Vec<u8>>, Vec<u8>))` - A tuple containing the private key (wrapped in `Secret`) and the public key bytes.
/// * `Err(Box<dyn Error>)` - If the algorithm ID is unrecognized.
///
/// # Notes
///
/// - ECC keys are generated using the NIST P-256 curve.
/// - RSA keys are encoded in PKCS#1 DER format.
/// - The public key is returned in a raw byte-encoded format appropriate for the algorithm.
pub fn id_keypair_gen(
    alg_id: u8,
    bits: Option<usize>,
) -> Result<(Secret<Vec<u8>>, Vec<u8>), Box<dyn Error>> {
    match alg_id {
        ECC_ID => ecc_key_gen(),
        RSA_ID => rsa_key_gen(bits.unwrap_or(4096)),
        KYBER_ID => kyber_key_gen(),
        DILITHIUM_ID => dilithium_key_gen(),
        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

/// Encrypts data using the specified asymmetric algorithm and public key.
///
/// This function routes encryption to the appropriate implementation based on the
/// provided algorithm ID. ECC encryption uses hybrid encryption (ECDH + symmetric),
/// requiring an additional symmetric algorithm ID; Kyber works similarly.
/// RSA encryption uses direct encryption.
///
/// # Arguments
///
/// * `alg_id` - Identifier for the asymmetric encryption algorithm (e.g., ECC or RSA).
/// * `pub_key` - Byte slice containing the public key.
/// * `data` - The plaintext data to encrypt.
/// * `sym_alg_id` - Optional symmetric algorithm ID (required for ECC hybrid encryption).
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The encrypted ciphertext.
/// * `Err(Box<dyn Error>)` - If encryption fails or parameters are invalid.
///
/// # Notes
///
/// - For ECC, a symmetric key is derived via ECDH and used to encrypt `data` using the specified symmetric algorithm.
/// - For Kyber, a symetric key is generated and used to encrypt the data.
/// - For RSA, data is encrypted directly with the public key using PKCS#1 v1.5 padding.
///
/// # Errors
///
/// - Returns an error if `sym_alg_id` is missing when `alg_id` is ECC.
/// - Returns an error for unrecognized algorithm identifiers.
pub fn id_asym_enc(
    alg_id: u8,
    pub_key: &[u8],
    data: &[u8],
    sym_alg_id: Option<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match alg_id {
        ECC_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for ECC encryption")?;
            ecc_enc(pub_key, data, sym_alg_id)
        }
        RSA_ID => rsa_enc(pub_key, data),
        KYBER_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for Kyber encryption")?;
            kyber_enc(pub_key, data, sym_alg_id)
        }
        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

/// Decrypts data using the specified asymmetric algorithm and private key.
///
/// This function dispatches decryption logic based on the provided algorithm ID.
/// ECC decryption involves ECDH key agreement and symmetric decryption, requiring
/// an additional symmetric algorithm ID; Kyber works similarly. RSA decryption uses PKCS#1 v1.5.
///
/// # Arguments
///
/// * `alg_id` - Identifier for the asymmetric algorithm (e.g., ECC or RSA).
/// * `priv_key` - Byte slice containing the private key.
/// * `ciphertext` - The encrypted data to decrypt.
/// * `sym_alg_id` - Optional symmetric algorithm ID (required for ECC hybrid decryption).
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext.
/// * `Err(Box<dyn Error>)` - If decryption fails or parameters are invalid.
///
/// # Notes
///
/// - ECC decryption reconstructs a shared secret from the ephemeral key and derives a symmetric key to decrypt the message.
/// - RSA decryption is performed directly using PKCS#1 v1.5.
///
/// # Errors
///
/// - Returns an error if `sym_alg_id` is not provided when `alg_id` is ECC.
/// - Returns an error if the `alg_id` is unrecognized or decryption fails.
pub fn id_asym_dec(
    alg_id: u8,
    priv_key: &[u8],
    ciphertext: &[u8],
    sym_alg_id: Option<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    match alg_id {
        ECC_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for ECC decryption")?;
            ecc_dec(priv_key, ciphertext, sym_alg_id)
        }
        RSA_ID => rsa_dec(priv_key, ciphertext),
        KYBER_ID => {
            let sym_alg_id =
                sym_alg_id.ok_or("Missing symmetric algorithm ID for Kyber decryption")?;
            kyber_dec(priv_key, ciphertext, sym_alg_id)
        }

        _ => Err(format!("Unrecognized asymmetric key type: {}", alg_id).into()),
    }
}

/// Signs data using the specified asymmetric signature algorithm and private key.
///
/// This function delegates to the appropriate signing implementation (RSA, ECDSA, or Dilithium2)
/// based on the provided algorithm ID.
///
/// # Arguments
///
/// * `alg_id` - Identifier for the signature algorithm (e.g., RSA or ECC).
/// * `priv_key` - Byte slice containing the private key (format depends on algorithm).
/// * `data` - The message bytes to be signed.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The generated signature (DER-encoded for ECC).
/// * `Err(Box<dyn Error>)` - If the algorithm ID is unsupported or signing fails.
///
/// # Notes
///
/// - RSA signatures are typically PKCS#1 v1.5 with SHA-256.
/// - ECC signatures use ECDSA over the NIST P-256 curve with deterministic nonce (RFC 6979).
/// - Dilithium signatures use Dilithium2, a post-quantum digital signature scheme (CRYSTALS).
pub fn id_sign(alg_id: u8, priv_key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    match alg_id {
        RSA_ID => rsa_sign(priv_key, data),
        ECC_ID => ecdsa_sign(priv_key, data),
        DILITHIUM_ID => dilithium_sign(data, priv_key),
        _ => Err(format!("Unsupported signature algorithm ID: {}", alg_id).into()),
    }
}

/// Verifies a digital signature using the specified asymmetric signature algorithm and public key.
///
/// This function delegates to the appropriate verification implementation (RSA or ECDSA)
/// based on the provided algorithm ID.
///
/// # Arguments
///
/// * `alg_id` - Identifier for the signature algorithm (e.g., RSA or ECC).
/// * `pub_key` - Byte slice containing the public key (format depends on algorithm).
/// * `data` - The original message that was signed.
/// * `signature` - The signature bytes to verify (DER-encoded for ECC).
///
/// # Returns
///
/// * `Ok(())` - If the signature is valid.
/// * `Err(Box<dyn Error>)` - If verification fails or the algorithm ID is unsupported.
///
/// # Notes
///
/// - RSA verification uses PKCS#1 v1.5 padding and SHA-256.
/// - ECC verification uses ECDSA with SHA-256 over the NIST P-256 curve.
/// - Dilithium verification uses Dilithium2, a post-quantum signature scheme from CRYSTALS.
/// - This function panics if the provided key formats are invalid.
pub fn id_verify(
    alg_id: u8,
    pub_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), Box<dyn Error>> {
    match alg_id {
        RSA_ID => rsa_verify(pub_key, data, signature).map_err(|e| e.into()),
        ECC_ID => ecdsa_verify(pub_key, data, signature).map_err(|e| e.into()),
        DILITHIUM_ID => dilithium_verify(pub_key, data, signature),
        _ => Err(format!("Unsupported signature algorithm ID: {}", alg_id).into()),
    }
}

// Testing for encryption, decryption, signing and verifying
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rsa_enc_dec_kat() -> Result<(), Box<dyn Error>> {
        let plaintext = b"Test vector: RSA encryption test";
        let key_bits = 2048;

        // Generate RSA keypair
        let (priv_key, pub_key) = rsa_key_gen(key_bits)?;

        // Encrypt
        let ciphertext = rsa_enc(&pub_key, plaintext)?;

        // Decrypt
        let decrypted = rsa_dec(&priv_key.expose_secret(), &ciphertext)?;

        // Verify the output matches input
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data does not match original"
        );

        Ok(())
    }
    #[test]
    fn test_rsa_sign_verify_kat() -> Result<(), Box<dyn Error>> {
        let message = b"Test vector: RSA signing test";
        let (priv_key_der, pub_key_der) = rsa_key_gen(2048)?;

        let signature = rsa_sign(&priv_key_der.expose_secret(), message)?;

        rsa_verify(&pub_key_der, message, &signature)?;

        Ok(())
    }

    #[test]
    fn test_ecc_enc_dec_kat() -> Result<(), Box<dyn Error>> {
        let sym_alg_id = AES_GCM_ID;
        let plaintext = b"Test vector: ECC encryption test";

        let (priv_key, pub_key) = ecc_key_gen()?;

        let ciphertext = ecc_enc(&pub_key, plaintext, sym_alg_id)?;

        let decrypted = ecc_dec(&priv_key.expose_secret(), &ciphertext, sym_alg_id)?;

        assert_eq!(
            decrypted, plaintext,
            "Decrypted data does not match original"
        );

        Ok(())
    }

    #[test]
    fn test_ecdsa_sign_verify_kat() -> Result<(), Box<dyn Error>> {
        let message = b"Test vector: ECDSA signing test";
        let (priv_key_der, pub_key_sec1) = ecc_key_gen()?;

        let signature = ecdsa_sign(&priv_key_der.expose_secret(), message)?;

        ecdsa_verify(&pub_key_sec1, message, &signature)?;

        Ok(())
    }

    #[test]
    fn test_kyber_enc_dec_kat() -> Result<(), Box<dyn Error>> {
        let plaintext = b"Test vector: Kyber encryption test";
        let sym_alg_id = AES_GCM_ID;

        let (secret_key_bytes, public_key_bytes) = kyber_key_gen()?;

        let ciphertext = kyber_enc(&public_key_bytes, plaintext, sym_alg_id)?;

        let decrypted = kyber_dec(&secret_key_bytes.expose_secret(), &ciphertext, sym_alg_id)?;

        assert_eq!(
            decrypted, plaintext,
            "Kyber decrypted data does not match original"
        );

        Ok(())
    }

    #[test]
    fn test_dilithium_sign_verify_kat() -> Result<(), Box<dyn Error>> {
        let message = b"Test vector: Dilithium signing test";

        let (secret_key_bytes, public_key_bytes) = dilithium_key_gen()?;

        let signature = dilithium_sign(message, &secret_key_bytes.expose_secret())?;

        dilithium_verify(&public_key_bytes, message, &signature)?;

        Ok(())
    }
}
