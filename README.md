# CIPHER: Command-line Interface for Protection, Hardening, and Endpoint Reinforcement

**Cipher** is a flexible, extensible command-line application for encrypting and decrypting files using modern cryptographic standards, including support for **post-quantum algorithms**. It supports both symmetric and asymmetric encryption schemes, configurable password-based key derivation functions (KDFs), and profile-based parameter management.

Cipher securely encapsulates all necessary cryptographic material—including ciphertext, salt, nonces, and algorithm identifiers—into a single `.enc` or `.sig` file for reliable and portable decryption and verification. Key generation, storage, and verification are handled via RocksDB and Serde, with user-defined profiles simplifying cryptographic parameter reuse.

## Features

- **Authenticated Encryption** using **AES-256-GCM** and **ChaCha20-Poly1305**
- **Known Answer Tests (KATs)** for symmetric encryption schemes
- **Password-based Key Derivation** with **Argon2** and **PBKDF2**
- **User Profiles** for storing cryptographic preferences (KDF parameters, AEAD choice)
- **Asymmetric Encryption Support** for **RSA**, **ECC**, **Kyber**, and **Dilithium** including:
  - Key generation
  - Encryption/decryption
  - Signing and verification
- **Signed files** are saved with a `.sig` extension
- **Serde-powered serialization** for user profiles and key storage
- **Secure Key Storage** using RocksDB with optional encryption of private keys
- Secure random **salt** and **nonce** generation
- Automatic **zeroization** of sensitive memory (e.g., keys, passwords)
- **Password verification** on entry to reduce human error
-  Encrypted output stored in a **single `.enc` file** containing:
  - Encrypted payload
  - Algorithm identifiers
  - Salt, nonce, and metadata

## Dependencies

This project makes use of the following Rust crates:

- [aes-gcm](https://crates.io/crates/aes-gcm) — Authenticated encryption (AES-256-GCM)
- [chacha20poly1305](https://crates.io/crates/chacha20poly1305) — Alternative AEAD cipher
- [argon2](https://crates.io/crates/argon2) — Memory-hard password hashing and key derivation
- [pbkdf2](https://crates.io/crates/pbkdf2) — Password-based key derivation function
- [hmac](https://crates.io/crates/hmac) — HMAC construction for PBKDF2
- [sha2](https://crates.io/crates/sha2) — SHA-2 hash functions
- [aead](https://crates.io/crates/aead) — AEAD trait abstraction
- [generic-array](https://crates.io/crates/generic-array) — Fixed-size arrays used in cryptographic types
- [typenum](https://crates.io/crates/typenum) — Type-level numbers used with generic-array
- [rsa](https://crates.io/crates/rsa) — RSA encryption, signing, and keypair generation
- [p256](https://crates.io/crates/p256) — NIST P-256 curve for ECC key exchange and signing
- [elliptic-curve](https://crates.io/crates/elliptic-curve) — ECC trait definitions and encoding support
- [pqcrypto-kyber](https://crates.io/crates/pqcrypto-kyber) — Post-quantum Kyber encryption (Kyber512)
- [pqcrypto-dilithium](https://crates.io/crates/pqcrypto-dilithium) — Post-quantum Dilithium digital signatures (Dilithium2)
- [pqcrypto-traits](https://crates.io/crates/pqcrypto-traits) — Common trait interfaces for post-quantum schemes
- [secrecy](https://crates.io/crates/secrecy) — Secret type wrappers for zeroization and memory safety
- [zeroize](https://crates.io/crates/zeroize) — Secure memory zeroing for sensitive data
- [serde](https://crates.io/crates/serde) — Serialization framework with `derive` support
- [bincode](https://crates.io/crates/bincode) — Binary serialization using Serde
- [rocksdb](https://crates.io/crates/rocksdb) — Persistent key-value database for profile and key storage
- [lazy_static](https://crates.io/crates/lazy_static) — Runtime-initialized global variables
- [rpassword](https://crates.io/crates/rpassword) — Secure password input from the terminal
- [clap](https://crates.io/crates/clap) — Command-line argument parsing with derive support
- [rand](https://crates.io/crates/rand) — Random number generation
- [rand_core](https://crates.io/crates/rand_core) — Core traits for RNGs
- [directories](https://crates.io/crates/directories) — Cross-platform standard directories (config, data, cache)
- [chrono](https://crates.io/crates/chrono) — Date and time utilities

## Usage

The `cipher` CLI tool provides a variety of commands to handle encryption, decryption, key management, and user profile customization.

### General Functions

#### File Encryption & Decryption

- `encrypt`: Encrypt a file using symmetric (default) or asymmetric encryption. Supports profile-based parameter configuration, custom AEAD and KDF choices, and secure key handling.
- `decrypt`: Decrypt an encrypted `.enc` file back to its original format.

#### Key Management

- `keygen`: Generate a new symmetric or asymmetric key pair (RSA or ECC). Can be associated with a profile for customized encryption settings.
- `list-keys`: Display all stored keys in the database.
- `delete-key`: Permanently delete a key by its ID.
- `export-key`: Export a public key as a `.pub` file for sharing or further use.
- `import-key`: Import a `.pub` file containing a public key for use in encryption or verification.

#### Profiles

- `profile`: Update a user profile’s encryption parameters (e.g., `kdf_id`, `aead_alg_id`, `memory_cost`, etc.).
- `list-profiles`: Show all stored user profiles.

####  Signing & Verification

- `sign`: Digitally sign a file using a private key. The signature is saved as a `.sig` file.
- `verify`: Verify a signed file and optionally extract the original content.


### Inputs

#### `encrypt`

| Argument          | Type     | Description                                                                |
|-------------------|----------|----------------------------------------------------------------------------|
| `input`           | `String` | Path to the file to encrypt *(required)*                                   |
| `output`          | `String` | Path to write the encrypted `.enc` file *(optional)*                       |
| `--key`, `-k`     | `String` | Use existing key ID *(will default to symmetric encryption without a key)* |
| `--sign`, `-s`    | `String` | Sign the file using the specified private key *(optional)*                 |
| `--profile`, `-p` | `String` | Use default encryption parameters from a non-default profile *(optional)*  |
| `--kdf`           | `String` | KDF algorithm to use (e.g., `argon2`, `pbkdf2`) *(optional)*               |
| `--mem-cost`      | `u32`    | Argon2 memory cost *(optional)*                                            |
| `--time-cost`     | `u32`    | Argon2 time cost *(optional)*                                              |
| `--parallelism`   | `u32`    | Argon2 parallelism *(optional)*                                            |
| `--iters`         | `u32`    | PBKDF2 iterations *(optional)*                                             |
| `--aead`          | `String` | AEAD algorithm (e.g., `aes256gcm`, `chacha20poly1305`) *(optional)*        |

Encrypts a file into a `.enc` file. Can be used for asymmetric encryption if an asymmetric key is provided. Optionally signes the ciphertext with a private key. If not key is provided it will default to symmetric encryption with a single use key.

#### 🔓 `decrypt`

| Argument         | Type      | Description                                        |
|------------------|-----------|----------------------------------------------------|
| `input`          | `String`  | Path to the encrypted `.enc` file *(required)*     |
| `output`         | `String`  | Path to write the decrypted file *(optional)*      |

Decrypts all `.enc` file. Verifies a signature if signed.

#### `profile`

| Argument         | Type      | Description                                                                            |
|------------------|-----------|----------------------------------------------------------------------------------------|
| `--profile`, `-p`| `String`  | Profile ID to update *(defaults to `Default`)*                                        |
| `update_field`   | `String`  | Field to update (`kdf`, `aead`, `memory_cost`, `time_cost`, `parallelism`, or `iterations`) *(required)*                       |
| `value`          | `String`  | New value for the specified field *(required)*                                        |

Updated profiles that contain default parameters for key derivation and symmetric encryption.

#### `list-profiles`
Lists all existing profiles.

#### `key-gen`

| Argument              | Type      | Description                                                                |
|-----------------------|-----------|----------------------------------------------------------------------------|
| `id`                  | `String`  | Unique identifier for the key *(required)*                                 |
| `--symmetric`, `-s`   | `bool`    | Generate a symmetric key                                                   |
| `--asymmetric-alg`, `-a` | `String`  | Generate an asymmetric key pair (`rsa`, `ecc`, `kyber`, `dilithium`) *(mutually exclusive with symmetric)* |
| `--bits`, `-b`        | `usize`   | RSA key size in bits (`2048`, `3072`, `4096`) *(RSA only)*                 |
| `--profile`, `-p`     | `String`  | Associated profile ID *(defaults to `Default`)*                            |

Generates a new key or keypair.

####  `list-keys`

| Argument            | Type   | Description                                                           |
|---------------------|--------|-----------------------------------------------------------------------|
| `--unowned`, `-u`   | `bool` | List only keys that have been imported *(optional, default: false)* |

Displays stored keys in the database. By default includes owned keys unless `--unowned` is specified.

#### `delete-key`

| Argument            | Type     | Description                                           |
|---------------------|----------|-------------------------------------------------------|
| `id`                | `String` | ID of the key to delete *(required)*                 |
| `--unowned`, `-u`   | `bool`   | Delete from the imported (unowned) key list *(optional)* |

Deletes a key by ID. Use `--unowned` if the key was imported and not locally generated.

#### `wipe`

| Argument               | Type   | Description                                        |
|------------------------|--------|----------------------------------------------------|
| `--keys`, `-k`         | `bool` | Wipe all keys                                      |
| `--profiles`, `-p`     | `bool` | Wipe all profiles                                  |
| `--unowned`, `-u`      | `bool` | Wipe all imported (unowned) keys                   |

If no flags are provided, **all keys and profiles will be wiped by default**.

####  `sign`

| Argument         | Type      | Description                        |
|------------------|-----------|------------------------------------|
| `input`          | `String`  | File to sign *(required)*          |
| `--key`, `-k`    | `String`  | ID of the private key to sign with |

Signs a file and creates a `.sig` file.

#### `verify`

| Argument             | Type     | Description                                        |
|----------------------|----------|----------------------------------------------------|
| `input`              | `String` | Path to `.sig` file to verify *(required)*         |
| `--only-verify`, `-o`| `bool`   | Only verify, do not output original file (optional)|

Verifies `.sig` files, can also strip the signature and header from the file.

#### `export-key`

| Argument           | Type      | Description                                                      |
|--------------------|-----------|------------------------------------------------------------------|
| `key_id`           | `String`  | ID of the key to export *(required)*                             |
| `--name`, `-n`     | `String`  | Optional filename (without extension) for the exported `.pub` file |

Exports a public key associated with the given ID to a `.pub` file. If no name is provided, the key ID is used as the filename.

#### `import-key`

| Argument            | Type      | Description                                                             |
|---------------------|-----------|-------------------------------------------------------------------------|
| `input_file`        | `String`  | Path to the `.pub` file to import *(must end with `.pub`)*              |
| `--name`, `-n`      | `String`  | Optional name to associate with the imported key                        |

Imports a public key from a `.pub` file into the local key database. The file must have a `.pub` extension. Optionally assigns a user-defined name to the key.

## File Format

### `.enc` — Encrypted File Format

The `.enc` file has two distinct variants, depending on whether **symmetric** or **asymmetric** encryption is used.

#### Symmetric Encryption (`ENC1`)

| Field             | Size         | Description                                         |
|------------------|--------------|-----------------------------------------------------|
| Magic bytes      | 4 bytes      | `b"ENC1"` (format identifier)                       |
| KDF ID           | 1 byte       | ID for the key derivation function (e.g. Argon2)    |
| AEAD ID          | 1 byte       | AEAD algorithm ID (e.g. AES-GCM)                    |
| Salt length      | 4 bytes      | Big-endian `u32`, number of salt bytes              |
| Salt             | variable     | Random salt for KDF                                 |
| KDF Params       | variable     | Depends on KDF:<br/>- Argon2: `memory_cost (4)`, `time_cost (4)`, `parallelism (4)`<br/>- PBKDF2: `iterations (4)` |
| Filename length  | 2 bytes      | Big-endian `u16`                                    |
| Ciphertext       | variable     | AEAD-encrypted content + filename (as payload)      |

All fields are concatenated in the above order. The header is also used as AEAD associated data (AAD).

#### Asymmetric Encryption (`ENC2`)

| Field             | Size         | Description                                             |
|------------------|--------------|---------------------------------------------------------|
| Magic bytes      | 4 bytes      | `b"ENC2"`                                               |
| Asym Alg ID      | 1 byte       | Asymmetric encryption algorithm (e.g. RSA, X25519)     |
| AEAD ID          | 1 byte       | AEAD used for symmetric key wrapping (e.g. AES-GCM)    |
| Key ID length    | 2 bytes      | Big-endian `u16`                                       |
| Key ID           | variable     | UTF-8 key ID used for encryption                       |
| Filename length  | 2 bytes      | Big-endian `u16`                                       |
| Ciphertext       | variable     | Encrypted content + filename (as payload)              |

Unlike symmetric encryption, the ciphertext includes a key ID so the associated private key can be used.

---

### `.sig` — Signed File Format

| Field              | Size         | Description                                          |
|-------------------|--------------|------------------------------------------------------|
| Magic bytes       | 4 bytes      | `b"SIG1"` (format identifier for signatures)         |
| Asym Alg ID       | 1 byte       | Signing algorithm (e.g. RSA, Ed25519)                |
| Key ID length     | 1 byte       | Length of key ID in bytes                            |
| Key ID            | variable     | UTF-8 key ID used for signing                        |
| Filename length   | 2 bytes      | Big-endian `u16`, original filename                  |
| Filename          | variable     | UTF-8 bytes of original filename                     |
| Data length       | 8 bytes      | Big-endian `u64`, original input file size           |
| Data              | variable     | File contents                                        |
| Signature         | variable     | Signature over header + data                         |

The signature is generated over the **header and file content**, hashed and signed using the appropriate algorithm.

### `.enc` — Signed Encrypted File Format

Encrypted files may be wrapped in a signature using the `.enc` extension. These files combine the encrypted content with a signature. These have the same external header as a `.sig` file with `SIG2` as the magic bytes.

## Security Notes

- Uses for password-based key derivation configurable parameters, 16-byte salt, 32-byte derived key.
- Symmetric encryption with a 12-byte nonce and AEAD for integrity and confidentiality.
- Asymmetric encryption schemes with optional signing for authenticity
- Digital signatures use asymmetric keys and sign both file metadata and contents.
- Passwords and plaintext key material are **zeroized from memory** after use.

### Full List of Supported Algorithms

- **Key Derivation**
  - Argon2id
  - PBKDF2-HMAC-SHA256
- **Authenticated Symmetric Encryption and Decryption**
  - AES-256-GCM
  - CHACHA20-POLY1305
- **Asymmetric Encryption and Decryption**
  - X25519 (ECIES-style hybrid encryption)
  - RSA PKCS1v1.5
  - Kyber512 (Post-quantum KEM, hybrid encryption)
- **Asymmetric Signing and Verifying**
  - ECDSA-P256 (SHA256)
  - RSA PKCS1v1.5
  - Dilithium2 (Post-quantum signature scheme)
### File Storage Details

- `.enc` files:
  - **Symmetric mode** stores: salt, KDF parameters, AEAD algorithm ID, and original filename (encrypted), and ciphertext (encrypted).
  - **Asymmetric mode** stores: asymmetric key type, symmetric AEAD ID, key ID, filename (encrypted) and ciphertext (encrypted).
- `.sig` files:
  - Include: magic bytes (`SIG1`), signing algorithm ID, key ID, original filename, original file length, original data, and the signature.
  - The private signing key is **never stored**, only the **key ID** is embedded in the file.
  - The signature covers both metadata and the full file content to prevent tampering.

## Build Notes
Build production executable with:
```sh
cargo build --release
```

## License

This project is licensed under the [MIT License](LICENSE).
