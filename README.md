# File Encryption

A command-line tool to encrypt and decrypt files using AES-256-GCM and Argon2 password-based key derivation. Encrypted files are stored in a directory containing the ciphertext, salt, nonce, and original filename.

In the past I had used GPG to password encrypt files but I was looking over its protcols and noticed that it uses a somewhat dated KDF and does not include authenticated encryption, this fills those gaps.

## Features

- **AES-256-GCM** for authenticated encryption
- **Argon2** for secure password-based key derivation
- Secure random salt and nonce generation
- Memory zeroization of sensitive data
- Password verification during encryption
- Original filename preservation

## Dependencies

- [aes-gcm](https://crates.io/crates/aes-gcm)
- [argon2](https://crates.io/crates/argon2)
- [rand](https://crates.io/crates/rand)
- [zeroize](https://crates.io/crates/zeroize)
- [rpassword](https://crates.io/crates/rpassword)
- [clap](https://crates.io/crates/clap)

## Usage

### Encrypt a file

```sh
cargo run --release -- encrypt path/to/file.txt
```
or
```sh
cargo run --release -- e path/to/file.txt
```

- You will be prompted to enter and confirm a password.
- The tool will create a directory named after your file (without extension) in the same location, containing:
  - `ciphertext.bin` (the encrypted data)
  - `salt.bin` (the random salt)
  - `nonce.bin` (the random nonce)
  - `original_filename.txt` (the original filename)

### Decrypt a file

```sh
cargo run --release -- decrypt path/to/file
```
or
```sh
cargo run --release -- d path/to/file
```

- You will be prompted for the password used during encryption.
- The tool will write the decrypted file into the same directory, using the original filename.


## Security Notes

- Uses **Argon2** for password-based key derivation (16-byte salt, 32-byte key).
- Uses **AES-256-GCM** for encryption (12-byte nonce).
- Passwords and keys are zeroized from memory after use.
- The salt and nonce are stored unencrypted alongside the ciphertext; this is standard and necessary for decryption.





