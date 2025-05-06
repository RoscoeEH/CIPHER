# CIPHER: Command-line Interface for Protection, Hardening, and Endpoint Reinforcement

A command-line tool to encrypt and decrypt files using AES-256-GCM and Argon2 password-based key derivation. Encrypted files are stored in a single `.enc` file containing all necessary decryption parameters and the ciphertext.

In the past I had used GPG to password encrypt files but I was looking over its protocols and noticed that it uses a somewhat dated KDF and does not include authenticated encryption. This tool fills those gaps.

## Features

- **AES-256-GCM** for authenticated encryption
- **Argon2** for secure password-based key derivation
- Secure random salt and nonce generation
- Memory zeroization of sensitive data
- Password verification during encryption
- Original filename embedded in the encrypted file
- All encrypted data stored in a single `.enc` file

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
- The tool will create a file named after your input, but with a `.enc` extension (e.g., `file.txt.enc`).
- The `.enc` file contains all information needed for decryption: salt, nonce, original filename, and ciphertext.

You can optionally specify an output path (without `.enc`) using the third argument:

```sh
cargo run --release -- e path/to/file.txt path/to/output/file
```
This will produce `path/to/output/file.enc`.

### Decrypt a file

```sh
cargo run --release -- decrypt path/to/file.txt.enc
```
or
```sh
cargo run --release -- d path/to/file.txt.enc
```

- You will be prompted for the password used during encryption.
- The tool will write the decrypted file in the same directory, using the original filename embedded in the `.enc` file.

## File Format

The `.enc` file is a custom binary format with the following structure:

| Field            | Size         | Description                                 |
|------------------|--------------|---------------------------------------------|
| Magic bytes      | 4 bytes      | `b"ENC1"` (format identifier)               |
| Salt             | 16 bytes     | Random salt for Argon2 key derivation       |
| Nonce            | 12 bytes     | Random nonce for AES-GCM                    |
| Filename length  | 2 bytes      | Big-endian unsigned integer (u16)           |
| Filename         | variable     | UTF-8 encoded original filename             |
| Ciphertext       | variable     | Encrypted file data (AES-GCM)               |

All fields are concatenated in the above order.

## Security Notes

- Uses **Argon2** for password-based key derivation (16-byte salt, 32-byte key).
- Uses **AES-256-GCM** for encryption (12-byte nonce).
- Passwords and keys are zeroized from memory after use.
- The salt, nonce, and original filename are stored unencrypted in the `.enc` file.

## Other Notes

1. **To create an independently useful executable**, run the following command:

```sh
cargo build --release
```

This will generate the optimized executable in the `target/release` directory. Store a copy of the resulting executable at a location of your choice.

2. **Using Bash Scripts for Encryption and Decryption**

After building the executable, you can use the following Bash functions to encrypt and decrypt files:

**Encrypting a File**:
```bash
encrypt-file() {
  local fullpath
  fullpath="$(realpath "$1")" || return 1
  /path/to/executable encrypt "$fullpath"
}
```

**Decrypting a File**:
```bash
decrypt-file() {
  local fullpath
  fullpath="$(realpath "$1")" || return 1
  /path/to/executable decrypt "$fullpath"
}
```
