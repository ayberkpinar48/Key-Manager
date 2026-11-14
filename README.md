# Secure Local Command-Line Password Manager

A secure, lightweight local password manager built in Python. It implements cryptographic best practices including key derivation functions and authenticated encryption to protect sensitive user credentials.

## Cryptographic Architecture

1. **Key Derivation (KDF):** User master passwords are never stored. Instead, a strong 256-bit AES key is derived using **PBKDF2-HMAC-SHA256** with 100,000 iterations and a cryptographically secure random 16-byte salt.
2. **Authenticated Encryption (AEAD):** All stored credentials are encrypted using **AES-GCM (Galois/Counter Mode)**. This ensures both confidentiality and data integrity (detecting any tampering or unauthorized modifications).
3. **Secret Generation:** Standalone and automatic strong passwords are generated using Python's cryptographically secure `secrets` module.
4. **Secure Input:** Master passwords and secrets are securely read from the terminal without echoing using the `getpass` module.

## Prerequisites

- Python 3.7+
- `cryptography` library
- `pyperclip` library (for clipboard support)

## Installation

1. Clone the repository and navigate to the project folder.
2. Install the required dependencies:
   ```bash
   pip install cryptography pyperclip