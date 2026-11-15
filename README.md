# Secure Local Password Manager

A project I initially started to learn about encryption algorithms has evolved into something I now use myself. A secure, lightweight, and performance oriented local password manager built in Python using **Tkinter** for the graphical interface and the **`cryptography`** library for robust security. Designed with zero heavy dependencies or unnecessary animations.

## Cryptographic Architecture

1. **Key Derivation (KDF):** User master passwords are never stored. Instead, a strong 256-bit AES key is derived using **PBKDF2-HMAC-SHA256** with 100,000 iterations and a cryptographically secure random 16-byte salt.
2. **Authenticated Encryption (AEAD):** All stored credentials are encrypted using **AES-GCM (Galois/Counter Mode)**, ensuring confidentiality and integrity verification (detecting any tampering).
3. **Secret Generation:** Strong passwords are automatically generated using Python's cryptographically secure `secrets` module.

## Features

- **Performance-Oriented GUI:** Clean, lightweight Tkinter interface with zero bloat.
- **Multiple Accounts Support:** Store multiple usernames/passwords for the same service
  - `Ctrl + C`: Instantly copy selected password to clipboard.
  - `Ctrl + B`: Instantly copy selected username to clipboard.
  - `Enter`: Trigger actions quickly (Unlock, Save, etc.).
- **Standalone Packaging:** Can be compiled into a single executable file using PyInstaller.

## Prerequisites

- Python 3.7+
- `cryptography` library
- `pyperclip` library

## Installation & Running

1. Clone the repository and navigate to the project folder.
2. Install the required dependencies:
   ```bash
   pip install cryptography pyperclip

## Usage Terminal

 1. Initialize a new vault:
    ```bash
    python password_manager.py init
 
 2. Add a password (with auto generation and clipboard copy)
    ```bash
    python password_manager.py add -s [service.com] -u [user] --gen
    python password_manager.py add -s [service.com] -u [another_user] --gen

 3. Retrieve a password (automatically copies to clipboard)  !! do not forget to unlock to vault for this
    ```bash
    python password_manager.py get -s [service.com] -u [user]

 4. Generate a sandalone secure password
    ```bash
    python password_manager.py generate

## Usage Graphical Application
To start the app run:
```bash
python password_manager.py
```
If you want to run the app without openeing the terminal you can run these commands and this will create a executable that you can open with double click:
```bash
pip install pyinstaller
pyinstaller --onefile --noconsole password_manager_gui.py
```

## Security Note

The local vault file (vault.json) contains encrypted data and should never be committed to public version control systems. It is excluded via .gitignore.