import os
import json
import base64
import secrets
import string
import getpass
import argparse
import pyperclip
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecurePasswordManager:
    """
    A secure, local command-line password manager implementing PBKDF2 
    for key derivation and AES-GCM for authenticated encryption.
    Supports multiple accounts per service via unique service-username keys.
    """
    def __init__(self, storage_file="vault.json"):
        self.storage_file = storage_file

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from the master password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(master_password.encode())

    def initialize_vault(self):
        """Initializes a new encrypted vault file."""
        if os.path.exists(self.storage_file):
            print("\n[-] Vault already exists! Delete 'vault.json' if you want to create a new one.")
            return

        master_password = getpass.getpass("Enter a strong Master Password: ")
        confirm_password = getpass.getpass("Confirm Master Password: ")

        if master_password != confirm_password:
            print("\n[-] Passwords do not match! Vault creation aborted.")
            return

        # Generate a cryptographically secure random salt (16 bytes)
        salt = os.urandom(16)
        
        # Save salt and empty encrypted payload container
        vault_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_data": ""
        }
        self._save_vault_file(vault_data)
        print("\n[+] Vault successfully created and initialized!")

    def _load_and_decrypt_vault(self, master_password: str) -> dict:
        """Loads the vault file, verifies the master password, and returns decrypted passwords."""
        if not os.path.exists(self.storage_file):
            print("\n[-] Vault file not found. Run 'init' first.")
            return None

        vault_data = self._load_vault_file()
        salt = base64.b64decode(vault_data["salt"])
        key = self._derive_key(master_password, salt)

        if not vault_data.get("encrypted_data"):
            return {} # Vault is empty, but password is valid

        try:
            data = base64.b64decode(vault_data["encrypted_data"].encode('utf-8'))
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_bytes.decode('utf-8'))
        
        except (InvalidTag, Exception):
            print("\n[-] Incorrect master password or corrupted vault file!")
            return None

    def add_password(self, service: str, username: str, password: str):
        """Adds or updates a credential using a composite key (service + username)."""
        master_password = getpass.getpass("Enter Master Password to unlock vault: ")
        passwords = self._load_and_decrypt_vault(master_password)
        
        if passwords is None:
            return

        # Use a composite key to allow multiple accounts per service without overwriting
        record_key = f"{service} | {username}"
        passwords[record_key] = {"service": service, "username": username, "password": password}

        # Re-encrypt everything with a freshly derived key and existing salt
        vault_data = self._load_vault_file()
        salt = base64.b64decode(vault_data["salt"])
        key = self._derive_key(master_password, salt)

        json_bytes = json.dumps(passwords).encode('utf-8')
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json_bytes, None)

        encrypted_payload = base64.b64encode(nonce + ciphertext).decode('utf-8')
        vault_data["encrypted_data"] = encrypted_payload
        
        self._save_vault_file(vault_data)
        print(f"\n[+] Credentials for '{service}' ({username}) successfully saved.")

    def get_password(self, service: str, username: str = None):
        """Retrieves and displays service credentials. If multiple exist, username is required."""
        master_password = getpass.getpass("Enter Master Password to unlock vault: ")
        passwords = self._load_and_decrypt_vault(master_password)
        
        if passwords is None:
            return

        # Filter records matching the requested service
        matching_records = [v for k, v in passwords.items() if v.get("service") == service]

        if not matching_records:
            print(f"\n[-] No records found for service '{service}'.")
            return

        # If multiple accounts exist for this service and no specific username was given
        if len(matching_records) > 1 and not username:
            print(f"\n[!] Multiple accounts found for '{service}':")
            for rec in matching_records:
                print(f"    - Username: {rec['username']}")
            print("[-] Please specify a username using the -u/--username flag.")
            return

        # Find the specific target record
        target_record = None
        if username:
            for rec in matching_records:
                if rec['username'] == username:
                    target_record = rec
                    break
        else:
            target_record = matching_records[0]

        if target_record:
            pwd = target_record['password']
            print(f"\n--- [ {target_record['service']} ({target_record['username']}) ] ---")
            print(f"Username : {target_record['username']}")
            print(f"Password : [Copied to Clipboard]")
            print("-" * 35)
            pyperclip.copy(pwd)
        else:
            print(f"\n[-] No record found for service '{service}' with username '{username}'.")

    def _save_vault_file(self, data):
        with open(self.storage_file, "w") as f:
            json.dump(data, f, indent=4)

    def _load_vault_file(self):
        with open(self.storage_file, "r") as f:
            return json.load(f)


def generate_strong_password(length=16) -> str:
    """Generates a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            return password


def main():
    parser = argparse.ArgumentParser(description="Secure Local Command-Line Password Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    subparsers.add_parser("init", help="Initialize a new encrypted vault")

    # add command
    add_parser = subparsers.add_parser("add", help="Add or update a password entry")
    add_parser.add_argument("-s", "--service", required=True, help="Service name (e.g., github.com)")
    add_parser.add_argument("-u", "--username", required=True, help="Username or email")
    add_parser.add_argument("--gen", action="store_true", help="Automatically generate a strong password and copy it")

    # get command
    get_parser = subparsers.add_parser("get", help="Retrieve a password entry")
    get_parser.add_argument("-s", "--service", required=True, help="Service name to look up")
    get_parser.add_argument("-u", "--username", required=False, help="Specific username (required if multiple accounts exist)")

    # generate command
    subparsers.add_parser("generate", help="Generate a standalone strong random password")

    args = parser.parse_args()
    manager = SecurePasswordManager()

    if args.command == "init":
        manager.initialize_vault()

    elif args.command == "add":
        if args.gen:
            password = generate_strong_password()
            pyperclip.copy(password)
            print(f"\n[+] Generated Strong Password & Copied to Clipboard: {password}")
        else:
            password = getpass.getpass("Enter password to store: ")
        manager.add_password(args.service, args.username, password)

    elif args.command == "get":
        manager.get_password(args.service, args.username)

    elif args.command == "generate":
        strong_pwd = generate_strong_password()
        pyperclip.copy(strong_pwd)
        print(f"\n[+] Generated & Copied Secure Password: {strong_pwd}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()