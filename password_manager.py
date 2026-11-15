import os
import json
import base64
import secrets
import string
import argparse
import pyperclip
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecurePasswordManager:
    """
    Core cryptographic backend for the local password manager.
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

    def initialize_vault(self, master_password: str) -> bool:
        """Initializes a new encrypted vault file with the given master password."""
        if os.path.exists(self.storage_file):
            return False

        salt = os.urandom(16)
        vault_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_data": ""
        }
        self._save_vault_file(vault_data)
        return True

    def _load_and_decrypt_vault(self, master_password: str) -> dict:
        """Loads and decrypts the vault using the master password."""
        if not os.path.exists(self.storage_file):
            return None

        vault_data = self._load_vault_file()
        salt = base64.b64decode(vault_data["salt"])
        key = self._derive_key(master_password, salt)

        if not vault_data.get("encrypted_data"):
            return {}

        try:
            data = base64.b64decode(vault_data["encrypted_data"].encode('utf-8'))
            nonce = data[:12]
            ciphertext = data[12:]
            
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted_bytes.decode('utf-8'))
        
        except (InvalidTag, Exception):
            return None

    def save_passwords(self, master_password: str, passwords: dict) -> bool:
        """Encrypts and saves the password dictionary to disk."""
        vault_data = self._load_vault_file()
        if not vault_data:
            return False
            
        salt = base64.b64decode(vault_data["salt"])
        key = self._derive_key(master_password, salt)

        json_bytes = json.dumps(passwords).encode('utf-8')
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, json_bytes, None)

        encrypted_payload = base64.b64encode(nonce + ciphertext).decode('utf-8')
        vault_data["encrypted_data"] = encrypted_payload
        
        self._save_vault_file(vault_data)
        return True

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


class PasswordManagerGUI:
    """
    Lightweight, performance-oriented Tkinter GUI with custom keyboard shortcuts for quick copying.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("600x600")
        self.root.resizable(True, True)

        self.manager = SecurePasswordManager()
        self.master_password = None
        self.passwords = {}

        self.build_auth_screen()

    def clear_window(self):
        """Destroys all current widgets in the window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_auth_screen(self):
        """Builds the Vault Initialization / Unlock Screen with Enter-key binding."""
        self.clear_window()

        is_existing = os.path.exists("vault.json")
        title_text = "Unlock Existing Vault" if is_existing else "Initialize New Vault"

        tk.Label(self.root, text=title_text, font=("Arial", 14, "bold")).pack(pady=20)

        tk.Label(self.root, text="Master Password:", font=("Arial", 10)).pack(pady=5)
        self.pass_entry = tk.Entry(self.root, show="*", width=32, font=("Arial", 11))
        self.pass_entry.pack(pady=5)
        self.pass_entry.focus()

        if not is_existing:
            tk.Label(self.root, text="Confirm Master Password:", font=("Arial", 10)).pack(pady=5)
            self.confirm_entry = tk.Entry(self.root, show="*", width=32, font=("Arial", 11))
            self.confirm_entry.pack(pady=5)
            btn_text = "Create Vault"
            btn_command = self.handle_init
        else:
            btn_text = "Unlock Vault"
            btn_command = self.handle_unlock

        btn = tk.Button(self.root, text=btn_text, width=22, bg="#2E7D32", fg="white", font=("Arial", 10, "bold"), command=btn_command)
        btn.pack(pady=20)

        self.root.bind('<Return>', lambda event: btn_command())

    def handle_init(self):
        """Handles new vault creation from GUI."""
        p1 = self.pass_entry.get()
        p2 = self.confirm_entry.get()

        if not p1 or p1 != p2:
            messagebox.showerror("Error", "Passwords do not match or are empty!")
            return

        if self.manager.initialize_vault(p1):
            messagebox.showinfo("Success", "Vault successfully created!")
            self.master_password = p1
            self.passwords = {}
            self.root.unbind('<Return>')
            self.build_main_screen()
        else:
            messagebox.showerror("Error", "Vault already exists.")

    def handle_unlock(self):
        """Handles unlocking existing vault from GUI."""
        password = self.pass_entry.get()
        decrypted_data = self.manager._load_and_decrypt_vault(password)

        if decrypted_data is not None:
            self.master_password = password
            self.passwords = decrypted_data
            self.root.unbind('<Return>')
            self.build_main_screen()
        else:
            messagebox.showerror("Error", "Incorrect Master Password!")

    def build_main_screen(self):
        """Builds the main dashboard screen after successful unlock with keyboard bindings."""
        self.clear_window()

        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=10, fill=tk.X, padx=20)

        tk.Label(top_frame, text="Stored Credentials", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        tk.Button(top_frame, text="Lock Vault", bg="#616161", fg="white", font=("Arial", 9), command=self.build_auth_screen).pack(side=tk.RIGHT)

        list_frame = tk.Frame(self.root)
        list_frame.pack(pady=5)

        self.listbox = tk.Listbox(list_frame, width=54, height=12, font=("Arial", 10))
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH)
        self.listbox.focus_set() # Focus on listbox so shortcuts work immediately

        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)

        self.refresh_listbox()

        # Bind keyboard shortcuts to the listbox
        # Ctrl+C -> Copy Password, Ctrl+B -> Copy Username
        self.listbox.bind('<Control-k>', lambda event: self.copy_selected_password())
        self.listbox.bind('<Control-K>', lambda event: self.copy_selected_password())
        self.listbox.bind('<Control-b>', lambda event: self.copy_selected_username())
        self.listbox.bind('<Control-B>', lambda event: self.copy_selected_username())

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="➕ Add Entry", width=14, bg="#1976D2", fg="white", font=("Arial", 9, "bold"), command=self.open_add_dialog).grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="📋 Copy Password", width=14, bg="#F57C00", fg="white", font=("Arial", 9, "bold"), command=self.copy_selected_password).grid(row=0, column=1, padx=6)
        tk.Button(btn_frame, text="🗑️ Delete Entry", width=14, bg="#D32F2F", fg="white", font=("Arial", 9, "bold"), command=self.delete_selected_entry).grid(row=0, column=2, padx=6)

    def refresh_listbox(self):
        """Refreshes the entries displayed in the listbox."""
        self.listbox.delete(0, tk.END)
        for record_key, data in self.passwords.items():
            service = data.get('service', record_key.split(' | ')[0] if ' | ' in record_key else record_key)
            username = data.get('username', 'N/A')
            self.listbox.insert(tk.END, f"{service}  —  ({username})")

    def open_add_dialog(self):
        """Opens a popup dialog to add a new credential."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Credential")
        dialog.geometry("360x320")
        dialog.resizable(True, True)
        dialog.grab_set()

        tk.Label(dialog, text="Service Name (e.g., github.com):", font=("Arial", 9)).pack(anchor="w", padx=20, pady=(15, 5))
        srv_entry = tk.Entry(dialog, width=34, font=("Arial", 10))
        srv_entry.pack(padx=20)
        srv_entry.focus()

        tk.Label(dialog, text="Username / Email:", font=("Arial", 9)).pack(anchor="w", padx=20, pady=(10, 5))
        usr_entry = tk.Entry(dialog, width=34, font=("Arial", 10))
        usr_entry.pack(padx=20)

        tk.Label(dialog, text="Password (leave blank to auto-generate):", font=("Arial", 9)).pack(anchor="w", padx=20, pady=(10, 5))
        pwd_entry = tk.Entry(dialog, width=34, show="*", font=("Arial", 10))
        pwd_entry.pack(padx=20)

        def save_entry():
            service = srv_entry.get().strip()
            username = usr_entry.get().strip()
            password = pwd_entry.get().strip()

            if not service or not username:
                messagebox.showerror("Error", "Service and Username are required!", parent=dialog)
                return

            if not password:
                password = generate_strong_password()
                messagebox.showinfo("Generated", f"Strong password generated & copied!", parent=dialog)
                pyperclip.copy(password)

            record_key = f"{service} | {username}"
            self.passwords[record_key] = {
                "service": service,
                "username": username,
                "password": password
            }

            if self.manager.save_passwords(self.master_password, self.passwords):
                self.refresh_listbox()
                dialog.destroy()
                messagebox.showinfo("Success", "Credential saved successfully!")
            else:
                messagebox.showerror("Error", "Failed to save to vault.", parent=dialog)

        save_btn = tk.Button(dialog, text="💾 Save Credential", width=22, bg="#2E7D32", fg="white", font=("Arial", 9, "bold"), command=save_entry)
        save_btn.pack(pady=20)
        
        dialog.bind('<Return>', lambda event: save_entry())

    def copy_selected_password(self):
        """Copies the password of the selected item in the listbox to clipboard (Ctrl+C)."""
        selected_idx = self.listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select an entry from the list first.")
            return

        record_keys = list(self.passwords.keys())
        target_key = record_keys[selected_idx[0]]
        password = self.passwords[target_key]['password']

        pyperclip.copy(password)

    def copy_selected_username(self):
        """Copies the username of the selected item in the listbox to clipboard (Ctrl+B)."""
        selected_idx = self.listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select an entry from the list first.")
            return

        record_keys = list(self.passwords.keys())
        target_key = record_keys[selected_idx[0]]
        username = self.passwords[target_key]['username']

        pyperclip.copy(username)

    def delete_selected_entry(self):
        """Deletes the selected credential entry after confirmation."""
        selected_idx = self.listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Warning", "Please select an entry to delete first.")
            return

        record_keys = list(self.passwords.keys())
        target_key = record_keys[selected_idx[0]]

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete this entry?"):
            del self.passwords[target_key]
            if self.manager.save_passwords(self.master_password, self.passwords):
                self.refresh_listbox()
                messagebox.showinfo("Success", "Entry deleted successfully!")
            else:
                messagebox.showerror("Error", "Failed to update vault.")


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()