🔐 Password Manager

A lightweight command-line password manager written in Python by safouane02
.
Passwords are encrypted locally — nothing ever leaves your machine.

Features

AES-256 encryption via cryptography (Fernet + PBKDF2HMAC key derivation)

Strong password generator — letters, digits, symbols, configurable length

Clipboard copy — paste passwords without typing them

CRUD operations — add, view, update, delete entries

Single master password — unlocks the entire vault

Quick start
# 1. Clone the repo
git clone https://github.com/safouane02/password-manager.git
cd password-manager

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python password_manager.py

On first run you'll be prompted to set a master password.
The encrypted vault is stored at ~/.pm_vault.json.

Dependencies
Package	Purpose
cryptography	Fernet encryption + PBKDF2 key derivation
pyperclip	Cross-platform clipboard access
Security notes

The master password is never stored — only used to derive the encryption key.

Key derivation uses PBKDF2-HMAC-SHA256 with 480,000 iterations.

A random 16-byte salt is generated once and saved to ~/.pm_salt.bin.

Vault file (~/.pm_vault.json) is fully encrypted; it contains no plaintext.

License

MIT