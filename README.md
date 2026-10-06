# FortKey

FortKey is a **local-first** password manager for Windows, macOS, and Linux. Your master password is never stored on disk; vault records are encrypted with **Fernet** (AES-128-CBC + HMAC-SHA256) from the **cryptography** library before being written to **SQLite**.

## Features

- Master password setup with PBKDF2-HMAC-SHA256 key derivation and an encrypted verifier (no plaintext master on disk).
- Encrypted vault entries (website, username, password, notes, category, timestamps).
- Password generator with strength labels and optional confusing-character exclusion.
- Dashboard: search, category filter, copy username/password, edit/delete, reveal with confirmation.
- Auto-lock after inactivity; manual lock returns to login.
- Offline breach-style checks (common passwords, reuse, composition heuristics).
- Encrypted backup export/import (`.svv` files use a separate export passphrase).
- Settings: dark mode, audit log, master password rotation.

## Requirements

- Python **3.10+**
- Tkinter (included with most Windows/macOS Python builds; on Linux install `python3-tk` if needed).

## Setup

```bash
cd fortkey
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

From the `fortkey` directory:

```bash
python main.py
```

On first launch, create a **strong master password** (at least 10 characters). The database is stored at:

- Windows: `%USERPROFILE%\.fortkey\vault.db`
- macOS / Linux: `~/.fortkey/vault.db`

## Sample data

The `fortkey/demo_import.svv` file is an encrypted backup with three fictional entries.

1. Complete setup with your master password and unlock.
2. **Vault → Import encrypted backup…** → select `demo_import.svv`.
3. Export passphrase: **`DemoImport2024!`**

## Security notes

- Vault passwords are stored only as Fernet ciphertext in SQLite.
- Clipboard is cleared on a timer after copying passwords.
- The offline “breach checker” does not call external APIs.

## Layout

| Path | Role |
|------|------|
| `fortkey/main.py` | Application entry |
| `fortkey/database.py` | SQLite |
| `fortkey/auth.py` | Master password lifecycle |
| `fortkey/encryption.py` | PBKDF2 + Fernet + backups |
| `fortkey/password_generator.py` | Generator + strength |
| `fortkey/breach_checker.py` | Local heuristics |
| `fortkey/gui.py` | Tkinter UI |
| `fortkey/utils.py` | Paths, clipboard helpers |

## License

Use at your own risk; no warranty. 
All Rights Reserved.
