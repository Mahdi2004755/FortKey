# FortKey (application package)

Application code for **FortKey** lives in this directory. See the [repository README](../README.md) for setup, run instructions, and security notes.

Quick start:

```bash
cd fortkey
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
pip install -r requirements.txt
python main.py
```

Database file: `~/.fortkey/vault.db` (Windows: `%USERPROFILE%\.fortkey\vault.db`).
