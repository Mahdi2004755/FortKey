"""
Symmetric encryption for vault records using Fernet (AES-128-CBC + HMAC-SHA256).

The master password never leaves memory as plaintext longer than needed; we derive
a Fernet key with PBKDF2-HMAC-SHA256 and a random salt stored on disk.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP-style iteration count for PBKDF2 (tune for slower machines if needed).
PBKDF2_ITERATIONS = 390_000
SALT_SIZE = 16
KEY_LENGTH = 32

# Fixed plaintext used only to verify the derived key matches setup (never stored in plaintext).
_AUTH_CHALLENGE = b"fortkey_master_auth_v1"


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    """Derive a URL-safe 32-byte key suitable for Fernet from the master password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def create_cipher(master_password: str, salt: bytes) -> Fernet:
    return Fernet(derive_fernet_key(master_password, salt))


def encrypt_auth_verifier(master_password: str, salt: bytes) -> bytes:
    """Produce ciphertext proving knowledge of the master password (stored instead of the password)."""
    f = create_cipher(master_password, salt)
    return f.encrypt(_AUTH_CHALLENGE)


def verify_master_password(master_password: str, salt: bytes, verifier: bytes) -> bool:
    """Return True if master_password matches the verifier created at setup."""
    try:
        f = create_cipher(master_password, salt)
        pt = f.decrypt(verifier)
        return pt == _AUTH_CHALLENGE
    except InvalidToken:
        return False


def encrypt_entry_payload(cipher: Fernet, payload: dict[str, Any]) -> bytes:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return cipher.encrypt(data)


def decrypt_entry_payload(cipher: Fernet, blob: bytes) -> dict[str, Any]:
    data = cipher.decrypt(blob)
    return json.loads(data.decode("utf-8"))


def encrypt_bytes(cipher: Fernet, data: bytes) -> bytes:
    return cipher.encrypt(data)


def decrypt_bytes(cipher: Fernet, blob: bytes) -> bytes:
    return cipher.decrypt(blob)


def create_export_cipher(export_password: str, salt: bytes) -> Fernet:
    """Separate salt for backup files so export passphrase is independent of master salt."""
    return Fernet(derive_fernet_key(export_password, salt))


def encrypt_backup_blob(export_password: str, inner_json: dict[str, Any]) -> bytes:
    salt = generate_salt()
    cipher = create_export_cipher(export_password, salt)
    payload = json.dumps(inner_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    body = cipher.encrypt(payload)
    return salt + body


def decrypt_backup_blob(export_password: str, blob: bytes) -> dict[str, Any]:
    if len(blob) < SALT_SIZE + 16:
        raise ValueError("Invalid backup file")
    salt, body = blob[:SALT_SIZE], blob[SALT_SIZE:]
    cipher = create_export_cipher(export_password, salt)
    data = cipher.decrypt(body)
    return json.loads(data.decode("utf-8"))
