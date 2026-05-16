"""Master password lifecycle: setup, unlock, audit logging hooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import database as db
from encryption import encrypt_auth_verifier, generate_salt, verify_master_password

if TYPE_CHECKING:
    from cryptography.fernet import Fernet


@dataclass
class Session:
    """Holds runtime unlock state. Do not persist cipher or master password."""

    user_id: int
    salt: bytes
    cipher: "Fernet"


def is_first_run() -> bool:
    return not db.database_exists() or not db.has_any_user()


def setup_master_password(master_password: str) -> Session:
    """
    First-time setup: create DB, salt, encrypted verifier, default settings.
    The master password is never written to disk—only salt + encrypted challenge.
    """
    db.initialize_database()
    salt = generate_salt()
    verifier = encrypt_auth_verifier(master_password, salt)
    user_id = db.create_user(salt, verifier)
    db.ensure_default_categories(user_id)
    from encryption import create_cipher

    cipher = create_cipher(master_password, salt)
    return Session(user_id=user_id, salt=salt, cipher=cipher)


def unlock(master_password: str) -> Session | None:
    row = db.get_primary_user()
    if row is None:
        return None
    user_id, salt, verifier = row
    ok = verify_master_password(master_password, salt, verifier)
    db.append_audit(user_id, "login_success" if ok else "login_failure", None)
    if not ok:
        return None
    from encryption import create_cipher

    return Session(user_id=user_id, salt=salt, cipher=create_cipher(master_password, salt))


def change_master_password(
    session: Session,
    old_password: str,
    new_password: str,
) -> bool:
    """Re-encrypt all entry blobs with a new key; update verifier and salt."""
    if not verify_master_password(old_password, session.salt, db.get_user_verifier(session.user_id)):
        return False
    new_salt = generate_salt()
    new_verifier = encrypt_auth_verifier(new_password, new_salt)
    from encryption import create_cipher

    new_cipher = create_cipher(new_password, new_salt)
    entries = db.list_entry_rows(session.user_id)
    for eid, blob in entries:
        from encryption import decrypt_entry_payload, encrypt_entry_payload

        payload = decrypt_entry_payload(session.cipher, blob)
        new_blob = encrypt_entry_payload(new_cipher, payload)
        db.update_entry_blob(session.user_id, eid, new_blob)
    db.update_user_crypto(session.user_id, new_salt, new_verifier)
    session.salt = new_salt
    session.cipher = new_cipher
    db.append_audit(session.user_id, "master_password_changed", None)
    return True
