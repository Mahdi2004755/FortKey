"""SQLite persistence: encrypted blobs only for secrets, settings, audit."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Generator

from utils import database_path


def database_exists() -> bool:
    return database_path().exists()


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    path = database_path()
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database() -> None:
    database_path().parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                UNIQUE(user_id, name)
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                payload_enc BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS settings (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_entries_user ON entries(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
            """
        )


def has_any_user() -> bool:
    if not database_exists():
        return False
    with get_connection() as conn:
        row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None


def create_user(salt: bytes, verifier: bytes) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (salt, verifier) VALUES (?, ?)",
            (salt, verifier),
        )
        uid = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO settings (user_id, json) VALUES (?, ?)",
            (uid, json.dumps({"dark_mode": True, "auto_lock_minutes": 5})),
        )
        return uid


def get_primary_user() -> tuple[int, bytes, bytes] | None:
    with get_connection() as conn:
        row = conn.execute("SELECT id, salt, verifier FROM users ORDER BY id LIMIT 1").fetchone()
        if row is None:
            return None
        return int(row["id"]), bytes(row["salt"]), bytes(row["verifier"])


def get_user_verifier(user_id: int) -> bytes:
    with get_connection() as conn:
        row = conn.execute("SELECT verifier FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise ValueError("user not found")
        return bytes(row["verifier"])


def update_user_crypto(user_id: int, salt: bytes, verifier: bytes) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET salt = ?, verifier = ? WHERE id = ?",
            (salt, verifier, user_id),
        )


def ensure_default_categories(user_id: int) -> None:
    defaults = ["General", "Work", "Personal", "Finance", "Social"]
    with get_connection() as conn:
        for name in defaults:
            conn.execute(
                "INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)",
                (user_id, name),
            )


def list_categories(user_id: int) -> list[tuple[int, str]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name FROM categories WHERE user_id = ? ORDER BY name",
            (user_id,),
        ).fetchall()
        return [(int(r["id"]), str(r["name"])) for r in rows]


def add_category(user_id: int, name: str) -> int:
    name = name.strip()
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)",
            (user_id, name),
        )
        row = conn.execute(
            "SELECT id FROM categories WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if row is None:
            raise RuntimeError("failed to resolve category")
        return int(row["id"])


def delete_category(user_id: int, category_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE entries SET category_id = NULL WHERE user_id = ? AND category_id = ?",
            (user_id, category_id),
        )
        conn.execute(
            "DELETE FROM categories WHERE user_id = ? AND id = ?",
            (user_id, category_id),
        )


def load_settings(user_id: int) -> dict[str, Any]:
    with get_connection() as conn:
        row = conn.execute("SELECT json FROM settings WHERE user_id = ?", (user_id,)).fetchone()
        if row is None:
            return {}
        return json.loads(row["json"])


def save_settings(user_id: int, data: dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE settings SET json = ? WHERE user_id = ?",
            (json.dumps(data), user_id),
        )


def append_audit(user_id: int, event: str, detail: str | None) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (user_id, event, detail) VALUES (?, ?, ?)",
            (user_id, event, detail),
        )


def list_audit(user_id: int, limit: int = 200) -> list[tuple[str, str | None, str]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT event, detail, created_at FROM audit_log
            WHERE user_id = ? ORDER BY id DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [(str(r["event"]), r["detail"], str(r["created_at"])) for r in rows]


def insert_entry(user_id: int, category_id: int | None, payload_enc: bytes) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO entries (user_id, category_id, payload_enc)
            VALUES (?, ?, ?)
            """,
            (user_id, category_id, payload_enc),
        )
        return int(cur.lastrowid)


def update_entry(
    user_id: int,
    entry_id: int,
    category_id: int | None,
    payload_enc: bytes,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE entries
            SET category_id = ?, payload_enc = ?, updated_at = datetime('now')
            WHERE user_id = ? AND id = ?
            """,
            (category_id, payload_enc, user_id, entry_id),
        )


def update_entry_blob(user_id: int, entry_id: int, payload_enc: bytes) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE entries SET payload_enc = ?, updated_at = datetime('now')
            WHERE user_id = ? AND id = ?
            """,
            (payload_enc, user_id, entry_id),
        )


def delete_entry(user_id: int, entry_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM entries WHERE user_id = ? AND id = ?", (user_id, entry_id))


def list_entry_rows(user_id: int) -> list[tuple[int, bytes]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, payload_enc FROM entries WHERE user_id = ?",
            (user_id,),
        ).fetchall()
        return [(int(r["id"]), bytes(r["payload_enc"])) for r in rows]


def list_entries_for_user(user_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT e.id, e.category_id, e.created_at, e.updated_at, e.payload_enc, c.name AS category_name
            FROM entries e
            LEFT JOIN categories c ON c.id = e.category_id
            WHERE e.user_id = ?
            ORDER BY e.updated_at DESC
            """,
            (user_id,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "id": int(r["id"]),
                    "category_id": r["category_id"],
                    "created_at": str(r["created_at"]),
                    "updated_at": str(r["updated_at"]),
                    "category_name": r["category_name"],
                    "payload_enc": bytes(r["payload_enc"]),
                }
            )
        return out
