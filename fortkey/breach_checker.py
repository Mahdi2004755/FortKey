"""Offline breach-style checks: common list, reuse, composition rules."""

from __future__ import annotations

import re
from pathlib import Path

# Small embedded top-passwords sample (public domain style list); extend locally as needed.
_COMMON_PASSWORDS = {
    "password",
    "password1",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "shadow",
    "michael",
    "mustang",
    "trustno1",
    "superman",
    "654321",
    "batman",
    "passw0rd",
    "hunter2",
    "master",
    "login",
}


def load_common_passwords_file(path: Path | None) -> set[str]:
    """Optional extra wordlist (one password per line, lowercase compared)."""
    words: set[str] = set(_COMMON_PASSWORDS)
    if path and path.is_file():
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                w = line.strip().lower()
                if w:
                    words.add(w)
        except OSError:
            pass
    return words


def analyze_password(
    password: str,
    *,
    all_vault_passwords: list[str],
    common_extra_path: Path | None = None,
) -> list[str]:
    """
    Return human-readable issues (empty list = no issues flagged by local rules).
    """
    issues: list[str] = []
    common = load_common_passwords_file(common_extra_path)
    lower = password.lower()
    if lower in common:
        issues.append("Matches a common password dictionary entry.")
    if len(password) < 12:
        issues.append("Shorter than 12 characters (recommended minimum).")
    if not re.search(r"\d", password):
        issues.append("Contains no digits.")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>/?]", password):
        issues.append("Contains no symbols.")
    repeats = sum(1 for p in all_vault_passwords if p == password)
    if repeats > 1:
        issues.append("Same password is reused for multiple vault entries.")
    if len(password) < 8:
        issues.append("Very short password (under 8 characters).")
    return issues
