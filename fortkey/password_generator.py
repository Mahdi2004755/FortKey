"""Configurable password generation and strength scoring."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
# Printable ASCII symbols; user can exclude confusing subset.
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>/?"


@dataclass
class GeneratorOptions:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_confusing: bool = True


CONFUSING = set("0O1Il5S2Z")


def _filtered_pool(opts: GeneratorOptions) -> str:
    pools: list[str] = []
    if opts.use_lower:
        pools.append(LOWER)
    if opts.use_upper:
        pools.append(UPPER)
    if opts.use_digits:
        pools.append(DIGITS)
    if opts.use_symbols:
        pools.append(SYMBOLS)
    if not pools:
        pools.append(LOWER)
    alphabet = "".join(pools)
    if opts.exclude_confusing:
        alphabet = "".join(ch for ch in alphabet if ch not in CONFUSING)
    if not alphabet:
        alphabet = LOWER
    return alphabet


def generate_password(opts: GeneratorOptions) -> str:
    """Cryptographically secure random password satisfying selected character classes."""
    alphabet = _filtered_pool(opts)
    length = max(4, min(128, int(opts.length)))

    required: list[str] = []
    if opts.use_lower and any(c in alphabet for c in LOWER):
        required.append(secrets.choice([c for c in LOWER if c in alphabet]))
    if opts.use_upper and any(c in alphabet for c in UPPER):
        required.append(secrets.choice([c for c in UPPER if c in alphabet]))
    if opts.use_digits and any(c in alphabet for c in DIGITS):
        required.append(secrets.choice([c for c in DIGITS if c in alphabet]))
    if opts.use_symbols and any(c in alphabet for c in SYMBOLS):
        required.append(secrets.choice([c for c in SYMBOLS if c in alphabet]))

    remaining = length - len(required)
    if remaining < 0:
        required = required[:length]
        remaining = 0
    body = [secrets.choice(alphabet) for _ in range(remaining)]
    chars = required + body
    rng = secrets.SystemRandom()
    rng.shuffle(chars)
    return "".join(chars)


def password_strength(password: str) -> str:
    """
    Heuristic strength label (not entropy analysis).
    Maps to: Weak, Medium, Strong, Very Strong.
    """
    score = 0
    n = len(password)
    if n >= 8:
        score += 1
    if n >= 12:
        score += 1
    if n >= 16:
        score += 1
    if n >= 20:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in SYMBOLS for c in password):
        score += 1
    # penalty for very short
    if n < 8:
        score = min(score, 2)

    if score <= 3:
        return "Weak"
    if score <= 5:
        return "Medium"
    if score <= 7:
        return "Strong"
    return "Very Strong"
