"""Utility helpers for password hashing and verification."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

_ITERATIONS = 200_000
_ALGORITHM = "sha256"


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(_ALGORITHM, password.encode("utf-8"), salt, _ITERATIONS)


def hash_password(password: str) -> str:
    """Return a salted hash for storage."""
    salt = os.urandom(16)
    derived = _derive_key(password, salt)
    return f"{base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Validate ``password`` against the stored hash."""
    try:
        salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(hash_b64)
    actual = _derive_key(password, salt)
    return hmac.compare_digest(actual, expected)
