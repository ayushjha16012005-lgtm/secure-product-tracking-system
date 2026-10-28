"""Passwords, session tokens and role-based access control (RBAC)."""
import base64
import hashlib
import hmac
import json
import os
import time

PBKDF2_ROUNDS = 200_000

# Principle of least privilege: each role gets only what it needs.
ROLE_PERMISSIONS = {
    "manufacturer": {"register", "ship", "verify", "history"},
    "distributor": {"receive", "ship", "verify", "history"},
    "retailer": {"receive", "sell", "verify", "history"},
    "admin": {"audit", "verify", "history", "add_user"},
    "customer": {"verify", "history"},
}


class PermissionDenied(Exception):
    pass


def hash_password(password: str, salt: bytes = None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def check_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    _, d = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(d, digest_hex)      # constant-time compare


def authorize(role: str, action: str):
    if action not in ROLE_PERMISSIONS.get(role, set()):
        raise PermissionDenied(f"role '{role}' is not allowed to '{action}'")


# --- small HS256-style token (same idea as JWT, written by hand to learn it)
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(secret: bytes, username: str, role: str, ttl: int = 900) -> str:
    body = _b64(json.dumps({"sub": username, "role": role,
                            "exp": int(time.time()) + ttl}).encode())
    sig = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_token(secret: bytes, token: str) -> dict:
    try:
        body, sig = token.split(".")
    except ValueError:
        raise PermissionDenied("malformed token")
    good = _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, good):
        raise PermissionDenied("bad token signature")
    data = json.loads(_unb64(body))
    if data["exp"] < time.time():
        raise PermissionDenied("token expired")
    return data
