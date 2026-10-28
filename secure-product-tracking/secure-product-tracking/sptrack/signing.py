"""Digital signatures (Ed25519) - each actor signs the events they create."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    """Returns (private_pem, public_hex)."""
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return private_pem, public_hex


def sign(private_pem: str, message_hex: str) -> str:
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return priv.sign(bytes.fromhex(message_hex)).hex()


def verify(public_hex: str, signature_hex: str, message_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
        return True
    except (InvalidSignature, ValueError):
        return False
