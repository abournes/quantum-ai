"""Intentionally incomplete messaging cryptography fixture."""

from __future__ import annotations


DEFAULT_SHARED_SECRET = "snapstabook-demo-secret"


def generate_identity_keypair(user_id: str) -> dict[str, str]:
    """Placeholder identity keys for the future coding benchmark."""
    return {
        "public_key": f"{user_id}-public-key",
        "private_key": f"{user_id}-private-key",
    }


def derive_session_key(sender_id: str, recipient_id: str) -> str:
    """Insecure placeholder for future replacement."""
    return f"{DEFAULT_SHARED_SECRET}:{sender_id}:{recipient_id}"


def encrypt_message(session_key: str, plaintext: str) -> str:
    """Deliberately insecure stand-in that returns the plaintext unchanged."""
    del session_key
    return plaintext


def sign_message(identity_private_key: str, message: str) -> str:
    """Incomplete signature placeholder."""
    del identity_private_key
    del message
    return "signature-not-implemented"
