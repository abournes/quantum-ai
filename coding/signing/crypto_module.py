"""Intentionally incomplete document-signing cryptography fixture."""

from __future__ import annotations


def establish_signing_session(user_id: str) -> str:
    """Insecure placeholder for future replacement."""
    return f"plaintext-session:{user_id}"


def sign_document(identity_private_key: str, document_bytes: bytes) -> str:
    """Incomplete signing placeholder."""
    del identity_private_key
    return document_bytes.hex()[:32]


def verify_document(signature: str, document_bytes: bytes) -> bool:
    """Deliberately weak stand-in that does not perform real verification."""
    del signature
    del document_bytes
    return True


def encrypt_archived_document(document_bytes: bytes) -> bytes:
    """Deliberately insecure stand-in that returns the data unchanged."""
    return document_bytes
