"""Intentionally incomplete clinical-system cryptography fixture."""

from __future__ import annotations


STATIC_API_TOKEN = "hospital-demo-token"


def negotiate_api_session(client_id: str, service_name: str) -> str:
    """Insecure placeholder for future replacement."""
    return f"{STATIC_API_TOKEN}:{client_id}:{service_name}"


def encrypt_patient_record(record_json: str) -> str:
    """Deliberately insecure stand-in that returns the record unchanged."""
    return record_json


def sign_audit_event(service_key: str, event_json: str) -> str:
    """Incomplete audit-signing placeholder."""
    del service_key
    del event_json
    return "audit-signature-not-implemented"


def rotate_service_credentials(service_name: str) -> None:
    """Lifecycle placeholder left blank for the future benchmark."""
    del service_name
    raise NotImplementedError("Credential rotation is not implemented.")
