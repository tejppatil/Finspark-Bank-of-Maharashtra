"""Local keystore: persists Prahari's own PQC keypairs under ./keys (gitignored).

- vault ML-KEM keypair: wraps credential-vault encryption keys
- audit ML-DSA keypair: signs audit-log entries
"""
from pathlib import Path

from app.security import pqc

KEYS_DIR = Path("keys")


def _load_or_create(name: str, generator) -> tuple[bytes, bytes]:
    pub_path = KEYS_DIR / f"{name}.pub"
    sec_path = KEYS_DIR / f"{name}.key"
    if pub_path.exists() and sec_path.exists():
        return pub_path.read_bytes(), sec_path.read_bytes()
    KEYS_DIR.mkdir(exist_ok=True)
    public, secret = generator()
    pub_path.write_bytes(public)
    sec_path.write_bytes(secret)
    return public, secret


def vault_keypair() -> tuple[bytes, bytes]:
    """(public, secret) ML-KEM-768 keypair for the credential vault."""
    return _load_or_create("vault_kem", pqc.kem_keypair)


def audit_keypair() -> tuple[bytes, bytes]:
    """(public, secret) ML-DSA-65 keypair for audit-log signing."""
    return _load_or_create("audit_dsa", pqc.sig_keypair)
