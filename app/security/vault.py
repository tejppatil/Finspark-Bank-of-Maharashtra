"""Quantum-safe credential vault.

Each secret is encrypted with AES-256-GCM under a fresh key; that key is the
shared secret produced by ML-KEM-768 encapsulation against the vault's public
key. Decryption requires the vault's KEM secret key to decapsulate — so even a
recorded-today/decrypted-later quantum adversary can't recover the credentials.
"""
import base64
import os
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session as OrmSession

from app.config import settings
from app.models.entities import CredentialCheckout, User, VaultItem
from app.security import keys, pqc

# Privileged credentials seeded into the vault so the checkout desk has real
# (demo) content on first boot. Never shown in plaintext except via a checkout.
SEED_CREDENTIALS = {
    "core-banking-db-root": "pg#Rb7!vX2qLm9@banking-prod",
    "payment-gateway-api-key": "pgw_live_4f8Zk2Nq7RtY1sWx",
    "swift-terminal-cert-passphrase": "SWIFT-hsm-9!Kd82jQ",
}


class CheckoutDenied(Exception):
    """A credential checkout refused by the risk gate."""


def store_secret(db: OrmSession, name: str, secret: str) -> VaultItem:
    """Encrypt and persist a credential; replaces any existing item of the same name."""
    vault_pub, _ = keys.vault_keypair()
    kem_ct, shared_secret = pqc.kem_encapsulate(vault_pub)  # 32 bytes -> AES-256 key
    nonce = os.urandom(12)
    ciphertext = AESGCM(shared_secret).encrypt(nonce, secret.encode(), name.encode())

    item = db.query(VaultItem).filter_by(name=name).first()
    if item is None:
        item = VaultItem(name=name)
        db.add(item)
    item.ciphertext = base64.b64encode(ciphertext).decode()
    item.nonce = base64.b64encode(nonce).decode()
    item.kem_ciphertext = base64.b64encode(kem_ct).decode()
    db.commit()
    return item


def get_secret(db: OrmSession, name: str) -> str:
    """Decapsulate + decrypt a stored credential."""
    item = db.query(VaultItem).filter_by(name=name).first()
    if item is None:
        raise KeyError(f"no vault item named '{name}'")
    _, vault_sec = keys.vault_keypair()
    shared_secret = pqc.kem_decapsulate(vault_sec, base64.b64decode(item.kem_ciphertext))
    plaintext = AESGCM(shared_secret).decrypt(
        base64.b64decode(item.nonce), base64.b64decode(item.ciphertext), name.encode())
    return plaintext.decode()


def seed_credentials(db: OrmSession) -> None:
    """Ensure the demo privileged credentials exist in the vault (idempotent)."""
    for name, secret in SEED_CREDENTIALS.items():
        if db.query(VaultItem).filter_by(name=name).first() is None:
            store_secret(db, name, secret)


def _expire_stale_checkouts(db: OrmSession) -> None:
    now = datetime.now()
    stale = (db.query(CredentialCheckout)
             .filter(CredentialCheckout.status == "ACTIVE",
                     CredentialCheckout.expires_at < now).all())
    for c in stale:
        c.status = "EXPIRED"
    if stale:
        db.commit()


def _checkout_dict(c: CredentialCheckout, username: str) -> dict:
    remaining = 0
    if c.status == "ACTIVE":
        remaining = max(0, int((c.expires_at - datetime.now()).total_seconds()))
    return {"id": c.id, "name": c.name, "user": username, "status": c.status,
            "checked_out_at": c.checked_out_at.isoformat(),
            "expires_at": c.expires_at.isoformat(),
            "remaining_seconds": remaining,
            "risk_at_checkout": round(c.risk_at_checkout, 1),
            "denied_reason": c.denied_reason}


def checkout_credential(db: OrmSession, user: User, name: str,
                        session_risk: float, session_id: int | None,
                        session_blocked: bool = False) -> dict:
    """Risk-gated, time-boxed credential checkout from the PQC vault.

    The same risk score that drives session enforcement gates the vault: a
    high-risk or blocked session is refused the secret, and the refusal itself
    is recorded (a denied checkout is evidence, not silence).
    """
    if db.query(VaultItem).filter_by(name=name).first() is None:
        raise KeyError(f"no vault item named '{name}'")
    _expire_stale_checkouts(db)
    now = datetime.now()

    if session_blocked or session_risk >= settings.checkout_risk_ceiling:
        reason = ("session is BLOCKED" if session_blocked
                  else f"session risk {session_risk:.0f} >= ceiling {settings.checkout_risk_ceiling:.0f}")
        c = CredentialCheckout(name=name, user_id=user.id, session_id=session_id,
                               checked_out_at=now, expires_at=now, status="DENIED",
                               risk_at_checkout=session_risk, denied_reason=reason)
        db.add(c)
        db.commit()
        raise CheckoutDenied(reason)

    c = CredentialCheckout(
        name=name, user_id=user.id, session_id=session_id, checked_out_at=now,
        expires_at=now + timedelta(seconds=settings.checkout_ttl_seconds),
        status="ACTIVE", risk_at_checkout=session_risk)
    db.add(c)
    db.commit()
    out = _checkout_dict(c, user.username)
    out["secret"] = get_secret(db, name)
    return out


def list_credentials(db: OrmSession, user: User) -> dict:
    """The checkout desk: available credential names + this user's checkout history."""
    _expire_stale_checkouts(db)
    names = [v.name for v in db.query(VaultItem).order_by(VaultItem.name).all()]
    mine = (db.query(CredentialCheckout)
            .filter(CredentialCheckout.user_id == user.id)
            .order_by(CredentialCheckout.id.desc()).limit(10).all())
    return {"credentials": names, "ttl_seconds": settings.checkout_ttl_seconds,
            "risk_ceiling": settings.checkout_risk_ceiling,
            "my_checkouts": [_checkout_dict(c, user.username) for c in mine]}


def list_all_checkouts(db: OrmSession, limit: int = 30) -> list[dict]:
    """SOC view: every checkout (and refusal) across all users, newest first."""
    _expire_stale_checkouts(db)
    rows = (db.query(CredentialCheckout, User.username)
            .join(User, CredentialCheckout.user_id == User.id)
            .order_by(CredentialCheckout.id.desc()).limit(limit).all())
    return [_checkout_dict(c, uname) for c, uname in rows]
