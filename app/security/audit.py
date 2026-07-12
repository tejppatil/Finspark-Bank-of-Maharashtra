"""Tamper-evident audit log: hash-chained + ML-DSA-65 signed entries.

Each entry's hash covers its content AND the previous entry's hash, so editing
any historical entry breaks every hash after it. Each hash is also signed with
the audit ML-DSA key, so an attacker can't simply recompute the chain.
"""
import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session as OrmSession

from app.models.entities import AuditLogEntry
from app.security import keys, pqc

GENESIS = "GENESIS"


def _entry_hash(prev_hash: str, timestamp: str, actor: str, action: str, payload: str) -> str:
    material = f"{prev_hash}|{timestamp}|{actor}|{action}|{payload}"
    return hashlib.sha256(material.encode()).hexdigest()


def append_entry(db: OrmSession, actor: str, action: str, payload: str) -> AuditLogEntry:
    """Append a hash-chained, signed audit entry."""
    last = db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).first()
    prev_hash = last.entry_hash if last else GENESIS
    ts = datetime.now().replace(microsecond=0)
    entry_hash = _entry_hash(prev_hash, ts.isoformat(), actor, action, payload)
    _, audit_sec = keys.audit_keypair()
    signature = base64.b64encode(pqc.sign(audit_sec, entry_hash.encode())).decode()

    entry = AuditLogEntry(timestamp=ts, actor=actor, action=action, payload=payload,
                          prev_hash=prev_hash, entry_hash=entry_hash, signature=signature)
    db.add(entry)
    db.commit()
    return entry


@dataclass
class ChainReport:
    ok: bool
    entries_checked: int
    first_bad_id: int | None = None
    problem: str | None = None


def verify_chain(db: OrmSession) -> ChainReport:
    """Walk the whole log: recompute hashes, check linkage, verify signatures."""
    audit_pub, _ = keys.audit_keypair()
    prev_hash = GENESIS
    entries = db.query(AuditLogEntry).order_by(AuditLogEntry.id).all()
    for e in entries:
        if e.prev_hash != prev_hash:
            return ChainReport(False, len(entries), e.id, "chain linkage broken")
        expected = _entry_hash(prev_hash, e.timestamp.isoformat(), e.actor, e.action, e.payload)
        if e.entry_hash != expected:
            return ChainReport(False, len(entries), e.id, "entry content was modified")
        if not pqc.verify(audit_pub, e.entry_hash.encode(), base64.b64decode(e.signature)):
            return ChainReport(False, len(entries), e.id, "signature invalid")
        prev_hash = e.entry_hash
    return ChainReport(True, len(entries))
