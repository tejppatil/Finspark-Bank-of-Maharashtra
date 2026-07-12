"""Phase 4 tests: PQC primitives, vault round-trip, audit chain + tamper detection."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import entities  # noqa: F401
from app.models.db import Base
from app.models.entities import AuditLogEntry
from app.security import audit, keys, pqc, vault


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def temp_keys(tmp_path, monkeypatch):
    """Isolate keystore per test."""
    monkeypatch.setattr(keys, "KEYS_DIR", tmp_path / "keys")


def test_kem_roundtrip():
    pub, sec = pqc.kem_keypair()
    ct, ss1 = pqc.kem_encapsulate(pub)
    ss2 = pqc.kem_decapsulate(sec, ct)
    assert ss1 == ss2 and len(ss1) == 32


def test_sign_verify_and_reject():
    pub, sec = pqc.sig_keypair()
    sig = pqc.sign(sec, b"legit message")
    assert pqc.verify(pub, b"legit message", sig)
    assert not pqc.verify(pub, b"forged message", sig)


def test_vault_roundtrip(db):
    vault.store_secret(db, "core-db-root", "S3cr3t!Pa55")
    assert vault.get_secret(db, "core-db-root") == "S3cr3t!Pa55"
    # ciphertext at rest is not the plaintext
    item = db.query(entities.VaultItem).filter_by(name="core-db-root").one()
    assert "S3cr3t!Pa55" not in item.ciphertext
    # overwrite works
    vault.store_secret(db, "core-db-root", "rotated")
    assert vault.get_secret(db, "core-db-root") == "rotated"


def test_vault_missing(db):
    with pytest.raises(KeyError):
        vault.get_secret(db, "nope")


def test_audit_chain_verifies_clean(db):
    for i in range(5):
        audit.append_entry(db, "prahari-engine", "TEST_EVENT", f"entry {i}")
    report = audit.verify_chain(db)
    assert report.ok and report.entries_checked == 5


def test_audit_tamper_detected(db):
    for i in range(5):
        audit.append_entry(db, "prahari-engine", "TEST_EVENT", f"entry {i}")
    victim = db.query(AuditLogEntry).filter(AuditLogEntry.id == 3).one()
    victim.payload = "entry 2 [rewritten by insider]"
    db.commit()
    report = audit.verify_chain(db)
    assert not report.ok
    assert report.first_bad_id == 3
    assert report.problem == "entry content was modified"


def test_audit_signature_forgery_detected(db):
    """Recomputing hashes isn't enough — signatures must come from the audit key."""
    audit.append_entry(db, "prahari-engine", "TEST_EVENT", "original")
    e = db.query(AuditLogEntry).one()
    # attacker rewrites content AND recomputes a consistent hash chain
    e.payload = "rewritten"
    e.entry_hash = audit._entry_hash(e.prev_hash, e.timestamp.isoformat(),
                                     e.actor, e.action, e.payload)
    db.commit()
    report = audit.verify_chain(db)
    assert not report.ok and report.problem == "signature invalid"
