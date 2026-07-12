"""The three insider scenarios (malicious / compromised / negligent).

Each builds one recorded privileged session that should drive a *distinct*
adaptive response:
  malicious   -> BLOCK          (dormant vendor escalates + bulk-exports at 2 AM)
  compromised -> STEP_UP_MFA    (a normal admin's account logs in from a new
                                 country + device and acts rapid-fire)
  negligent   -> MAKER_CHECKER  (an active-but-expired vendor over-accesses
                                 sensitive data from an unmanaged device)
"""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as OrmSession

from app.models.entities import Event, Session, User
from app.pam import record_command


def _build(db: OrmSession, user: User, at: datetime, ip: str, geo: str, device: str,
           steps: list[tuple[float, str, str, int]]) -> Session:
    """Create a recorded session from (minute_offset, action, resource, records) steps."""
    sess = Session(user_id=user.id, started_at=at, status="CLOSED",
                   source_ip=ip, geo=geo, device=device)
    db.add(sess)
    db.flush()
    for minutes, action, resource, records in steps:
        ts = at + timedelta(minutes=minutes)
        db.add(Event(user_id=user.id, session_id=sess.id, action_type=action,
                     resource=resource, records_touched=records, source_ip=ip,
                     geo=geo, device=device, timestamp=ts))
        record_command(db, sess.id, action, resource, records, ts, user.username)
    sess.ended_at = at + timedelta(minutes=steps[-1][0] + 1)
    db.commit()
    return sess


def trigger_malicious(db: OrmSession) -> Session:
    """Dormant vendor wakes at 2 AM, escalates privilege, bulk-exports 5000 records."""
    vendor = db.query(User).filter_by(is_dormant=True, is_vendor=True).first()
    if vendor is None:
        raise ValueError("no dormant vendor account found — run the seeder first")
    t0 = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
    return _build(db, vendor, t0, "103.94.55.7", "Unknown (VPN exit)", "LAPTOP-UNREG", [
        (0, "LOGIN", "pam-gateway", 0),
        (2, "PRIV_CHANGE", "core-banking-db", 0),
        (5, "DB_QUERY", "core-banking-db", 300),
        (9, "DB_EXPORT", "core-banking-db", 5000),
    ])


def trigger_compromised(db: OrmSession) -> Session:
    """A normal sysadmin's account logs in from a new country + device, rapid-fire."""
    admin = db.query(User).filter_by(username="akulkarni").first()
    if admin is None:
        raise ValueError("expected user 'akulkarni' — run the seeder first")
    t0 = datetime.now().replace(hour=22, minute=10, second=0, microsecond=0)
    # Six actions within ~90 seconds — inhumanly fast — from Singapore on a new laptop.
    return _build(db, admin, t0, "203.0.113.45", "Singapore, SG", "LAPTOP-UNKNOWN", [
        (0.0, "LOGIN", "pam-gateway", 0),
        (0.3, "DB_QUERY", "app-server-01", 90),
        (0.6, "DB_QUERY", "app-server-02", 120),
        (0.9, "FILE_ACCESS", "backup-server", 0),
        (1.2, "DB_QUERY", "app-server-01", 80),
        (1.5, "CONFIG_CHANGE", "app-server-02", 0),
    ])


def trigger_negligent(db: OrmSession) -> Session:
    """An active vendor whose access has expired over-reads sensitive data from an
    unmanaged device — no malice, but a serious policy breach."""
    vendor = db.query(User).filter_by(username="ext_rao").first()
    if vendor is None:
        raise ValueError("expected user 'ext_rao' — run the seeder first")
    t0 = datetime.now().replace(hour=14, minute=30, second=0, microsecond=0)
    # Modest data volume — the risk here is *who and how* (expired grant, personal
    # laptop), not bulk theft. Signals: EXPIRED_ACCESS_IN_USE + UNMANAGED_DEVICE.
    return _build(db, vendor, t0, "10.20.19.11", "Pune, IN", "LAPTOP-HOME", [
        (0, "LOGIN", "pam-gateway", 0),
        (3, "FILE_ACCESS", "report-server", 0),
        (8, "DB_QUERY", "report-server", 120),
    ])


# Backwards-compatible alias (older callers / tests).
trigger_attack = trigger_malicious
