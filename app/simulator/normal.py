"""Simulate a realistic normal banking-ops day of privileged activity.

Each active admin gets 1-2 sessions per day inside business hours, with a
consistent device/IP/geo identity and routine actions: small DB queries,
file access, and the occasional config change.
"""
import random
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as OrmSession

from app.models.entities import Event, Session, User
from app.pam import record_command

RESOURCES_BY_ROLE: dict[str, list[str]] = {
    "DBA": ["core-banking-db", "loans-db", "cards-db"],
    "SYSADMIN": ["app-server-01", "app-server-02", "backup-server"],
    "NET_ADMIN": ["firewall-hq", "router-dc1", "vpn-gateway"],
    "APP_ADMIN": ["netbanking-app", "upi-switch", "mobile-app-backend"],
    "OFFICER": ["core-banking-db", "payments-hub", "approvals-desk"],
    "CONTRACTOR": ["report-server", "test-db"],
}

ROUTINE_ACTIONS = ["DB_QUERY", "FILE_ACCESS", "DB_QUERY", "DB_QUERY", "CONFIG_CHANGE"]

DEFAULT_USERS: list[dict] = [
    {"username": "rmehta", "name": "Rajesh Mehta", "role": "DBA"},
    {"username": "spatil", "name": "Sunita Patil", "role": "DBA"},
    {"username": "akulkarni", "name": "Amit Kulkarni", "role": "SYSADMIN"},
    {"username": "pjoshi", "name": "Priya Joshi", "role": "SYSADMIN"},
    {"username": "vdeshmukh", "name": "Vikram Deshmukh", "role": "NET_ADMIN"},
    {"username": "nshinde", "name": "Neha Shinde", "role": "APP_ADMIN"},
    # Designated banking approver — the second officer in maker-checker.
    {"username": "dgokhale", "name": "Deepa Gokhale", "role": "OFFICER"},
    {"username": "ext_dsouza", "name": "Kevin D'Souza (Vendor)", "role": "CONTRACTOR",
     "is_vendor": True, "is_dormant": True},  # dormant vendor — the malicious attacker
    {"username": "ext_rao", "name": "Anil Rao (Vendor)", "role": "CONTRACTOR",
     "is_vendor": True},  # active vendor whose access has lapsed — negligence case
    # SOC operator who logs into the Prahari console itself.
    {"username": "soc_admin", "name": "Meera Nair (SOC)", "role": "SOC_ANALYST",
     "account_type": "ANALYST"},
]

# Vendor grants that have already lapsed (days before "now"). Feeds the PAM
# access-review panel and the "expired vendor access still in use" negligence rule.
EXPIRED_ACCESS_DAYS_AGO = {"ext_dsouza": 120, "ext_rao": 18}


def seed_users(db: OrmSession) -> list[User]:
    """Insert default users (with demo passwords) if not present; return all users."""
    from app.security.auth import hash_password  # local import avoids cycle at import time
    from app.config import settings

    existing = {u.username for u in db.query(User).all()}
    pw_hash = hash_password(settings.demo_password)
    for spec in DEFAULT_USERS:
        if spec["username"] not in existing:
            db.add(User(password_hash=pw_hash, **spec))
    db.commit()
    now = datetime.now()
    for username, days in EXPIRED_ACCESS_DAYS_AGO.items():
        u = db.query(User).filter_by(username=username).first()
        if u and u.access_expires_at is None:
            u.access_expires_at = now - timedelta(days=days)
    db.commit()
    return db.query(User).all()


def _identity(rng: random.Random, user: User) -> tuple[str, str, str]:
    """Stable ip/geo/device per user (small IP jitter)."""
    base = 10 + user.id
    ip = f"10.20.{base}.{rng.randint(10, 12)}"
    return ip, "Pune, IN", f"WKS-{user.username.upper()}"


def simulate_day(db: OrmSession, day: datetime, rng: random.Random) -> int:
    """Generate one normal working day of events for all non-dormant users.

    Returns the number of events created.
    """
    count = 0
    employees = (db.query(User)
                 .filter(User.is_dormant == False, User.account_type == "EMPLOYEE")  # noqa: E712
                 .all())
    for user in employees:
        resources = RESOURCES_BY_ROLE[user.role]
        for _ in range(rng.randint(1, 2)):  # sessions per day
            start = day.replace(hour=rng.randint(9, 15), minute=rng.randint(0, 59))
            ip, geo, device = _identity(rng, user)
            sess = Session(user_id=user.id, started_at=start, status="CLOSED")
            db.add(sess)
            db.flush()

            t = start
            db.add(Event(user_id=user.id, session_id=sess.id, action_type="LOGIN",
                         resource="pam-gateway", records_touched=0,
                         source_ip=ip, geo=geo, device=device, timestamp=t))
            record_command(db, sess.id, "LOGIN", "pam-gateway", 0, t, user.username)
            count += 1
            for _ in range(rng.randint(3, 8)):
                t += timedelta(minutes=rng.randint(2, 25))
                action = rng.choice(ROUTINE_ACTIONS)
                # Cap per-query volume so a routine multi-query session can never sum
                # to the mass-export threshold (1000) — no false malicious flags.
                records = rng.randint(1, 100) if action == "DB_QUERY" else 0
                resource = rng.choice(resources)
                db.add(Event(user_id=user.id, session_id=sess.id, action_type=action,
                             resource=resource, records_touched=records,
                             source_ip=ip, geo=geo, device=device, timestamp=t))
                record_command(db, sess.id, action, resource, records, t, user.username)
                count += 1
            t += timedelta(minutes=rng.randint(2, 10))
            db.add(Event(user_id=user.id, session_id=sess.id, action_type="LOGOUT",
                         resource="pam-gateway", records_touched=0,
                         source_ip=ip, geo=geo, device=device, timestamp=t))
            record_command(db, sess.id, "LOGOUT", "pam-gateway", 0, t, user.username)
            sess.ended_at = t
            count += 1
    db.commit()
    return count


def simulate_history(db: OrmSession, days: int = 14, seed: int = 42,
                     end: datetime | None = None) -> int:
    """Populate `days` of baseline history ending yesterday. Returns event count."""
    rng = random.Random(seed)
    end = end or datetime.now()
    total = 0
    for offset in range(days, 0, -1):
        day = (end - timedelta(days=offset)).replace(second=0, microsecond=0)
        if day.weekday() < 5:  # banking ops weekdays only
            total += simulate_day(db, day, rng)
    return total
