"""Privileged Access Management helpers: session-command recording + access review.

- `command_for` renders a realistic shell/SQL command string for an action, so a
  recorded privileged session reads like a real terminal transcript on replay.
- `record_command` persists one line of that transcript (`SessionCommand`).
- `access_review` produces the PAM access-review table (dormant / vendor / expired).
"""
from datetime import datetime

from sqlalchemy.orm import Session as OrmSession

from app.models.entities import SessionCommand, User


def command_for(action: str, resource: str, records: int, username: str = "user") -> str:
    """Render the recorded command line for a privileged action."""
    if action == "LOGIN":
        return f"ssh {username}@{resource} && sudo -i"
    if action == "LOGOUT":
        return "exit"
    if action == "DB_QUERY":
        return f"psql {resource} -c 'SELECT * FROM accounts LIMIT {records};'"
    if action == "DB_EXPORT":
        return f"psql {resource} -c \"COPY customers TO '/tmp/out.csv' CSV;\"  -- {records} rows"
    if action == "FILE_ACCESS":
        return f"cat /mnt/{resource}/report.dat"
    if action == "CONFIG_CHANGE":
        return f"vim /etc/{resource}/settings.conf"
    if action == "PRIV_CHANGE":
        return f"psql {resource} -c 'GRANT ALL PRIVILEGES ON DATABASE {resource} TO {username};'"
    return f"{action.lower()} {resource}"


def record_command(db: OrmSession, session_id: int, action: str, resource: str,
                   records: int, timestamp: datetime, username: str = "user",
                   outcome: str = "EXECUTED") -> SessionCommand:
    """Append one line to a session's recorded command trail."""
    cmd = SessionCommand(session_id=session_id, timestamp=timestamp,
                         command=command_for(action, resource, records, username),
                         action_type=action, resource=resource, outcome=outcome)
    db.add(cmd)
    return cmd


def access_review(db: OrmSession, now: datetime | None = None) -> list[dict]:
    """PAM access-review rows for privileged (employee) accounts, with risk flags."""
    now = now or datetime.now()
    rows: list[dict] = []
    for u in (db.query(User).filter(User.account_type == "EMPLOYEE")
              .order_by(User.id).all()):
        expired = bool(u.access_expires_at and u.access_expires_at < now)
        flags = []
        if u.is_dormant:
            flags.append("DORMANT")
        if u.is_vendor:
            flags.append("VENDOR")
        if expired:
            flags.append("EXPIRED")
        rows.append({
            "username": u.username, "name": u.name, "role": u.role,
            "is_dormant": u.is_dormant, "is_vendor": u.is_vendor,
            "access_expires_at": u.access_expires_at.isoformat() if u.access_expires_at else None,
            "expired": expired, "flags": flags,
            "risk": "HIGH" if (u.is_dormant or expired) else ("REVIEW" if u.is_vendor else "OK"),
        })
    return rows
