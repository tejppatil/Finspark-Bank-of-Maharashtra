"""Just-in-time (JIT) privileged access.

Removes standing privilege: an employee requests a time-boxed elevation for one
resource with a justification; an SOC analyst approves or denies it; an approved
grant auto-expires. While a grant is ACTIVE, a privilege escalation on that
resource is *sanctioned* — the PRIVILEGE_ESCALATION rule does not fire — so the
same click that raises an alarm without a grant sails through with one.
"""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as OrmSession

from app.config import settings
from app.models.entities import JitGrant, User


class JitError(Exception):
    """A JIT request/approval that cannot proceed."""


def _expire_stale(db: OrmSession) -> None:
    """Lazily flip past-deadline ACTIVE grants to EXPIRED (no background job needed)."""
    now = datetime.now()
    stale = (db.query(JitGrant)
             .filter(JitGrant.status == "ACTIVE", JitGrant.expires_at < now).all())
    for g in stale:
        g.status = "EXPIRED"
    if stale:
        db.commit()


def _grant_dict(g: JitGrant) -> dict:
    remaining = None
    if g.status == "ACTIVE" and g.expires_at:
        remaining = max(0, int((g.expires_at - datetime.now()).total_seconds()))
    return {"id": g.id, "user": g.user.username, "name": g.user.name, "role": g.user.role,
            "privilege": g.privilege, "justification": g.justification,
            "duration_minutes": g.duration_minutes, "status": g.status,
            "requested_at": g.requested_at.isoformat(),
            "approved_by": g.approved_by,
            "expires_at": g.expires_at.isoformat() if g.expires_at else None,
            "remaining_seconds": remaining}


def request_grant(db: OrmSession, user: User, privilege: str, justification: str,
                  duration_minutes: int) -> dict:
    if not justification.strip():
        raise JitError("a business justification is required")
    if not 1 <= duration_minutes <= settings.jit_max_minutes:
        raise JitError(f"duration must be 1-{settings.jit_max_minutes} minutes")
    open_same = (db.query(JitGrant)
                 .filter(JitGrant.user_id == user.id, JitGrant.privilege == privilege,
                         JitGrant.status.in_(["PENDING", "ACTIVE"])).first())
    if open_same:
        raise JitError(f"an open grant for '{privilege}' already exists (#{open_same.id})")
    g = JitGrant(user_id=user.id, privilege=privilege, justification=justification.strip(),
                 duration_minutes=duration_minutes)
    db.add(g)
    db.commit()
    return _grant_dict(g)


def decide_grant(db: OrmSession, grant_id: int, approver: str, approve: bool) -> dict:
    g = db.get(JitGrant, grant_id)
    if g is None:
        raise JitError("grant not found")
    if g.status != "PENDING":
        raise JitError(f"grant #{grant_id} is already {g.status}")
    if approve:
        g.status = "ACTIVE"
        g.approved_by = approver
        g.approved_at = datetime.now()
        g.expires_at = g.approved_at + timedelta(minutes=g.duration_minutes)
    else:
        g.status = "DENIED"
        g.approved_by = approver
        g.approved_at = datetime.now()
    db.commit()
    return _grant_dict(g)


def list_grants(db: OrmSession, user: User | None = None) -> list[dict]:
    _expire_stale(db)
    q = db.query(JitGrant)
    if user is not None:
        q = q.filter(JitGrant.user_id == user.id)
    return [_grant_dict(g) for g in q.order_by(JitGrant.id.desc()).all()]


def active_privileges(db: OrmSession, user: User) -> set[str]:
    """Resources this user currently holds an ACTIVE, unexpired JIT grant for."""
    _expire_stale(db)
    rows = (db.query(JitGrant)
            .filter(JitGrant.user_id == user.id, JitGrant.status == "ACTIVE").all())
    return {g.privilege for g in rows}
