"""Live privileged-session engine.

When an employee logs in through the portal, a live Session is opened. Every
action they perform is appended as an Event, the whole session-so-far is
re-scored, and an adaptive decision (ALLOW / STEP_UP_MFA / MAKER_CHECKER /
BLOCK) is enforced *before the action is allowed to take effect*. A BLOCK marks
the session and refuses all further actions.
"""
import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session as OrmSession

from app import jit
from app.config import settings
from app.detection.response import decide
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models.entities import Alert, Event, Session, User
from app.pam import record_command


def _stamp() -> datetime:
    """Timestamp for a live event.

    With the demo business-clock on (default), a live session run *outside*
    normal banking hours is anchored to a business hour, so a legitimate
    employee demoing in the evening isn't spuriously flagged as after-hours /
    atypical. The scripted attack scenarios set their own explicit odd hours
    (2 AM, 22:00) and are unaffected. Turn off for a real deployment.
    """
    now = datetime.now()
    if settings.demo_business_clock and not (9 <= now.hour <= 17):
        now = now.replace(hour=11)
    return now

# Catalogue of actions an employee can perform in the portal.
# records_touched is a sensible default the UI can override (e.g. export size).
ACTION_CATALOG: dict[str, dict] = {
    "DB_QUERY":      {"label": "Run database query",      "default_records": 50},
    "FILE_ACCESS":   {"label": "Open file / report",      "default_records": 0},
    "CONFIG_CHANGE": {"label": "Change configuration",    "default_records": 0},
    "PRIV_CHANGE":   {"label": "Escalate privilege",      "default_records": 0},
    "DB_EXPORT":     {"label": "Bulk export records",     "default_records": 500},
}


@dataclass
class ActionOutcome:
    allowed: bool
    decision: str          # ALLOW / STEP_UP_MFA / MAKER_CHECKER / BLOCK
    severity: str
    score: float
    reasons: list[str]
    message: str
    event_id: int | None
    session_status: str
    insider_type: str | None = None  # malicious / negligent / compromised


def open_session(db: OrmSession, user: User, source_ip: str, geo: str,
                 device: str) -> Session:
    """Return the user's current live session, or open a new one.

    An existing ACTIVE session is reused. A BLOCKED session is returned as-is so a
    blocked account stays locked out — a blocked user cannot escape enforcement by
    simply logging in again. Only when there is no open session is a new one created.
    """
    sess = (db.query(Session)
            .filter(Session.user_id == user.id, Session.status.in_(["ACTIVE", "BLOCKED"]))
            .order_by(Session.id.desc()).first())
    if sess is not None:
        return sess
    now = _stamp()
    sess = Session(user_id=user.id, started_at=now, status="ACTIVE",
                   source_ip=source_ip, geo=geo, device=device)
    db.add(sess)
    db.flush()
    db.add(Event(user_id=user.id, session_id=sess.id, action_type="LOGIN",
                 resource="pam-gateway", records_touched=0, source_ip=source_ip,
                 geo=geo, device=device, timestamp=now))
    record_command(db, sess.id, "LOGIN", "pam-gateway", 0, now, user.username)
    db.commit()
    return sess


def _candidate_event(sess: Session, user: User, action: str, resource: str,
                     records: int) -> Event:
    """An unsaved Event used only to score 'what if this action happened'."""
    return Event(user_id=user.id, session_id=sess.id, action_type=action,
                 resource=resource, records_touched=records, source_ip=sess.source_ip,
                 geo=sess.geo, device=sess.device, timestamp=_stamp())


def perform_action(db: OrmSession, model: UebaModel, sess: Session, user: User,
                   action: str, resource: str, records: int,
                   mfa_ok: bool = False) -> ActionOutcome:
    """Score the session *including* this candidate action and enforce the decision.

    The event is only persisted if the action is allowed to take effect (or, for a
    BLOCK, as a zeroed 'attempt' record). Re-submitting a challenged action therefore
    re-evaluates the same action rather than stacking duplicates.
    """
    if sess.status == "BLOCKED":
        return ActionOutcome(False, "BLOCK", "CRITICAL", sess.risk_score,
                             json.loads(sess.risk_reasons or "[]"),
                             "Session is blocked. All privileged actions are denied.",
                             None, "BLOCKED")

    candidate = _candidate_event(sess, user, action, resource, records)
    events = sorted(sess.events, key=lambda e: e.timestamp) + [candidate]
    assessment = assess(user, events, model, jit_privileges=jit.active_privileges(db, user))
    decision, severity = decide(assessment.score, assessment.insider_type)

    sess.risk_score = assessment.score
    sess.risk_reasons = json.dumps(assessment.reasons)

    allowed = False
    message = ""
    event_id = None

    if decision == "ALLOW" or (decision == "STEP_UP_MFA" and mfa_ok):
        allowed = True
        candidate.timestamp = _stamp()
        db.add(candidate)
        db.flush()
        event_id = candidate.id
        message = "Action completed." if decision == "ALLOW" \
            else "Step-up MFA verified — action completed."
    elif decision == "STEP_UP_MFA":
        message = "Elevated risk — step-up MFA required to proceed."
    elif decision == "MAKER_CHECKER":
        message = "High risk — action held pending a second-approver (maker-checker)."
    elif decision == "BLOCK":
        # Log the blocked attempt (zero records — it never took effect) and freeze the session.
        attempt = _candidate_event(sess, user, action, resource, 0)
        db.add(attempt)
        db.flush()
        event_id = attempt.id
        sess.status = "BLOCKED"
        sess.ended_at = datetime.now()
        message = "BLOCKED — malicious privileged activity detected and stopped."

    # Record this action in the privileged-session transcript (PAM session recording).
    outcome = "EXECUTED" if allowed else ("DENIED" if decision == "BLOCK" else "HELD")
    record_command(db, sess.id, action, resource, records, _stamp(),
                   user.username, outcome=outcome)

    if decision != "ALLOW" and not (decision == "STEP_UP_MFA" and mfa_ok):
        db.add(Alert(user_id=user.id, session_id=sess.id, severity=severity,
                     action_taken=decision, insider_type=assessment.insider_type,
                     message=f"{user.username}: {action} on {resource} -> {decision} "
                             f"(risk {assessment.score:.0f}). " + " | ".join(assessment.reasons)))
    db.commit()

    return ActionOutcome(allowed, decision, severity, assessment.score,
                         assessment.reasons, message, event_id, sess.status,
                         insider_type=assessment.insider_type)


def close_session(db: OrmSession, sess: Session) -> None:
    if sess.status == "ACTIVE":
        now = _stamp()
        db.add(Event(user_id=sess.user_id, session_id=sess.id, action_type="LOGOUT",
                     resource="pam-gateway", records_touched=0, source_ip=sess.source_ip,
                     geo=sess.geo, device=sess.device, timestamp=now))
        record_command(db, sess.id, "LOGOUT", "pam-gateway", 0, now, sess.user.username)
        sess.status = "CLOSED"
        sess.ended_at = now
        db.commit()
