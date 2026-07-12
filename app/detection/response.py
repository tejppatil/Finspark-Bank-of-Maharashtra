"""Adaptive access control: map a risk score to an enforcement action + Alert."""
from dataclasses import dataclass

from sqlalchemy.orm import Session as OrmSession

from app.detection.score import RiskAssessment
from app.models.entities import Alert, Session, User

# score thresholds (inclusive lower bounds)
THRESHOLDS = [
    (85, "BLOCK", "CRITICAL"),
    (70, "MAKER_CHECKER", "CRITICAL"),
    (40, "STEP_UP_MFA", "WARNING"),
    (0, "ALLOW", "INFO"),
]


@dataclass
class ResponseDecision:
    action: str
    severity: str
    alert_id: int | None


NEGLIGENT_REVIEW_FLOOR = 50  # a flagged-negligent session at/above this needs human review


def decide(score: float, insider_type: str | None = None) -> tuple[str, str]:
    """Return (action, severity) for a 0-100 risk score, refined by insider type.

    Response is *risk-based on the nature of the risk*, not the score alone:
    negligence is a control failure to remediate with a human second-check, never an
    attack to hard-block — so a negligent session is floored to maker-checker review
    and never escalated to an automated BLOCK.
    """
    action, severity = "ALLOW", "INFO"
    for floor, act, sev in THRESHOLDS:
        if score >= floor:
            action, severity = act, sev
            break
    if insider_type == "negligent":
        if action == "BLOCK":                       # ceiling: never auto-block negligence
            action, severity = "MAKER_CHECKER", "CRITICAL"
        elif action == "STEP_UP_MFA" and score >= NEGLIGENT_REVIEW_FLOOR:
            action, severity = "MAKER_CHECKER", "WARNING"  # floor: send for review
    return action, severity


def respond(db: OrmSession, user: User, session: Session,
            assessment: RiskAssessment) -> ResponseDecision:
    """Apply the adaptive-response policy and persist an Alert (except plain ALLOW)."""
    action, severity = decide(assessment.score, assessment.insider_type)
    alert_id = None
    if action != "ALLOW":
        alert = Alert(
            user_id=user.id,
            session_id=session.id,
            severity=severity,
            action_taken=action,
            insider_type=assessment.insider_type,
            message=(f"Risk {assessment.score:.0f}/100 for '{user.username}' -> {action}. "
                     + " | ".join(assessment.reasons)),
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id
    return ResponseDecision(action=action, severity=severity, alert_id=alert_id)
