"""Risk scoring engine: combine rule hits + UEBA anomaly into one 0-100 score."""
from dataclasses import dataclass, field

from app.detection.rules import RuleHit, dominant_insider_type, evaluate
from app.detection.ueba import UebaModel
from app.models.entities import Event, User

# Contribution caps so neither side alone saturates the scale dishonestly.
# The cap only binds when several rules stack (i.e. a genuine multi-signal attack);
# a single-rule legitimate anomaly is well under it, so raising it does not make
# ordinary activity block — it only sharpens clearly-malicious combinations.
RULE_CAP = 80
# UEBA is a *secondary* nudge (max 25 pts): the rule engine — which is stable and
# explainable — should place a session's band; the behavioural model refines within it.
UEBA_WEIGHT = 0.25
PEER_BONUS = 10  # extra if wildly above same-role peers


@dataclass
class RiskAssessment:
    score: float  # 0-100
    rule_hits: list[RuleHit] = field(default_factory=list)
    ueba_summary: str = ""
    reasons: list[str] = field(default_factory=list)
    insider_type: str | None = None  # malicious / negligent / compromised

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "insider_type": self.insider_type,
            "reasons": self.reasons,
            "rules": [{"rule": h.rule, "reason": h.reason, "weight": h.weight,
                       "insider_type": h.insider_type} for h in self.rule_hits],
            "ueba": self.ueba_summary,
        }


def assess(user: User, events: list[Event], model: UebaModel,
           jit_privileges: set[str] | None = None) -> RiskAssessment:
    """Score one session 0-100 with a human-readable breakdown.

    `jit_privileges` — resources under an ACTIVE just-in-time grant — are passed
    through to the rule engine so a sanctioned escalation is not treated as an attack.
    """
    hits = evaluate(user, events, jit_privileges=jit_privileges)
    ueba = model.score_session(user, events)

    rule_points = min(sum(h.weight for h in hits), RULE_CAP)
    ueba_points = ueba.anomaly_score * UEBA_WEIGHT
    peer_points = PEER_BONUS if ueba.peer_deviation >= 5 else 0.0

    score = min(rule_points + ueba_points + peer_points, 100.0)

    reasons = [h.reason for h in hits]
    if jit_privileges and any(e.action_type == "PRIV_CHANGE" and e.resource in jit_privileges
                              for e in events):
        reasons.append("privilege change sanctioned by an approved JIT grant")
    reasons.append(ueba.summary)
    if peer_points:
        reasons.append(f"far above {user.role} peer group (x{ueba.peer_deviation:.0f})")

    return RiskAssessment(score=score, rule_hits=hits, ueba_summary=ueba.summary,
                          reasons=reasons, insider_type=dominant_insider_type(hits))
