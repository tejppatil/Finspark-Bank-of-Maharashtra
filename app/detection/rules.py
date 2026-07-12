"""Rule engine: known-bad privileged-access patterns across all three insider types.

Each rule returns a `RuleHit` carrying a reason, a weight, and an `insider_type`
tag — malicious, negligent, or compromised — matching the problem statement's three
insider categories.
"""
from dataclasses import dataclass
from datetime import datetime

from app.models.entities import Event, User
from app.simulator.normal import RESOURCES_BY_ROLE

MASS_EXPORT_THRESHOLD = 1000       # >= this in one session = malicious mass export
AFTER_HOURS = range(0, 6)          # 00:00-05:59  (malicious deep-night)
ATYPICAL_HOURS = {6, 20, 21, 22, 23}  # off-shift but not deep-night (compromised)
HOME_GEO = "Pune, IN"

MALICIOUS, NEGLIGENT, COMPROMISED = "malicious", "negligent", "compromised"


@dataclass
class RuleHit:
    rule: str
    reason: str
    weight: int
    insider_type: str


def _expected_device(user: User) -> str:
    return f"WKS-{user.username.upper()}"


def _acts(events: list[Event]) -> list[Event]:
    return [e for e in events if e.action_type not in ("LOGIN", "LOGOUT")]


def evaluate(user: User, events: list[Event], now: datetime | None = None,
             jit_privileges: set[str] | None = None) -> list[RuleHit]:
    """Run all rules over one session's events; return every hit.

    `jit_privileges` are resources the user holds an ACTIVE just-in-time grant
    for: a privilege change covered by an approved, unexpired grant is
    sanctioned and does not fire PRIVILEGE_ESCALATION.
    """
    now = now or datetime.now()
    jit_privileges = jit_privileges or set()
    hits: list[RuleHit] = []
    logins = [e for e in events if e.action_type == "LOGIN"]

    # ---------- MALICIOUS ----------
    if user.is_dormant and logins:
        hits.append(RuleHit("DORMANT_REACTIVATION",
            f"Dormant {'vendor ' if user.is_vendor else ''}account '{user.username}' became active",
            30, MALICIOUS))

    priv = [e for e in events if e.action_type == "PRIV_CHANGE"
            and e.resource not in jit_privileges]
    if priv:
        hits.append(RuleHit("PRIVILEGE_ESCALATION",
            f"Privilege change on {priv[0].resource} outside normal grant process", 25, MALICIOUS))

    night = [e for e in events if e.timestamp.hour in AFTER_HOURS and e.action_type != "LOGOUT"]
    if night:
        hits.append(RuleHit("AFTER_HOURS_ACCESS",
            f"{len(night)} privileged action(s) in the 00:00-06:00 window", 20, MALICIOUS))

    exported = sum(e.records_touched for e in events if e.action_type in ("DB_QUERY", "DB_EXPORT"))
    if exported >= MASS_EXPORT_THRESHOLD:
        hits.append(RuleHit("MASS_EXPORT",
            f"{exported} records touched in one session (threshold {MASS_EXPORT_THRESHOLD})",
            30, MALICIOUS))

    allowed = set(RESOURCES_BY_ROLE.get(user.role, [])) | {"pam-gateway"}
    foreign = {e.resource for e in events} - allowed
    if foreign:
        hits.append(RuleHit("NO_BUSINESS_RELATIONSHIP",
            f"Access to resource(s) outside role '{user.role}': {', '.join(sorted(foreign))}",
            15, MALICIOUS))

    # ---------- COMPROMISED (account looks hijacked) ----------
    off_geo = {e.geo for e in events if e.geo and e.geo != HOME_GEO}
    if off_geo:
        hits.append(RuleHit("NEW_GEO",
            f"Login from unrecognized location: {', '.join(sorted(off_geo))}", 16, COMPROMISED))

    devices = {e.device for e in events if e.device}
    unrecognized_device = bool(devices) and _expected_device(user) not in devices
    # A new device *with* a foreign location reads as account takeover; a new device
    # from the home location is an unmanaged personal device (negligence, below).
    if unrecognized_device and off_geo:
        hits.append(RuleHit("NEW_DEVICE",
            f"Unrecognized device fingerprint: {', '.join(sorted(devices))}", 12, COMPROMISED))

    if logins and logins[0].timestamp.hour in ATYPICAL_HOURS:
        hits.append(RuleHit("ATYPICAL_HOUR",
            f"Login at {logins[0].timestamp:%H:%M}, atypical for this user", 8, COMPROMISED))

    acts = _acts(events)
    if len(acts) >= 5:
        span = (max(a.timestamp for a in acts) - min(a.timestamp for a in acts)).total_seconds()
        if span <= 180:
            hits.append(RuleHit("RAPID_FIRE",
                f"{len(acts)} actions in {int(span)}s — inconsistent with human pace", 8, COMPROMISED))

    # ---------- NEGLIGENT (well-meaning but risky) ----------
    # Weights are kept so that pure-negligence (no malicious rule, no peer blow-out)
    # tops out below the BLOCK line: negligence is held for review, never auto-blocked.
    if user.access_expires_at and user.access_expires_at < now:
        days = (now - user.access_expires_at).days
        hits.append(RuleHit("EXPIRED_ACCESS_IN_USE",
            f"Access grant for '{user.username}' expired {days} days ago but is still in use",
            30, NEGLIGENT))

    db_touch = any(e.action_type in ("DB_QUERY", "DB_EXPORT", "FILE_ACCESS") for e in events)
    if db_touch and unrecognized_device and not off_geo:
        hits.append(RuleHit("UNMANAGED_DEVICE",
            "Sensitive data accessed from an unmanaged (non-corporate) device", 30, NEGLIGENT))

    return hits


def dominant_insider_type(hits: list[RuleHit]) -> str | None:
    """The insider category carrying the most rule weight in this session."""
    if not hits:
        return None
    totals: dict[str, int] = {}
    for h in hits:
        totals[h.insider_type] = totals.get(h.insider_type, 0) + h.weight
    # tie-break priority: malicious > compromised > negligent
    priority = {MALICIOUS: 3, COMPROMISED: 2, NEGLIGENT: 1}
    return max(totals, key=lambda t: (totals[t], priority[t]))
