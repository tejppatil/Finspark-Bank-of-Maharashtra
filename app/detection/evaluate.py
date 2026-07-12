"""Measured detection performance — turns "we have AI" into "we measured our AI".

Builds a sandbox (in-memory database, independent random seed), simulates a month
of known-benign privileged activity, trains a fresh UEBA model on it, then scores
(a) every benign session and (b) the three scripted insider-attack patterns.
Ground truth is exact because the sandbox simulator only produces benign sessions
and the attack patterns are constructed explicitly. Nothing touches the live DB.
"""
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.detection.response import decide
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models.db import Base
from app.models.entities import Event, Session, User

EVAL_DAYS = 30
EVAL_SEED = 11  # independent from the demo seed — this is a held-out world

# The three insider patterns (mirrors app/simulator/attack.py, built unsaved).
ATTACKS = {
    "malicious": {
        "user": "ext_dsouza", "hour": 2,
        "ip": "103.94.55.7", "geo": "Unknown (VPN exit)", "device": "LAPTOP-UNREG",
        "steps": [(0, "LOGIN", "pam-gateway", 0), (2, "PRIV_CHANGE", "core-banking-db", 0),
                  (5, "DB_QUERY", "core-banking-db", 300), (9, "DB_EXPORT", "core-banking-db", 5000)],
        "expected": "BLOCK",
    },
    "compromised": {
        "user": "akulkarni", "hour": 22,
        "ip": "203.0.113.45", "geo": "Singapore, SG", "device": "LAPTOP-UNKNOWN",
        "steps": [(0.0, "LOGIN", "pam-gateway", 0), (0.3, "DB_QUERY", "app-server-01", 90),
                  (0.6, "DB_QUERY", "app-server-02", 120), (0.9, "FILE_ACCESS", "backup-server", 0),
                  (1.2, "DB_QUERY", "app-server-01", 80), (1.5, "CONFIG_CHANGE", "app-server-02", 0)],
        "expected": "STEP_UP_MFA",
    },
    "negligent": {
        "user": "ext_rao", "hour": 14,
        "ip": "10.20.19.11", "geo": "Pune, IN", "device": "LAPTOP-HOME",
        "steps": [(0, "LOGIN", "pam-gateway", 0), (3, "FILE_ACCESS", "report-server", 0),
                  (8, "DB_QUERY", "report-server", 120)],
        "expected": "MAKER_CHECKER",
    },
}

_cache: dict | None = None


def _attack_events(user: User, spec: dict) -> list[Event]:
    t0 = datetime.now().replace(hour=spec["hour"], minute=0, second=0, microsecond=0)
    return [Event(user_id=user.id, session_id=None, action_type=action, resource=resource,
                  records_touched=records, source_ip=spec["ip"], geo=spec["geo"],
                  device=spec["device"], timestamp=t0 + timedelta(minutes=minutes))
            for minutes, action, resource, records in spec["steps"]]


def run_evaluation(force: bool = False) -> dict:
    """Benchmark the detector; cached after the first run (sandboxed, ~seconds)."""
    global _cache
    if _cache is not None and not force:
        return _cache

    from app.simulator.normal import seed_users, simulate_history

    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    try:
        seed_users(db)
        simulate_history(db, days=EVAL_DAYS, seed=EVAL_SEED)
        db.commit()

        model = UebaModel()
        model.train(db)

        # ---- benign set: every closed simulated session is known-normal ----
        benign = db.query(Session).filter(Session.status == "CLOSED").all()
        challenged = blocked = held = 0
        for s in benign:
            events = sorted(s.events, key=lambda e: e.timestamp)
            a = assess(s.user, events, model)
            action, _ = decide(a.score, a.insider_type)
            if action == "BLOCK":
                blocked += 1
            elif action == "MAKER_CHECKER":
                held += 1
            elif action == "STEP_UP_MFA":
                challenged += 1

        # ---- attack set: the three insider patterns, ground truth by construction ----
        attacks = []
        for kind, spec in ATTACKS.items():
            user = db.query(User).filter_by(username=spec["user"]).first()
            a = assess(user, _attack_events(user, spec), model)
            action, _ = decide(a.score, a.insider_type)
            attacks.append({"kind": kind, "score": round(a.score, 1),
                            "insider_type": a.insider_type, "response": action,
                            "expected": spec["expected"],
                            "detected": action != "ALLOW",
                            "correct_response": action == spec["expected"],
                            "correct_type": a.insider_type == kind})

        n = len(benign)
        _cache = {
            "methodology": (f"Held-out sandbox: {EVAL_DAYS} days of simulated benign privileged "
                            f"activity (seed {EVAL_SEED}, never seen in the demo) + the three "
                            f"scripted insider patterns. Ground truth is exact by construction."),
            "benign_sessions": n,
            "false_blocks": blocked,
            "false_holds": held,
            "false_challenges": challenged,
            "false_block_rate": round(blocked / n, 4) if n else 0.0,
            "false_alarm_rate": round((blocked + held + challenged) / n, 4) if n else 0.0,
            "attacks": attacks,
            "detection_rate": round(sum(a["detected"] for a in attacks) / len(attacks), 4),
            "typing_accuracy": round(sum(a["correct_type"] for a in attacks) / len(attacks), 4),
            "response_accuracy": round(sum(a["correct_response"] for a in attacks) / len(attacks), 4),
            "evaluated_at": datetime.now().isoformat(timespec="seconds"),
        }
        return _cache
    finally:
        db.close()
