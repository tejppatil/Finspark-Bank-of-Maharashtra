"""Phase 2 tests: rules, UEBA, and combined risk scoring."""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.detection.rules import evaluate
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models import entities
from app.models.db import Base
from app.models.entities import Event, User
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    seed_users(session)
    simulate_history(session, days=14, seed=3, end=datetime(2026, 7, 3, 12, 0))
    yield session
    session.close()


def _attack_events(user: User) -> list[Event]:
    """2 AM dormant-vendor session: escalate privilege, bulk-export 5000 records."""
    t0 = datetime(2026, 7, 4, 2, 0)
    common = dict(user_id=user.id, source_ip="103.94.55.7", geo="Unknown, RU",
                  device="LAPTOP-UNKNOWN")
    return [
        Event(action_type="LOGIN", resource="pam-gateway", records_touched=0,
              timestamp=t0, **common),
        Event(action_type="PRIV_CHANGE", resource="core-banking-db", records_touched=0,
              timestamp=t0 + timedelta(minutes=3), **common),
        Event(action_type="DB_EXPORT", resource="core-banking-db", records_touched=5000,
              timestamp=t0 + timedelta(minutes=7), **common),
    ]


def _trained(db) -> UebaModel:
    model = UebaModel()
    assert model.train(db) > 50
    return model


def test_rules_fire_on_attack(db):
    vendor = db.query(User).filter_by(is_dormant=True).one()
    hits = {h.rule for h in evaluate(vendor, _attack_events(vendor))}
    assert {"DORMANT_REACTIVATION", "PRIVILEGE_ESCALATION", "AFTER_HOURS_ACCESS",
            "MASS_EXPORT", "NO_BUSINESS_RELATIONSHIP"} <= hits


def test_rules_quiet_on_normal(db):
    # A clean permanent-staff session should fire no rules at all.
    rmehta = db.query(User).filter_by(username="rmehta").one()
    sess = next(s for s in db.query(entities.Session).all() if s.user_id == rmehta.id)
    assert evaluate(sess.user, sess.events) == []


def test_normal_sessions_score_low(db):
    # Permanent staff behaving normally stay well below the step-up threshold.
    # (Expired-access vendors like ext_rao are legitimately elevated and excluded.)
    model = _trained(db)
    clean = {"rmehta", "spatil", "akulkarni", "pjoshi", "vdeshmukh", "nshinde"}
    scores = [assess(s.user, s.events, model).score
              for s in db.query(entities.Session).limit(30).all()
              if s.user.username in clean]
    assert max(scores) < 40


def test_attack_scores_high_with_reasons(db):
    model = _trained(db)
    vendor = db.query(User).filter_by(is_dormant=True).one()
    result = assess(vendor, _attack_events(vendor), model)
    assert result.score >= 80
    text = " ".join(result.reasons).lower()
    assert "dormant" in text and "records" in text
    assert len(result.rule_hits) >= 4
