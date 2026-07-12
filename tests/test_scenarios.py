"""The three insider scenarios must drive three distinct, correctly-typed responses."""
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.detection.response import decide, respond
from app.detection.rules import evaluate, dominant_insider_type
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models import entities  # noqa: F401
from app.models.db import Base
from app.simulator.attack import (trigger_compromised, trigger_malicious,
                                   trigger_negligent)
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    seed_users(s)
    simulate_history(s, days=14, seed=3, end=datetime(2026, 7, 3, 12, 0))
    yield s
    s.close()


def _assess(db, trigger):
    model = UebaModel()
    model.train(db)
    sess = trigger(db)
    a = assess(sess.user, sorted(sess.events, key=lambda e: e.timestamp), model)
    action, _ = decide(a.score, a.insider_type)
    return a, action


def test_malicious_blocks(db):
    a, action = _assess(db, trigger_malicious)
    assert a.insider_type == "malicious" and action == "BLOCK" and a.score >= 85


def test_compromised_steps_up(db):
    a, action = _assess(db, trigger_compromised)
    assert a.insider_type == "compromised" and action == "STEP_UP_MFA"


def test_negligent_goes_to_maker_checker(db):
    a, action = _assess(db, trigger_negligent)
    assert a.insider_type == "negligent" and action == "MAKER_CHECKER"


def test_negligence_is_never_auto_blocked():
    # Policy: even at a blocking score, a negligent session is capped at maker-checker.
    assert decide(99, "negligent")[0] == "MAKER_CHECKER"
    assert decide(99, "malicious")[0] == "BLOCK"


def test_three_scenarios_are_distinct(db):
    actions = {
        _assess(db, trigger_malicious)[1],
        _assess(db, trigger_compromised)[1],
        _assess(db, trigger_negligent)[1],
    }
    assert actions == {"BLOCK", "STEP_UP_MFA", "MAKER_CHECKER"}
