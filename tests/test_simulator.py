"""Phase 1 tests: models + normal-day simulator."""
import random
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import entities  # noqa: F401
from app.models.db import Base
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def test_seed_users_idempotent(db):
    users = seed_users(db)
    assert len(seed_users(db)) == len(users) == 10  # 9 employees (incl. approving officer) + 1 SOC analyst
    dormant = [u for u in users if u.is_dormant]
    assert len(dormant) == 1 and dormant[0].is_vendor
    expired = [u for u in users if u.access_expires_at]
    assert {u.username for u in expired} == {"ext_dsouza", "ext_rao"}
    analysts = [u for u in users if u.account_type == "ANALYST"]
    assert len(analysts) == 1 and analysts[0].username == "soc_admin"
    assert all(u.password_hash for u in users)  # everyone can authenticate


def test_history_is_normal_business_hours(db):
    seed_users(db)
    n = simulate_history(db, days=10, seed=1, end=datetime(2026, 7, 3, 12, 0))
    events = db.query(entities.Event).all()
    assert len(events) == n > 100
    # all activity in daytime, none from the dormant account
    dormant_id = db.query(entities.User).filter_by(is_dormant=True).one().id
    for e in events:
        assert 9 <= e.timestamp.hour < 20  # daytime start, late sessions may drift into evening
        assert e.user_id != dormant_id
    # sessions have bounded windows
    for s in db.query(entities.Session).all():
        assert s.ended_at is not None and s.ended_at > s.started_at


def test_deterministic_with_seed(db):
    seed_users(db)
    rng_end = datetime(2026, 7, 3, 12, 0)
    n1 = simulate_history(db, days=5, seed=7, end=rng_end)
    n2 = simulate_history(db, days=5, seed=7, end=rng_end)
    assert n1 == n2
