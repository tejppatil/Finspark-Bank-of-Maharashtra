"""Phase 3 tests: attack trigger, adaptive response, WebSocket feed."""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.routes as routes
from app.detection.response import decide, respond
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models import entities
from app.models.db import Base
from app.models.entities import Alert
from app.simulator.attack import trigger_attack
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def db():
    # TestClient serves the app from a worker thread; StaticPool +
    # check_same_thread=False lets it share this in-memory DB safely.
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    seed_users(session)
    simulate_history(session, days=14, seed=3, end=datetime(2026, 7, 3, 12, 0))
    yield session
    session.close()


def test_decide_thresholds():
    assert decide(10)[0] == "ALLOW"
    assert decide(50)[0] == "STEP_UP_MFA"
    assert decide(75)[0] == "MAKER_CHECKER"
    assert decide(90)[0] == "BLOCK"


def test_attack_gets_blocked_with_alert(db):
    model = UebaModel()
    model.train(db)
    sess = trigger_attack(db)
    assessment = assess(sess.user, sorted(sess.events, key=lambda e: e.timestamp), model)
    decision = respond(db, sess.user, sess, assessment)
    assert decision.action == "BLOCK"
    alert = db.get(Alert, decision.alert_id)
    assert alert.severity == "CRITICAL" and "dormant" in alert.message.lower()


def test_demo_attack_endpoint_and_websocket(db, monkeypatch, tmp_path):
    """Full loop: analyst logs in, WS connected, POST /demo/attack, receive alert frame."""
    from app.main import app
    from app.security import auth, keys

    monkeypatch.setattr(keys, "KEYS_DIR", tmp_path / "keys")  # isolate keystore
    # Depends(get_db) resolves to auth.get_db everywhere now — override that object.
    app.dependency_overrides[auth.get_db] = lambda: db
    routes._model = UebaModel()  # force retrain on this test DB
    client = TestClient(app)
    try:
        token = client.post("/auth/login", json={"username": "soc_admin",
                                                  "password": "prahari123"}).json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        with client.websocket_connect("/ws/feed") as ws:
            r = client.post("/demo/attack", headers=h)
            assert r.status_code == 200
            body = r.json()
            assert body["score"] >= 85 and body["action"] == "BLOCK"
            frame = ws.receive_json()
            assert frame["type"] == "alert" and frame["action"] == "BLOCK"
            assert any("5000" in x or "records" in x for x in frame["reasons"])
        # SOC endpoints require the analyst token; without it they are rejected.
        assert client.get("/soc/alerts").status_code in (401, 403)
        alerts = client.get("/soc/alerts", headers=h).json()
        assert alerts and alerts[0]["action_taken"] == "BLOCK"
    finally:
        app.dependency_overrides.clear()
        routes._model = UebaModel()
