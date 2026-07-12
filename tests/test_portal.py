"""Tests for auth + the live employee portal (login, action scoring, enforcement)."""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.routes as routes
from app.models import entities  # noqa: F401
from app.models.db import Base
from app.security import auth
from app.security.auth import hash_password, verify_password, create_token, decode_token
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app.main import app
    from app.security import keys

    monkeypatch.setattr(keys, "KEYS_DIR", tmp_path / "keys")
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    seed_users(session)
    simulate_history(session, days=14, seed=3, end=datetime(2026, 7, 3, 12, 0))
    session.commit()
    app.dependency_overrides[auth.get_db] = lambda: session
    routes._model.__init__()  # fresh untrained model per test
    yield TestClient(app)
    app.dependency_overrides.clear()
    routes._model.__init__()
    session.close()


def _login(client, user, pw="prahari123"):
    r = client.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    if r.json().get("mfa_required"):  # risk-based login challenge (dormant/expired/vendor)
        r = client.post("/auth/login", json={"username": user, "password": pw,
                                             "mfa_code": "246810"})
        assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


# --- primitives ---

def test_password_hash_roundtrip():
    h = hash_password("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)


def test_token_roundtrip_and_tamper():
    class U:  # minimal stand-in
        username, role, account_type, name = "x", "DBA", "EMPLOYEE", "X"
    tok = create_token(U())
    assert decode_token(tok)["sub"] == "x"
    with pytest.raises(Exception):
        decode_token(tok[:-2] + "zz")  # broken signature


# --- auth ---

def test_login_rejects_bad_password(client):
    assert client.post("/auth/login", json={"username": "rmehta",
                                             "password": "nope"}).status_code == 401


def test_employee_cannot_reach_soc(client):
    h = _login(client, "rmehta")
    assert client.get("/soc/live", headers=h).status_code == 403


def test_analyst_can_reach_soc(client):
    h = _login(client, "soc_admin")
    assert client.get("/soc/live", headers=h).status_code == 200


# --- live portal ---

def test_normal_activity_allowed(client):
    h = _login(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)
    r = client.post("/portal/action", headers=h,
                    json={"action": "DB_QUERY", "resource": "core-banking-db", "records": 80})
    body = r.json()
    assert body["allowed"] and body["decision"] == "ALLOW" and body["score"] < 40


def test_vendor_attack_is_blocked(client):
    h = _login(client, "ext_dsouza")
    client.post("/portal/bootstrap", headers=h)
    # A dormant vendor escalating privilege out-of-role is at minimum a held,
    # never-allowed action (maker-checker or block).
    r = client.post("/portal/action", headers=h,
                    json={"action": "PRIV_CHANGE", "resource": "core-banking-db"}).json()
    assert not r["allowed"] and r["decision"] in ("MAKER_CHECKER", "BLOCK")
    # The actual theft — bulk export of 5000 records — is unconditionally BLOCKED.
    r2 = client.post("/portal/action", headers=h,
                     json={"action": "DB_EXPORT", "resource": "core-banking-db",
                           "records": 5000}).json()
    assert not r2["allowed"] and r2["decision"] == "BLOCK" and r2["score"] >= 85
    assert r2["session"]["status"] == "BLOCKED"
    # session frozen: all further actions denied
    r3 = client.post("/portal/action", headers=h,
                     json={"action": "DB_QUERY", "resource": "test-db", "records": 1}).json()
    assert not r3["allowed"] and r3["session"]["status"] == "BLOCKED"
    # SOC sees the blocked session
    ha = _login(client, "soc_admin")
    live = client.get("/soc/live", headers=ha).json()
    assert any(s["user"] == "ext_dsouza" and s["status"] == "BLOCKED" for s in live)


def test_step_up_mfa_unblocks_without_stacking_events(client):
    h = _login(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)
    held = client.post("/portal/action", headers=h,
                       json={"action": "DB_EXPORT", "resource": "core-banking-db",
                             "records": 1000}).json()
    assert held["decision"] == "STEP_UP_MFA" and not held["allowed"]
    ok = client.post("/portal/action", headers=h,
                     json={"action": "DB_EXPORT", "resource": "core-banking-db",
                           "records": 1000, "mfa_code": "246810"}).json()
    assert ok["allowed"]
    # LOGIN + exactly one export event (retry did not stack)
    exports = [e for e in ok["session"]["events"] if e["action"] == "DB_EXPORT"]
    assert len(exports) == 1


# --- SOC triage resolution ---

def test_soc_approve_resolves_session_but_keeps_score(client):
    ha = _login(client, "soc_admin")
    sc = client.post("/demo/scenario/compromised", headers=ha).json()
    sid = sc["session_id"]
    before = next(s for s in client.get("/soc/overview", headers=ha).json()["sessions"] if s["id"] == sid)
    assert before["review_status"] is None and before["score"] >= 40

    r = client.post(f"/soc/sessions/{sid}/approve", headers=ha).json()
    assert r["review_status"] == "APPROVED"
    after = next(s for s in client.get("/soc/overview", headers=ha).json()["sessions"] if s["id"] == sid)
    assert after["review_status"] == "APPROVED" and after["reviewed_by"] == "soc_admin"
    assert after["score"] == before["score"]                 # history preserved, not rewritten


def test_soc_dismiss_marks_session_reviewed(client):
    ha = _login(client, "soc_admin")
    sid = client.post("/demo/scenario/negligent", headers=ha).json()["session_id"]
    client.post(f"/soc/sessions/{sid}/dismiss", headers=ha)
    row = next(s for s in client.get("/soc/overview", headers=ha).json()["sessions"] if s["id"] == sid)
    assert row["review_status"] == "DISMISSED"
