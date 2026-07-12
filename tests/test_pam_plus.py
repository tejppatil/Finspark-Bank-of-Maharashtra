"""Tests for risk-based login, PQC credential checkout, and just-in-time access."""
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.api.routes as routes
from app.models import entities
from app.models.db import Base
from app.security import auth
from app.simulator.normal import seed_users, simulate_history


@pytest.fixture()
def env(tmp_path, monkeypatch):
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
    from app.bank import seed_bank
    from app.security.vault import seed_credentials
    seed_credentials(session)
    seed_bank(session)
    app.dependency_overrides[auth.get_db] = lambda: session
    routes._model.__init__()
    yield TestClient(app), session
    app.dependency_overrides.clear()
    routes._model.__init__()
    session.close()


def _token(client, user, mfa=None):
    body = {"username": user, "password": "prahari123"}
    if mfa:
        body["mfa_code"] = mfa
    r = client.post("/auth/login", json=body)
    return r


def _headers(client, user, mfa=None):
    r = _token(client, user, mfa)
    assert r.status_code == 200 and "token" in r.json(), r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


# --- risk-based authentication (adaptive login) ---

def test_trusted_login_needs_no_mfa(env):
    client, _ = env
    r = _token(client, "rmehta")
    assert r.status_code == 200 and "token" in r.json()
    assert not r.json().get("mfa_required")


def test_dormant_account_is_challenged_at_the_door(env):
    client, _ = env
    r = _token(client, "ext_dsouza")
    assert r.status_code == 200 and r.json()["mfa_required"]
    assert "token" not in r.json()
    assert any("dormant" in f for f in r.json()["factors"])


def test_wrong_login_mfa_rejected_and_alerted(env):
    client, db = env
    r = _token(client, "ext_dsouza", mfa="000000")
    assert r.status_code == 401
    alerts = db.query(entities.Alert).all()
    assert any("Failed step-up MFA at login" in a.message for a in alerts)


def test_correct_login_mfa_issues_token_and_audits(env):
    client, db = env
    r = _token(client, "ext_dsouza", mfa="246810")
    assert r.status_code == 200 and "token" in r.json()
    actions = {e.action for e in db.query(entities.AuditLogEntry).all()}
    assert "LOGIN_MFA_VERIFIED" in actions


def test_expired_vendor_is_challenged(env):
    client, _ = env
    r = _token(client, "ext_rao")
    assert r.json()["mfa_required"]
    assert any("expired" in f for f in r.json()["factors"])


# --- PQC credential checkout ---

def test_low_risk_checkout_returns_secret_with_lease(env):
    client, db = env
    h = _headers(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)
    names = client.get("/vault/credentials", headers=h).json()["credentials"]
    assert "core-banking-db-root" in names
    r = client.post("/vault/checkout", headers=h, json={"name": "core-banking-db-root"})
    assert r.status_code == 200
    body = r.json()
    assert body["secret"] and body["status"] == "ACTIVE" and body["remaining_seconds"] > 0
    actions = {e.action for e in db.query(entities.AuditLogEntry).all()}
    assert "CREDENTIAL_CHECKOUT" in actions


def test_high_risk_session_is_refused_checkout(env):
    client, db = env
    h = _headers(client, "ext_dsouza", mfa="246810")
    client.post("/portal/bootstrap", headers=h)
    # drive the session to a blocked/high-risk state
    client.post("/portal/action", headers=h,
                json={"action": "DB_EXPORT", "resource": "core-banking-db", "records": 5000})
    r = client.post("/vault/checkout", headers=h, json={"name": "core-banking-db-root"})
    assert r.status_code == 403
    rows = db.query(entities.CredentialCheckout).all()
    assert any(c.status == "DENIED" for c in rows)  # the refusal is evidence
    actions = {e.action for e in db.query(entities.AuditLogEntry).all()}
    assert "CHECKOUT_DENIED" in actions


def test_checkout_lease_expires(env):
    client, db = env
    h = _headers(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)
    client.post("/vault/checkout", headers=h, json={"name": "payment-gateway-api-key"})
    co = db.query(entities.CredentialCheckout).filter_by(status="ACTIVE").first()
    co.expires_at = datetime.now() - timedelta(seconds=1)
    db.commit()
    mine = client.get("/vault/credentials", headers=h).json()["my_checkouts"]
    assert all(c["status"] != "ACTIVE" for c in mine)


def test_soc_sees_all_checkouts(env):
    client, _ = env
    h = _headers(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)
    client.post("/vault/checkout", headers=h, json={"name": "core-banking-db-root"})
    ha = _headers(client, "soc_admin")
    rows = client.get("/soc/checkouts", headers=ha).json()
    assert any(c["name"] == "core-banking-db-root" and c["user"] == "rmehta" for c in rows)


# --- just-in-time access ---

def test_jit_lifecycle_and_sanctioned_escalation(env):
    client, db = env
    h = _headers(client, "rmehta")
    client.post("/portal/bootstrap", headers=h)

    # without a grant, escalation fires the malicious rule (never plain-ALLOW)
    r0 = client.post("/portal/action", headers=h,
                     json={"action": "PRIV_CHANGE", "resource": "core-banking-db"}).json()
    assert any("Privilege change" in x for x in r0["reasons"])

    # request -> pending
    g = client.post("/jit/request", headers=h,
                    json={"privilege": "core-banking-db",
                          "justification": "quarterly schema migration",
                          "duration_minutes": 15}).json()
    assert g["status"] == "PENDING"

    # analyst approves -> active, time-boxed
    ha = _headers(client, "soc_admin")
    queue = client.get("/soc/jit", headers=ha).json()
    assert any(q["id"] == g["id"] and q["status"] == "PENDING" for q in queue)
    ap = client.post(f"/soc/jit/{g['id']}/approve", headers=ha).json()
    assert ap["status"] == "ACTIVE" and ap["remaining_seconds"] > 0

    # the same escalation is now sanctioned: rule does not fire
    r1 = client.post("/portal/action", headers=h,
                     json={"action": "PRIV_CHANGE", "resource": "core-banking-db"}).json()
    assert not any("outside normal grant process" in x for x in r1["reasons"])
    assert any("sanctioned by an approved JIT grant" in x for x in r1["reasons"])

    # grant auto-expires -> escalation is hostile again
    grant = db.get(entities.JitGrant, g["id"])
    grant.expires_at = datetime.now() - timedelta(seconds=1)
    db.commit()
    mine = client.get("/jit/mine", headers=h).json()
    assert any(m["id"] == g["id"] and m["status"] == "EXPIRED" for m in mine)


def test_jit_deny_and_validation(env):
    client, _ = env
    h = _headers(client, "rmehta")
    g = client.post("/jit/request", headers=h,
                    json={"privilege": "hr-payroll-db", "justification": "urgent fix",
                          "duration_minutes": 10}).json()
    ha = _headers(client, "soc_admin")
    d = client.post(f"/soc/jit/{g['id']}/deny", headers=ha).json()
    assert d["status"] == "DENIED"
    # a denied grant never sanctions anything
    assert client.post("/jit/request", headers=h,
                       json={"privilege": "x", "justification": "  ",
                             "duration_minutes": 10}).status_code == 400  # blank justification
    assert client.post("/jit/request", headers=h,
                       json={"privilege": "x", "justification": "y",
                             "duration_minutes": 999}).status_code == 400  # over max


def test_jit_endpoints_are_role_gated(env):
    client, _ = env
    h = _headers(client, "rmehta")
    ha = _headers(client, "soc_admin")
    assert client.get("/soc/jit", headers=h).status_code == 403       # employee -> SOC: no
    assert client.get("/jit/mine", headers=ha).status_code == 403     # analyst -> portal: no


# --- SOC triage clears the banking alert when the officer resolves the transfer ---

def test_officer_resolution_clears_banking_alert(env):
    client, _ = env
    maker = _headers(client, "rmehta")
    officer = _headers(client, "dgokhale")
    analyst = _headers(client, "soc_admin")
    client.post("/portal/bootstrap", headers=maker)
    t = client.post("/bank/transfer", headers=maker,
                    json={"from_number": "50100000004821", "to_number": "59990000001111",
                          "amount": 30000, "mode": "NEFT"}).json()
    assert t["status"] == "FLAGGED"
    alerts = client.get("/soc/alerts", headers=analyst).json()
    assert any(a["message"].startswith("Banking:") and not a["resolved"] for a in alerts)

    client.post(f"/bank/transactions/{t['transaction']['id']}/resolve-fraud",
                headers=officer, json={"decision": "confirm"})
    alerts = client.get("/soc/alerts", headers=analyst).json()
    assert any(a["message"].startswith("Banking:") and a["resolved"] for a in alerts)  # cleared


# --- measured model performance ---

def test_model_evaluation_benchmarks_detector(env):
    client, _ = env
    ha = _headers(client, "soc_admin")
    r = client.get("/soc/model/eval", headers=ha)
    assert r.status_code == 200
    ev = r.json()
    assert ev["benign_sessions"] > 100
    assert ev["false_blocks"] == 0                    # no benign session is ever blocked
    assert ev["detection_rate"] == 1.0                # all three attacks detected
    assert ev["response_accuracy"] == 1.0             # ...with the correct response
    assert ev["typing_accuracy"] == 1.0               # ...and the correct insider type
    assert ev["false_alarm_rate"] < 0.05


# --- signed incident report ---

def test_incident_report_is_complete_and_pqc_signed(env):
    import base64
    import hashlib
    import json as jsonlib

    client, db = env
    h = _headers(client, "ext_dsouza", mfa="246810")
    client.post("/portal/bootstrap", headers=h)
    client.post("/portal/action", headers=h,
                json={"action": "DB_EXPORT", "resource": "core-banking-db", "records": 5000})
    sess = db.query(entities.Session).filter(entities.Session.status == "BLOCKED").first()
    ha = _headers(client, "soc_admin")
    r = client.get(f"/soc/sessions/{sess.id}/report", headers=ha)
    assert r.status_code == 200
    pack = r.json()
    rep = pack["report"]
    assert rep["session"]["user"] == "ext_dsouza" and rep["session"]["status"] == "BLOCKED"
    assert rep["session"]["risk_score"] >= 85          # score at decision time
    assert rep["assessment"]["score"] >= 40 and rep["risk_trajectory"]
    assert rep["session_transcript"] and rep["audit_chain"]["entries_checked"] >= 1
    assert rep["model_insights"]["features"] and rep["assessment"]["rules_fired"]

    # the ML-DSA signature verifies over the canonical report JSON
    from app.security import keys, pqc
    canonical = jsonlib.dumps(rep, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == pack["evidence_sha256"]
    pub, _ = keys.audit_keypair()
    assert pqc.verify(pub, canonical, base64.b64decode(pack["signature"]))
    # a tampered report fails verification
    bad = canonical.replace(b"BLOCKED", b"ALLOWED", 1)
    assert not pqc.verify(pub, bad, base64.b64decode(pack["signature"]))
