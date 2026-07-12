"""REST + WebSocket API: auth, employee portal, SOC console, PQC layer."""
import base64
import hashlib
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, WebSocket
from pydantic import BaseModel
from sqlalchemy.orm import Session as OrmSession

from app import bank, jit
from app.api.ws import feed_endpoint, manager
from app.config import settings
from app.detection import live
from app.detection.evaluate import run_evaluation
from app.detection.response import decide, respond
from app.detection.rules import dominant_insider_type, evaluate
from app.detection.score import assess
from app.detection.ueba import UebaModel
from app.models.entities import Alert, AuditLogEntry, Session, SessionCommand, User
from app.pam import access_review
from app.security import audit, keys, pqc, vault
from app.security.auth import (create_token, current_user, get_db, require_analyst,
                               verify_password)
from app.simulator.attack import (trigger_compromised, trigger_malicious,
                                   trigger_negligent)
from app.simulator.normal import RESOURCES_BY_ROLE

SCENARIOS = {"malicious": trigger_malicious, "compromised": trigger_compromised,
             "negligent": trigger_negligent}

router = APIRouter()
_model = UebaModel()

ALL_RESOURCES = [{"name": r, "owner_role": role}
                 for role, rs in RESOURCES_BY_ROLE.items() for r in rs]


def get_model(db: OrmSession) -> UebaModel:
    """Lazy-train the shared UEBA model on first use."""
    if not _model.is_trained:
        _model.train(db)
    return _model


def _login_identity(user: User) -> tuple[str, str, str]:
    """Connection profile for a login. A dormant/vendor account inherently comes
    from an untrusted context (this is what makes the attack realistic)."""
    if user.is_dormant or user.is_vendor:
        return "103.94.55.7", "Unknown (VPN exit)", "LAPTOP-UNREG"
    return f"10.20.{10 + user.id}.11", "Pune, IN", f"WKS-{user.username.upper()}"


async def _broadcast_activity(user: User, sess: Session, outcome: live.ActionOutcome,
                              action: str, resource: str) -> None:
    await manager.broadcast({
        "type": "activity",
        "session_id": sess.id, "user": user.username, "name": user.name,
        "role": user.role, "action": action, "resource": resource,
        "score": round(outcome.score, 1), "decision": outcome.decision,
        "allowed": outcome.allowed, "status": outcome.session_status,
        "insider_type": outcome.insider_type, "reasons": outcome.reasons,
    })
    if outcome.decision != "ALLOW":
        await manager.broadcast({
            "type": "alert", "session_id": sess.id, "user": user.username,
            "role": user.role, "severity": outcome.severity, "action": outcome.decision,
            "insider_type": outcome.insider_type,
            "score": round(outcome.score, 1), "reasons": outcome.reasons,
        })


# ======================= AUTH =======================

class LoginIn(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


def _login_risk_factors(user: User) -> list[str]:
    """Risk-based authentication: context signals that harden the front door.

    A correct password is not enough when the account itself is suspicious —
    the same signals the detection engine scores are checked *at login*, and any
    hit demands step-up MFA before a token is issued.
    """
    factors = []
    if user.is_dormant:
        factors.append("dormant account waking up")
    if user.access_expires_at and user.access_expires_at < datetime.now():
        days = (datetime.now() - user.access_expires_at).days
        factors.append(f"access grant expired {days} days ago")
    if user.is_dormant or user.is_vendor:
        # dormant/vendor logins arrive from an unregistered context (VPN exit, unknown device)
        factors.append("login from unrecognized network/device context")
    return factors


@router.post("/auth/login")
async def login(body: LoginIn, db: OrmSession = Depends(get_db)) -> dict:
    user = db.query(User).filter_by(username=body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "invalid username or password")

    factors = _login_risk_factors(user)
    if factors:
        if not body.mfa_code:
            audit.append_entry(db, actor="prahari-auth", action="LOGIN_CHALLENGED",
                               payload=f"user={user.username} factors={'; '.join(factors)}")
            return {"mfa_required": True, "factors": factors,
                    "message": "Risk-based authentication: step-up verification required."}
        if body.mfa_code != settings.mfa_code:
            audit.append_entry(db, actor="prahari-auth", action="LOGIN_MFA_FAILED",
                               payload=f"user={user.username} factors={'; '.join(factors)}")
            db.add(Alert(user_id=user.id, session_id=None, severity="WARNING",
                         action_taken="STEP_UP_MFA", insider_type=None,
                         message=f"Failed step-up MFA at login for risky account "
                                 f"'{user.username}' ({'; '.join(factors)})"))
            db.commit()
            await manager.broadcast({"type": "alert", "user": user.username, "role": user.role,
                                     "severity": "WARNING", "action": "MFA_FAILED",
                                     "score": 0, "insider_type": None,
                                     "reasons": [f"Failed login MFA: {f}" for f in factors]})
            raise HTTPException(401, "invalid MFA code")
        audit.append_entry(db, actor="prahari-auth", action="LOGIN_MFA_VERIFIED",
                           payload=f"user={user.username} factors={'; '.join(factors)}")

    return {"token": create_token(user), "user": {
        "username": user.username, "name": user.name, "role": user.role,
        "account_type": user.account_type, "is_dormant": user.is_dormant,
        "is_vendor": user.is_vendor}}


@router.get("/auth/me")
def me(user: User = Depends(current_user)) -> dict:
    return {"username": user.username, "name": user.name, "role": user.role,
            "account_type": user.account_type}


# ======================= EMPLOYEE PORTAL =======================

class ActionIn(BaseModel):
    action: str
    resource: str
    records: int | None = None
    mfa_code: str | None = None


def _employee(user: User = Depends(current_user)) -> User:
    if user.account_type != "EMPLOYEE":
        raise HTTPException(403, "employee account required for the portal")
    return user


def _session_state(sess: Session) -> dict:
    return {"id": sess.id, "status": sess.status, "score": round(sess.risk_score, 1),
            "started_at": sess.started_at.isoformat(), "source_ip": sess.source_ip,
            "geo": sess.geo, "device": sess.device,
            "reasons": json.loads(sess.risk_reasons or "[]"),
            "events": [{"t": e.timestamp.isoformat(), "action": e.action_type,
                        "resource": e.resource, "records": e.records_touched}
                       for e in sorted(sess.events, key=lambda e: e.timestamp)]}


async def _broadcast_presence(user: User, sess: Session, event: str) -> None:
    """Tell every connected SOC console that the live-session set changed."""
    await manager.broadcast({
        "type": "presence", "event": event, "session_id": sess.id,
        "user": user.username, "role": user.role, "status": sess.status,
        "score": round(sess.risk_score, 1),
    })


@router.post("/portal/bootstrap")
async def portal_bootstrap(user: User = Depends(_employee),
                           db: OrmSession = Depends(get_db)) -> dict:
    """Open the employee's live session and return everything the portal needs."""
    get_model(db)  # ensure baseline trained before any live scoring
    ip, geo, device = _login_identity(user)
    sess = live.open_session(db, user, ip, geo, device)
    await _broadcast_presence(user, sess, "login")  # SOC sees the session appear instantly
    return {
        "user": {"username": user.username, "name": user.name, "role": user.role,
                 "is_vendor": user.is_vendor, "is_dormant": user.is_dormant},
        "session": _session_state(sess),
        "my_resources": RESOURCES_BY_ROLE.get(user.role, []),
        "all_resources": ALL_RESOURCES,
        "catalog": live.ACTION_CATALOG,
    }


@router.get("/portal/session")
def portal_session(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> dict:
    """Current live-session state — polled by the portal so its gauge/log stay live."""
    sess = (db.query(Session)
            .filter(Session.user_id == user.id, Session.status.in_(["ACTIVE", "BLOCKED"]))
            .order_by(Session.id.desc()).first())
    return {"session": _session_state(sess)} if sess else {"session": None}


@router.post("/portal/action")
async def portal_action(body: ActionIn, user: User = Depends(_employee),
                        db: OrmSession = Depends(get_db)) -> dict:
    if body.action not in live.ACTION_CATALOG:
        raise HTTPException(400, f"unknown action '{body.action}'")
    ip, geo, device = _login_identity(user)
    sess = live.open_session(db, user, ip, geo, device)  # reuses active / stays-locked if blocked

    records = body.records if body.records is not None \
        else live.ACTION_CATALOG[body.action]["default_records"]
    mfa_ok = bool(body.mfa_code) and body.mfa_code == settings.mfa_code

    outcome = live.perform_action(db, get_model(db), sess, user, body.action,
                                  body.resource, records, mfa_ok=mfa_ok)
    if not outcome.allowed and outcome.decision == "BLOCK":
        audit.append_entry(db, actor="prahari-engine", action="THREAT_BLOCKED",
                           payload=f"user={user.username} session={sess.id} "
                                   f"score={outcome.score:.0f} attempted={body.action}:{body.resource}")
    await _broadcast_activity(user, sess, outcome, body.action, body.resource)
    return {"allowed": outcome.allowed, "decision": outcome.decision,
            "severity": outcome.severity, "score": round(outcome.score, 1),
            "message": outcome.message, "reasons": outcome.reasons,
            "session": _session_state(sess)}


@router.post("/portal/logout")
async def portal_logout(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> dict:
    sess = (db.query(Session)
            .filter(Session.user_id == user.id, Session.status == "ACTIVE")
            .order_by(Session.id.desc()).first())
    if sess:
        live.close_session(db, sess)
        await _broadcast_presence(user, sess, "logout")
    return {"ok": True}


# ======================= CORE BANKING (employee) =======================

class TransferIn(BaseModel):
    from_number: str
    to_number: str
    amount: float
    mode: str = "NEFT"


def _current_live_session(db: OrmSession, user: User) -> Session | None:
    return (db.query(Session)
            .filter(Session.user_id == user.id, Session.status.in_(["ACTIVE", "BLOCKED"]))
            .order_by(Session.id.desc()).first())


def _current_session_risk(db: OrmSession, user: User) -> float:
    sess = _current_live_session(db, user)
    return sess.risk_score if sess else 0.0


@router.get("/bank/accounts")
def bank_accounts(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> list[dict]:
    return bank.accounts(db)


@router.get("/bank/transactions")
def bank_transactions(limit: int = 30, user: User = Depends(_employee),
                      db: OrmSession = Depends(get_db)) -> list[dict]:
    return bank.transactions(db, limit=limit)


@router.get("/bank/pending")
def bank_pending(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> list[dict]:
    return bank.pending(db)


@router.get("/bank/beneficiaries")
def bank_beneficiaries(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> list[dict]:
    return bank.beneficiaries(db)


@router.post("/bank/transfer")
async def bank_transfer(body: TransferIn, user: User = Depends(_employee),
                        db: OrmSession = Depends(get_db)) -> dict:
    try:
        result = bank.transfer(db, body.from_number, body.to_number, body.amount,
                               body.mode, user.username,
                               session_risk=_current_session_risk(db, user))
    except bank.TransferError as e:
        raise HTTPException(400, str(e))
    # A held / flagged transfer raises a SOC alert and flashes both screens.
    if result["alert"]:
        a = result["alert"]
        db.add(Alert(user_id=user.id, session_id=None, severity=a["severity"],
                     action_taken=a["action"], insider_type=None,
                     ref_txn=result["transaction"]["id"],  # so resolving it clears the alert
                     message="Banking: " + a["text"]))
        db.commit()
        audit.append_entry(db, actor="core-banking", action=f"TXN_{a['action']}",
                           payload=a["text"])
        await manager.broadcast({"type": "alert", "user": user.username, "role": user.role,
                                 "severity": a["severity"], "action": a["action"],
                                 "score": round(_current_session_risk(db, user), 1),
                                 "insider_type": None, "reasons": [a["text"]]})
    return result


def _txn_audit_payload(tx: dict, checker: str) -> str:
    """A self-describing audit line for a checker's decision on a transfer."""
    return (f"tx={tx['id']} {tx['status']} amount={tx['amount']:.0f} "
            f"maker={tx['maker']} checker={checker} {tx['from']}->{tx['to']}")


def _clear_txn_alerts(db: OrmSession, tx_id: int) -> None:
    """Resolve the SOC banking alert(s) for a transaction once its review is done."""
    for al in db.query(Alert).filter(Alert.ref_txn == tx_id, Alert.resolved == False).all():  # noqa: E712
        al.resolved = True
    db.commit()


@router.post("/bank/transactions/{tx_id}/approve")
async def bank_tx_approve(tx_id: int, user: User = Depends(_employee),
                          db: OrmSession = Depends(get_db)) -> dict:
    try:
        r = bank.approve(db, tx_id, user.username, user.role)
    except bank.TransferError as e:
        raise HTTPException(400, str(e))
    audit.append_entry(db, actor=user.username, action="TXN_APPROVED",
                       payload=_txn_audit_payload(r["transaction"], user.username))
    _clear_txn_alerts(db, tx_id)
    return r


@router.post("/bank/transactions/{tx_id}/reject")
async def bank_tx_reject(tx_id: int, user: User = Depends(_employee),
                         db: OrmSession = Depends(get_db)) -> dict:
    try:
        r = bank.reject(db, tx_id, user.username, user.role)
    except bank.TransferError as e:
        raise HTTPException(400, str(e))
    audit.append_entry(db, actor=user.username, action="TXN_REJECTED",
                       payload=_txn_audit_payload(r["transaction"], user.username))
    _clear_txn_alerts(db, tx_id)
    return r


class FraudDecisionIn(BaseModel):
    decision: str  # "clear" (false positive -> settle) | "confirm" (fraud -> block)


@router.post("/bank/transactions/{tx_id}/resolve-fraud")
async def bank_tx_resolve_fraud(tx_id: int, body: FraudDecisionIn,
                                user: User = Depends(_employee),
                                db: OrmSession = Depends(get_db)) -> dict:
    """A second officer resolves a FLAGGED transfer: clear it or confirm the fraud."""
    try:
        r = bank.resolve_flag(db, tx_id, user.username, user.role, body.decision)
    except bank.TransferError as e:
        raise HTTPException(400, str(e))
    action = "TXN_FRAUD_CLEARED" if body.decision == "clear" else "TXN_FRAUD_CONFIRMED"
    audit.append_entry(db, actor=user.username, action=action,
                       payload=_txn_audit_payload(r["transaction"], user.username))
    _clear_txn_alerts(db, tx_id)
    await manager.broadcast({"type": "alert", "user": user.username, "role": user.role,
                             "severity": "INFO" if body.decision == "clear" else "CRITICAL",
                             "action": r["status"], "score": 0, "insider_type": None,
                             "reasons": [f"Flagged transfer #{tx_id} {r['status'].lower()} "
                                         f"by officer {user.username}"]})
    return r


# ================= CREDENTIAL CHECKOUT (PQC vault -> PAM workflow) =================

class CheckoutIn(BaseModel):
    name: str


@router.get("/vault/credentials")
def vault_credentials(user: User = Depends(_employee),
                      db: OrmSession = Depends(get_db)) -> dict:
    """The credential desk: what can be checked out + this user's checkout history."""
    return vault.list_credentials(db, user)


@router.post("/vault/checkout")
async def vault_checkout(body: CheckoutIn, user: User = Depends(_employee),
                         db: OrmSession = Depends(get_db)) -> dict:
    """Time-boxed credential checkout, gated by the caller's live session risk.

    The secret is unsealed from the ML-KEM-768 vault only if the session is
    trusted; the checkout (or the refusal) is signed into the audit chain and
    broadcast to the SOC.
    """
    sess = _current_live_session(db, user)
    risk = sess.risk_score if sess else 0.0
    blocked = bool(sess and sess.status == "BLOCKED")
    try:
        result = vault.checkout_credential(db, user, body.name, risk,
                                           sess.id if sess else None, session_blocked=blocked)
    except KeyError:
        raise HTTPException(404, f"no vault item named '{body.name}'")
    except vault.CheckoutDenied as e:
        audit.append_entry(db, actor="prahari-vault", action="CHECKOUT_DENIED",
                           payload=f"user={user.username} credential={body.name} reason={e}")
        db.add(Alert(user_id=user.id, session_id=sess.id if sess else None,
                     severity="CRITICAL", action_taken="BLOCK", insider_type=None,
                     message=f"Vault: credential checkout of '{body.name}' by "
                             f"{user.username} DENIED — {e}"))
        db.commit()
        await manager.broadcast({"type": "alert", "user": user.username, "role": user.role,
                                 "severity": "CRITICAL", "action": "CHECKOUT_DENIED",
                                 "score": round(risk, 1), "insider_type": None,
                                 "reasons": [f"Credential checkout refused: {e}"]})
        raise HTTPException(403, f"checkout denied — {e}")

    audit.append_entry(db, actor=user.username, action="CREDENTIAL_CHECKOUT",
                       payload=f"credential={body.name} session={sess.id if sess else '-'} "
                               f"risk={risk:.0f} lease={settings.checkout_ttl_seconds}s")
    await manager.broadcast({"type": "alert", "user": user.username, "role": user.role,
                             "severity": "INFO", "action": "CHECKOUT",
                             "score": round(risk, 1), "insider_type": None,
                             "reasons": [f"Credential '{body.name}' checked out "
                                         f"({settings.checkout_ttl_seconds // 60} min lease)"]})
    return result


# ======================= JUST-IN-TIME ACCESS (employee side) =======================

class JitRequestIn(BaseModel):
    privilege: str
    justification: str
    duration_minutes: int = 15


@router.get("/jit/mine")
def jit_mine(user: User = Depends(_employee), db: OrmSession = Depends(get_db)) -> list[dict]:
    return jit.list_grants(db, user)


@router.post("/jit/request")
async def jit_request(body: JitRequestIn, user: User = Depends(_employee),
                      db: OrmSession = Depends(get_db)) -> dict:
    try:
        g = jit.request_grant(db, user, body.privilege, body.justification,
                              body.duration_minutes)
    except jit.JitError as e:
        raise HTTPException(400, str(e))
    audit.append_entry(db, actor=user.username, action="JIT_REQUESTED",
                       payload=f"grant={g['id']} privilege={body.privilege} "
                               f"duration={body.duration_minutes}m reason={body.justification}")
    await manager.broadcast({"type": "jit", "event": "requested", **g})
    return g


# ======================= SOC CONSOLE (analyst only) =======================

@router.get("/soc/overview")
def soc_overview(user: User = Depends(require_analyst),
                 db: OrmSession = Depends(get_db)) -> dict:
    """Dashboard load: users, scored historical sessions, heatmap, live sessions."""
    model = get_model(db)
    sessions = (db.query(Session).filter(Session.status == "CLOSED")
                .order_by(Session.started_at).all())
    for sess in sessions:
        if sess.risk_reasons is None:
            a = assess(sess.user, sorted(sess.events, key=lambda e: e.timestamp), model)
            sess.risk_score = a.score
            sess.risk_reasons = json.dumps(a.reasons)
    db.commit()

    dates = sorted({s.started_at.date() for s in sessions})[-7:]
    users = db.query(User).filter(User.account_type == "EMPLOYEE").all()
    heatmap = []
    for u in users:
        cells = []
        for d in dates:
            day = [s.risk_score for s in sessions
                   if s.user_id == u.id and s.started_at.date() == d]
            cells.append(round(max(day), 1) if day else None)
        heatmap.append({"user": u.username, "role": u.role, "cells": cells})

    recent = sessions[-30:]
    return {
        "users": [{"id": u.id, "username": u.username, "name": u.name, "role": u.role,
                   "is_dormant": u.is_dormant, "is_vendor": u.is_vendor} for u in users],
        "sessions": [{"id": s.id, "user": s.user.username, "role": s.user.role,
                      "started_at": s.started_at.isoformat(),
                      "score": round(s.risk_score, 1),
                      "review_status": s.review_status, "reviewed_by": s.reviewed_by,
                      "reasons": json.loads(s.risk_reasons or "[]")}
                     for s in reversed(recent)],
        "heatmap": {"dates": [d.isoformat() for d in dates], "rows": heatmap},
        "live_sessions": _live_sessions(db),
    }


def _live_sessions(db: OrmSession) -> list[dict]:
    rows = (db.query(Session).filter(Session.status.in_(["ACTIVE", "BLOCKED"]))
            .order_by(Session.id.desc()).all())
    out = []
    for s in rows:
        evs = sorted(s.events, key=lambda e: e.timestamp)
        out.append({
            "id": s.id, "user": s.user.username, "name": s.user.name, "role": s.user.role,
            "status": s.status, "score": round(s.risk_score, 1),
            "review_status": s.review_status, "reviewed_by": s.reviewed_by,
            "insider_type": dominant_insider_type(
                evaluate(s.user, evs, jit_privileges=jit.active_privileges(db, s.user))),
            "source_ip": s.source_ip, "geo": s.geo, "device": s.device,
            "started_at": s.started_at.isoformat(),
            "reasons": json.loads(s.risk_reasons or "[]"),
            "events": [{"t": e.timestamp.isoformat(), "action": e.action_type,
                        "resource": e.resource, "records": e.records_touched,
                        "ip": e.source_ip, "device": e.device} for e in evs]})
    return out


@router.get("/soc/live")
def soc_live(user: User = Depends(require_analyst), db: OrmSession = Depends(get_db)) -> list[dict]:
    return _live_sessions(db)


@router.get("/soc/alerts")
def soc_alerts(limit: int = 50, user: User = Depends(require_analyst),
               db: OrmSession = Depends(get_db)) -> list[dict]:
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()
    return [{"id": a.id, "user_id": a.user_id, "session_id": a.session_id,
             "severity": a.severity, "action_taken": a.action_taken,
             "insider_type": a.insider_type, "resolved": a.resolved,
             "message": a.message, "created_at": a.created_at.isoformat()} for a in alerts]


@router.get("/soc/access-review")
def soc_access_review(user: User = Depends(require_analyst),
                      db: OrmSession = Depends(get_db)) -> list[dict]:
    """PAM access-review table: privileged accounts flagged dormant / vendor / expired."""
    return access_review(db)


@router.get("/soc/sessions/{session_id}/commands")
def soc_session_commands(session_id: int, user: User = Depends(require_analyst),
                         db: OrmSession = Depends(get_db)) -> dict:
    """Privileged-session recording: the replayable command trail of a session."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    cmds = (db.query(SessionCommand).filter_by(session_id=session_id)
            .order_by(SessionCommand.timestamp, SessionCommand.id).all())
    return {"session_id": session_id, "user": sess.user.username,
            "role": sess.user.role, "status": sess.status,
            "source_ip": sess.source_ip, "device": sess.device, "geo": sess.geo,
            "commands": [{"t": c.timestamp.isoformat(), "command": c.command,
                          "action": c.action_type, "resource": c.resource,
                          "outcome": c.outcome} for c in cmds]}


@router.post("/soc/sessions/{session_id}/approve")
async def soc_approve(session_id: int, user: User = Depends(require_analyst),
                      db: OrmSession = Depends(get_db)) -> dict:
    """Maker-checker: an analyst approves a session — the flag is resolved.

    The session is marked reviewed (APPROVED) so it reads as normal on the board;
    its risk_score is preserved as the immutable record of what actually happened.
    """
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    sess.review_status, sess.reviewed_by = "APPROVED", user.username
    db.commit()
    audit.append_entry(db, actor=user.username, action="MAKER_CHECKER_APPROVED",
                       payload=f"session={session_id} user={sess.user.username} resolved=APPROVED")
    await manager.broadcast({"type": "presence", "event": "approved", "session_id": session_id,
                             "user": sess.user.username})
    return {"ok": True, "session_id": session_id, "approved_by": user.username,
            "action": "APPROVED", "review_status": "APPROVED"}


@router.post("/soc/sessions/{session_id}/lock")
async def soc_lock(session_id: int, user: User = Depends(require_analyst),
                   db: OrmSession = Depends(get_db)) -> dict:
    """Analyst force-locks an account/session — enforcement outcome #5, audit-logged."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    sess.status = "BLOCKED"
    sess.ended_at = datetime.now()
    sess.review_status, sess.reviewed_by = None, None  # locking overrides any prior "reviewed" state
    db.commit()
    audit.append_entry(db, actor=user.username, action="ANALYST_LOCK",
                       payload=f"session={session_id} user={sess.user.username} locked by analyst")
    await manager.broadcast({"type": "alert", "session_id": session_id, "user": sess.user.username,
                             "role": sess.user.role, "severity": "CRITICAL", "action": "LOCKED",
                             "score": round(sess.risk_score, 1), "insider_type": None,
                             "reasons": [f"Account locked by SOC analyst {user.username}"]})
    return {"ok": True, "session_id": session_id, "status": "BLOCKED", "locked_by": user.username}


@router.post("/soc/sessions/{session_id}/dismiss")
async def soc_dismiss(session_id: int, user: User = Depends(require_analyst),
                      db: OrmSession = Depends(get_db)) -> dict:
    """Analyst dismisses a session as reviewed / benign (false positive) — flag resolved."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    sess.review_status, sess.reviewed_by = "DISMISSED", user.username
    db.commit()
    audit.append_entry(db, actor=user.username, action="ANALYST_DISMISS",
                       payload=f"session={session_id} user={sess.user.username} resolved=DISMISSED (benign)")
    await manager.broadcast({"type": "presence", "event": "dismissed", "session_id": session_id,
                             "user": sess.user.username})
    return {"ok": True, "session_id": session_id, "dismissed_by": user.username,
            "review_status": "DISMISSED"}


@router.get("/soc/jit")
def soc_jit(user: User = Depends(require_analyst), db: OrmSession = Depends(get_db)) -> list[dict]:
    """The JIT approvals queue: every elevation request with live status/expiry."""
    return jit.list_grants(db)


@router.post("/soc/jit/{grant_id}/approve")
async def soc_jit_approve(grant_id: int, user: User = Depends(require_analyst),
                          db: OrmSession = Depends(get_db)) -> dict:
    try:
        g = jit.decide_grant(db, grant_id, user.username, approve=True)
    except jit.JitError as e:
        raise HTTPException(400, str(e))
    audit.append_entry(db, actor=user.username, action="JIT_APPROVED",
                       payload=f"grant={grant_id} user={g['user']} privilege={g['privilege']} "
                               f"expires={g['expires_at']}")
    await manager.broadcast({"type": "jit", "event": "approved", **g})
    return g


@router.post("/soc/jit/{grant_id}/deny")
async def soc_jit_deny(grant_id: int, user: User = Depends(require_analyst),
                       db: OrmSession = Depends(get_db)) -> dict:
    try:
        g = jit.decide_grant(db, grant_id, user.username, approve=False)
    except jit.JitError as e:
        raise HTTPException(400, str(e))
    audit.append_entry(db, actor=user.username, action="JIT_DENIED",
                       payload=f"grant={grant_id} user={g['user']} privilege={g['privilege']}")
    await manager.broadcast({"type": "jit", "event": "denied", **g})
    return g


@router.get("/soc/checkouts")
def soc_checkouts(user: User = Depends(require_analyst),
                  db: OrmSession = Depends(get_db)) -> list[dict]:
    """Every credential checkout and refusal, newest first (PAM vault oversight)."""
    return vault.list_all_checkouts(db)


@router.get("/soc/sessions/{session_id}/trajectory")
def soc_trajectory(session_id: int, user: User = Depends(require_analyst),
                   db: OrmSession = Depends(get_db)) -> dict:
    """How the risk score climbed action-by-action across the session."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    model = get_model(db)
    events = sorted(sess.events, key=lambda e: e.timestamp)
    jit_privs = jit.active_privileges(db, sess.user)
    traj = []
    for k in range(1, len(events) + 1):
        a = assess(sess.user, events[:k], model, jit_privileges=jit_privs)
        traj.append({"step": k, "action": events[k - 1].action_type,
                     "resource": events[k - 1].resource, "score": round(a.score, 1)})
    return {"session_id": session_id, "user": sess.user.username, "trajectory": traj}


@router.get("/soc/sessions/{session_id}/model")
def soc_model(session_id: int, user: User = Depends(require_analyst),
              db: OrmSession = Depends(get_db)) -> dict:
    """AI Model Insights for a session: feature attribution + per-user baseline factors."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    model = get_model(db)
    events = sorted(sess.events, key=lambda e: e.timestamp)
    ur = model.score_session(sess.user, events)
    a = assess(sess.user, events, model, jit_privileges=jit.active_privileges(db, sess.user))
    return {"user": sess.user.username, "role": sess.user.role,
            "card": model.model_card(),
            "features": model.feature_breakdown(sess.user, events),
            "anomaly": round(ur.anomaly_score, 1),
            "self_deviation": round(ur.self_deviation, 1),
            "peer_deviation": round(ur.peer_deviation, 1),
            "factors": ur.factors, "score": round(a.score, 1),
            "insider_type": a.insider_type}


@router.get("/soc/model/eval")
def soc_model_eval(force: bool = False, user: User = Depends(require_analyst),
                   db: OrmSession = Depends(get_db)) -> dict:
    """Measured detector performance on a held-out sandbox: detection rate,
    typing/response accuracy, and the false-alarm profile on benign traffic."""
    return run_evaluation(force=force)


@router.get("/soc/sessions/{session_id}/report")
def soc_incident_report(session_id: int, user: User = Depends(require_analyst),
                        db: OrmSession = Depends(get_db)) -> dict:
    """One-click incident report: a self-contained, ML-DSA-65-signed evidence pack
    (session facts, replay transcript, score trajectory, model insights, alerts,
    audit extract, chain status) an analyst can hand to compliance as-is."""
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    model = get_model(db)
    events = sorted(sess.events, key=lambda e: e.timestamp)
    jit_privs = jit.active_privileges(db, sess.user)
    a = assess(sess.user, events, model, jit_privileges=jit_privs)
    action, severity = decide(a.score, a.insider_type)
    ur = model.score_session(sess.user, events)
    cmds = (db.query(SessionCommand).filter_by(session_id=session_id)
            .order_by(SessionCommand.timestamp, SessionCommand.id).all())
    alerts = (db.query(Alert).filter_by(session_id=session_id)
              .order_by(Alert.created_at).all())
    needle = f"session={session_id}"
    audit_rows = [e for e in db.query(AuditLogEntry).order_by(AuditLogEntry.id).all()
                  if needle in (e.payload or "") or sess.user.username in (e.payload or "")]
    chain = audit.verify_chain(db)

    trajectory = []
    for k in range(1, len(events) + 1):
        step = assess(sess.user, events[:k], model, jit_privileges=jit_privs)
        trajectory.append({"step": k, "action": events[k - 1].action_type,
                           "resource": events[k - 1].resource, "score": round(step.score, 1)})

    report = {
        "title": "Prahari privileged-session incident report",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "generated_by": user.username,
        "session": {
            "id": sess.id, "user": sess.user.username, "name": sess.user.name,
            "role": sess.user.role, "status": sess.status,
            "risk_score": round(sess.risk_score, 1),
            "started_at": sess.started_at.isoformat(),
            "ended_at": sess.ended_at.isoformat() if sess.ended_at else None,
            "source_ip": sess.source_ip, "geo": sess.geo, "device": sess.device,
        },
        "assessment": {
            "score": round(a.score, 1), "insider_type": a.insider_type,
            "recommended_response": action, "severity": severity,
            "reasons": a.reasons,
            "rules_fired": [{"rule": h.rule, "reason": h.reason, "weight": h.weight,
                             "insider_type": h.insider_type} for h in a.rule_hits],
        },
        "model_insights": {
            "anomaly": round(ur.anomaly_score, 1),
            "self_deviation": round(ur.self_deviation, 1),
            "peer_deviation": round(ur.peer_deviation, 1),
            "factors": ur.factors,
            "features": model.feature_breakdown(sess.user, events),
            "model_card": model.model_card(),
        },
        "risk_trajectory": trajectory,
        "session_transcript": [{"t": c.timestamp.isoformat(), "command": c.command,
                                "outcome": c.outcome} for c in cmds],
        "alerts": [{"t": al.created_at.isoformat(), "severity": al.severity,
                    "action_taken": al.action_taken, "insider_type": al.insider_type,
                    "message": al.message} for al in alerts],
        "audit_extract": [{"id": e.id, "t": e.timestamp.isoformat(), "actor": e.actor,
                           "action": e.action, "payload": e.payload,
                           "entry_hash": e.entry_hash} for e in audit_rows[-25:]],
        "audit_chain": {"ok": chain.ok, "entries_checked": chain.entries_checked,
                        "first_bad_id": chain.first_bad_id, "problem": chain.problem},
    }

    # Seal the pack: ML-DSA-sign the canonical report JSON with the audit key, so
    # the exported file is itself verifiable evidence (any edit breaks the seal).
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    _, audit_sec = keys.audit_keypair()
    signature = base64.b64encode(pqc.sign(audit_sec, canonical)).decode()
    audit.append_entry(db, actor=user.username, action="REPORT_EXPORTED",
                       payload=f"session={session_id} user={sess.user.username} sha256={digest[:16]}")
    return {"report": report, "evidence_sha256": digest,
            "signature": signature, "signature_alg": pqc.SIG_ALG,
            "note": "signature covers the canonical (sorted, compact) JSON of 'report'"}


@router.get("/soc/metrics")
def soc_metrics(user: User = Depends(require_analyst),
                db: OrmSession = Depends(get_db)) -> dict:
    """Business-impact metrics for the SOC overview strip — all computed from live data."""
    review = access_review(db)
    grants = jit.list_grants(db)
    return {
        "privileged_accounts": db.query(User).filter(User.account_type == "EMPLOYEE").count(),
        "sessions_monitored": db.query(Session).count(),
        "threats_blocked": db.query(Alert).filter(Alert.action_taken.in_(["BLOCK", "LOCKED"])).count(),
        "alerts_total": db.query(Alert).count(),
        "high_risk_accounts": sum(1 for r in review if r["risk"] == "HIGH"),
        "jit_pending": sum(1 for g in grants if g["status"] == "PENDING"),
        "jit_active": sum(1 for g in grants if g["status"] == "ACTIVE"),
        "checkouts_active": sum(1 for c in vault.list_all_checkouts(db) if c["status"] == "ACTIVE"),
        "detect_latency": "< 1s",
        "pqc": f"{pqc.KEM_ALG} / {pqc.SIG_ALG}",
    }


@router.get("/soc/sessions/{session_id}/events")
def soc_session_events(session_id: int, user: User = Depends(require_analyst),
                       db: OrmSession = Depends(get_db)) -> list[dict]:
    sess = db.get(Session, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    return [{"t": e.timestamp.isoformat(), "action": e.action_type, "resource": e.resource,
             "records": e.records_touched, "ip": e.source_ip, "device": e.device}
            for e in sorted(sess.events, key=lambda e: e.timestamp)]


async def _run_scenario(db: OrmSession, kind: str) -> dict:
    model = get_model(db)  # train on clean history BEFORE injecting the scenario
    sess = SCENARIOS[kind](db)
    events = sorted(sess.events, key=lambda e: e.timestamp)
    assessment = assess(sess.user, events, model)
    sess.risk_score = assessment.score
    sess.risk_reasons = json.dumps(assessment.reasons)
    decision = respond(db, sess.user, sess, assessment)
    db.commit()
    audit.append_entry(db, actor="prahari-engine", action="THREAT_DETECTED",
                       payload=f"user={sess.user.username} session={sess.id} "
                               f"type={assessment.insider_type} score={assessment.score:.0f} "
                               f"action={decision.action}")
    payload = {"scenario": kind, "session_id": sess.id, "user": sess.user.username,
               "role": sess.user.role, "insider_type": assessment.insider_type,
               "score": round(assessment.score, 1), "action": decision.action,
               "severity": decision.severity, "reasons": assessment.reasons}
    await manager.broadcast({"type": "alert", **payload})
    return payload


@router.post("/demo/scenario/{kind}")
async def demo_scenario(kind: str, user: User = Depends(require_analyst),
                        db: OrmSession = Depends(get_db)) -> dict:
    """Inject one scripted insider scenario: malicious / compromised / negligent."""
    if kind not in SCENARIOS:
        raise HTTPException(400, f"unknown scenario '{kind}'")
    return await _run_scenario(db, kind)


@router.post("/demo/attack")
async def demo_attack(user: User = Depends(require_analyst),
                      db: OrmSession = Depends(get_db)) -> dict:
    """Backwards-compatible alias for the malicious scenario."""
    return await _run_scenario(db, "malicious")


@router.websocket("/ws/feed")
async def ws_feed(ws: WebSocket) -> None:
    await feed_endpoint(ws)


# ======================= POST-QUANTUM SECURITY =======================

class SecretIn(BaseModel):
    name: str
    secret: str


@router.get("/pqc/info")
def pqc_info() -> dict:
    return {"provider": pqc.PROVIDER, "kem": pqc.KEM_ALG, "signature": pqc.SIG_ALG}


@router.post("/vault/secrets")
def vault_store(body: SecretIn, user: User = Depends(require_analyst),
                db: OrmSession = Depends(get_db)) -> dict:
    vault.store_secret(db, body.name, body.secret)
    audit.append_entry(db, actor=user.username, action="SECRET_STORED", payload=f"name={body.name}")
    return {"name": body.name, "kem": pqc.KEM_ALG, "stored": True}


@router.get("/vault/secrets/{name}")
def vault_get(name: str, user: User = Depends(require_analyst),
              db: OrmSession = Depends(get_db)) -> dict:
    try:
        secret = vault.get_secret(db, name)
    except KeyError:
        raise HTTPException(404, f"no vault item named '{name}'")
    audit.append_entry(db, actor=user.username, action="SECRET_ACCESSED", payload=f"name={name}")
    return {"name": name, "secret": secret}


@router.get("/audit")
def audit_list(limit: int = 100, user: User = Depends(require_analyst),
               db: OrmSession = Depends(get_db)) -> list[dict]:
    entries = db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(limit).all()
    return [{"id": e.id, "timestamp": e.timestamp.isoformat(), "actor": e.actor,
             "action": e.action, "payload": e.payload, "prev_hash": e.prev_hash,
             "entry_hash": e.entry_hash} for e in entries]


@router.get("/audit/verify")
def audit_verify(user: User = Depends(require_analyst),
                 db: OrmSession = Depends(get_db)) -> dict:
    report = audit.verify_chain(db)
    return {"ok": report.ok, "entries_checked": report.entries_checked,
            "first_bad_id": report.first_bad_id, "problem": report.problem,
            "signature_alg": pqc.SIG_ALG}


@router.post("/demo/tamper")
async def demo_tamper(user: User = Depends(require_analyst),
                      db: OrmSession = Depends(get_db)) -> dict:
    """Maliciously edit one audit entry, then re-verify — the chain must FAIL."""
    entry = db.query(AuditLogEntry).order_by(AuditLogEntry.id).first()
    if entry is None:
        raise HTTPException(400, "audit log is empty — run some activity first")
    original = entry.payload
    entry.payload = original.replace("BLOCK", "ALLOW") if "BLOCK" in original \
        else original + " [EDITED]"
    db.commit()
    report = audit.verify_chain(db)
    result = {"tampered_entry_id": entry.id, "original_payload": original,
              "tampered_payload": entry.payload, "chain_ok": report.ok,
              "problem": report.problem, "first_bad_id": report.first_bad_id}
    await manager.broadcast({"type": "audit_tamper", **result})
    return result
