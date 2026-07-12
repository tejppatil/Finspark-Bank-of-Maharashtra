"""Tests for core-banking operations: transfers, maker-checker, fraud flagging."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import bank
from app.models import entities  # noqa: F401
from app.models.db import Base


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    bank.seed_bank(s)
    yield s
    s.close()


def _bal(db, num):
    return bank._acct(db, num).balance


def test_seed_creates_accounts_and_ledger(db):
    assert len(bank.accounts(db)) == 6
    assert len(bank.transactions(db)) >= 6
    assert len(bank.beneficiaries(db)) == 6 + 3  # internal + external


def test_normal_transfer_clears_and_moves_money(db):
    a, b = "50100000004821", "50100000006610"
    before_a, before_b = _bal(db, a), _bal(db, b)
    r = bank.transfer(db, a, b, 50000, "NEFT", "rmehta")
    assert r["status"] == "CLEARED" and r["alert"] is None
    assert _bal(db, a) == before_a - 50000
    assert _bal(db, b) == before_b + 50000


def test_high_value_is_held_and_money_does_not_move(db):
    a, b = "50100000007735", "50100000006610"
    before = _bal(db, a)
    r = bank.transfer(db, a, b, 500000, "RTGS", "rmehta")
    assert r["status"] == "HELD" and r["alert"]["severity"] == "WARNING"
    assert _bal(db, a) == before  # held — nothing moved yet
    assert len(bank.pending(db)) == 1


def test_watchlist_beneficiary_is_flagged_as_fraud(db):
    r = bank.transfer(db, "50100000004821", "59990000001111", 30000, "NEFT", "rmehta")
    assert r["status"] == "FLAGGED" and r["alert"]["severity"] == "CRITICAL"
    assert "watchlist" in r["transaction"]["flagged_reason"]


def test_huge_amount_is_flagged(db):
    r = bank.transfer(db, "50100000007735", "50200000112233", 1500000, "RTGS", "rmehta")
    assert r["status"] == "FLAGGED"


def test_high_risk_session_flags_transfer(db):
    r = bank.transfer(db, "50100000004821", "50100000006610", 40000, "NEFT", "rmehta",
                      session_risk=90)
    assert r["status"] == "FLAGGED" and "high-risk" in r["transaction"]["flagged_reason"]


def test_approve_held_transfer_settles(db):
    a = "50100000007735"
    before = _bal(db, a)
    r = bank.transfer(db, a, "50100000006610", 300000, "RTGS", "rmehta")
    tx_id = r["transaction"]["id"]
    out = bank.approve(db, tx_id, "dgokhale", "OFFICER")
    assert _bal(db, a) == before - 300000
    tx = bank._tx_dict(db.get(entities.BankTransaction, tx_id))
    assert tx["status"] == "CLEARED" and tx["checker"] == "dgokhale"  # checker recorded
    assert out["transaction"]["checker"] == "dgokhale"


def test_maker_cannot_approve_own_transfer(db):
    a = "50100000007735"
    before = _bal(db, a)
    r = bank.transfer(db, a, "50100000006610", 300000, "RTGS", "rmehta")
    tx_id = r["transaction"]["id"]
    with pytest.raises(bank.TransferError, match="different from the maker"):
        bank.approve(db, tx_id, "rmehta", "DBA")          # maker == checker: refused
    assert _bal(db, a) == before                          # money did not move
    assert bank._tx_dict(db.get(entities.BankTransaction, tx_id))["status"] == "HELD"


def test_unauthorized_role_cannot_approve(db):
    r = bank.transfer(db, "50100000007735", "50100000006610", 300000, "RTGS", "rmehta")
    with pytest.raises(bank.TransferError, match="not authorized"):
        bank.approve(db, r["transaction"]["id"], "vdeshmukh", "NET_ADMIN")  # wrong role


def test_reject_records_checker_and_moves_no_money(db):
    a = "50100000007735"
    before = _bal(db, a)
    r = bank.transfer(db, a, "50100000006610", 300000, "RTGS", "rmehta")
    out = bank.reject(db, r["transaction"]["id"], "dgokhale", "OFFICER")
    assert out["status"] == "REJECTED" and out["transaction"]["checker"] == "dgokhale"
    assert _bal(db, a) == before


def test_flagged_transfer_cleared_by_officer_settles(db):
    a = "50100000004821"
    before = _bal(db, a)
    r = bank.transfer(db, a, "59990000001111", 30000, "NEFT", "rmehta")  # watchlist -> FLAGGED
    assert r["status"] == "FLAGGED"
    out = bank.resolve_flag(db, r["transaction"]["id"], "dgokhale", "OFFICER", "clear")
    assert out["status"] == "CLEARED" and out["transaction"]["checker"] == "dgokhale"
    assert _bal(db, a) == before - 30000                  # external payee: leaves the bank


def test_flagged_transfer_confirmed_blocks_money(db):
    a = "50100000004821"
    before = _bal(db, a)
    r = bank.transfer(db, a, "59990000001111", 30000, "NEFT", "rmehta")
    out = bank.resolve_flag(db, r["transaction"]["id"], "dgokhale", "OFFICER", "confirm")
    assert out["status"] == "BLOCKED"
    assert _bal(db, a) == before                          # confirmed fraud: money never moved


def test_maker_cannot_resolve_own_flag(db):
    r = bank.transfer(db, "50100000004821", "59990000001111", 30000, "NEFT", "rmehta")
    with pytest.raises(bank.TransferError, match="different from the maker"):
        bank.resolve_flag(db, r["transaction"]["id"], "rmehta", "DBA", "clear")


def test_pending_includes_held_and_flagged(db):
    bank.transfer(db, "50100000007735", "50100000006610", 300000, "RTGS", "rmehta")  # HELD
    bank.transfer(db, "50100000004821", "59990000001111", 30000, "NEFT", "rmehta")   # FLAGGED
    assert {p["status"] for p in bank.pending(db)} == {"HELD", "FLAGGED"}


def test_cleared_external_transfer_debits_source(db):
    a = "50100000004821"
    before = _bal(db, a)
    r = bank.transfer(db, a, "50200000112233", 40000, "NEFT", "rmehta")  # external, not watchlisted
    assert r["status"] == "CLEARED"
    assert _bal(db, a) == before - 40000                  # no crash on external (None) destination


def test_insufficient_funds_rejected(db):
    with pytest.raises(bank.TransferError):
        bank.transfer(db, "50100000006610", "50100000004821", 99999999, "NEFT", "rmehta")


def test_frozen_source_cannot_debit(db):
    with pytest.raises(bank.TransferError):
        bank.transfer(db, "50100000003357", "50100000004821", 1000, "NEFT", "rmehta")
