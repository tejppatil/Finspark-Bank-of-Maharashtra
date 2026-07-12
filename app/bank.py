"""Core banking operations the employee performs (accounts, ledger, transfers).

This is the 'real work' side of the demo: a privileged bank employee doing
day-to-day banking. Transfers actually move money between accounts and post to
the ledger; high-value transfers are held for maker-checker approval — a genuine
banking control. (This is separate from the privileged-access threat scoring,
which watches admin actions on core systems, not routine customer transfers.)
"""
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as OrmSession

from app.models.entities import BankAccount, BankTransaction

HIGH_VALUE = 200000.0    # > this needs a second approver (maker-checker HELD)
FRAUD_VALUE = 1000000.0  # >= this is auto-FLAGGED for fraud review (blocked pending)

# Roles with authority to sign off a held/flagged transfer. Segregation of duties:
# the approver must hold approval authority AND be a different person than the maker.
APPROVER_ROLES = {"OFFICER", "DBA"}

# External payees the portal offers. The watchlisted one triggers a fraud FLAG.
EXTERNAL_BENEFICIARIES = [
    {"number": "50200000112233", "name": "Sunrise Suppliers (external)", "watchlist": False},
    {"number": "50200000445566", "name": "Payroll Bulk Account (external)", "watchlist": False},
    {"number": "59990000001111", "name": "QuickCash Holdings", "watchlist": True},
]
_BENE = {b["number"]: b for b in EXTERNAL_BENEFICIARIES}
SUSPICIOUS = {b["number"] for b in EXTERNAL_BENEFICIARIES if b["watchlist"]}

SEED_ACCOUNTS = [
    ("50100000004821", "Aarti Deshpande", "Savings", "Fort", 245600.0, "ACTIVE"),
    ("50100000007735", "Meridian Traders Pvt Ltd", "Current", "BKC", 1890200.0, "ACTIVE"),
    ("50100000001188", "Rohan Kulkarni", "Savings", "Andheri", 76540.0, "DORMANT"),
    ("50100000009042", "Sana Sheikh", "Loan", "Fort", -420000.0, "ACTIVE"),
    ("50100000003357", "Vertex Exports", "Current", "Pune", 912780.0, "FROZEN"),
    ("50100000006610", "Kabir Nair", "Savings", "Thane", 158900.0, "ACTIVE"),
]

SEED_TX = [
    ("NEFT outward · vendor payout", "50100000007735", None, 120000.0, "NEFT"),
    ("IMPS inward · salary credit", None, "50100000004821", 8500.0, "IMPS"),
    ("RTGS outward · settlement", "50100000007735", None, 500000.0, "RTGS"),
    ("UPI collect · merchant", None, "50100000004821", 2240.0, "UPI"),
    ("Cheque clearing · inward", None, "50100000003357", 45000.0, "TRANSFER"),
    ("Standing instruction · EMI", "50100000009042", None, 32100.0, "TRANSFER"),
]


def mask(number: str) -> str:
    return f"AC ••••{number[-4:]}" if number else "—"


def seed_bank(db: OrmSession) -> None:
    """Populate accounts + a little ledger history (idempotent)."""
    if db.query(BankAccount).count() == 0:
        for num, holder, typ, branch, bal, status in SEED_ACCOUNTS:
            db.add(BankAccount(number=num, holder=holder, acc_type=typ, branch=branch,
                               balance=bal, status=status))
    if db.query(BankTransaction).count() == 0:
        base = datetime.now().replace(hour=9, minute=32, second=0, microsecond=0)
        for i, (desc, frm, to, amt, mode) in enumerate(SEED_TX):
            db.add(BankTransaction(timestamp=base - timedelta(minutes=17 * i), description=desc,
                                   from_number=frm, to_number=to, amount=amt, mode=mode,
                                   status="CLEARED", maker="system"))
    db.commit()


def _acct(db: OrmSession, number: str) -> BankAccount | None:
    return db.query(BankAccount).filter_by(number=number).first()


def accounts(db: OrmSession) -> list[dict]:
    rows = db.query(BankAccount).order_by(BankAccount.id).all()
    return [{"number": a.number, "masked": mask(a.number), "holder": a.holder,
             "type": a.acc_type, "branch": a.branch, "balance": a.balance,
             "status": a.status} for a in rows]


def transactions(db: OrmSession, limit: int = 25) -> list[dict]:
    rows = (db.query(BankTransaction).order_by(BankTransaction.timestamp.desc(),
            BankTransaction.id.desc()).limit(limit).all())
    return [_tx_dict(t) for t in rows]


def pending(db: OrmSession) -> list[dict]:
    """Transfers awaiting a second officer: HELD (maker-checker) + FLAGGED (fraud review)."""
    rows = (db.query(BankTransaction).filter(BankTransaction.status.in_(["HELD", "FLAGGED"]))
            .order_by(BankTransaction.id.desc()).all())
    return [_tx_dict(t) for t in rows]


def _tx_dict(t: BankTransaction) -> dict:
    return {"id": t.id, "t": t.timestamp.isoformat(), "description": t.description,
            "from": mask(t.from_number), "to": mask(t.to_number), "amount": t.amount,
            "mode": t.mode, "status": t.status, "maker": t.maker, "checker": t.checker,
            "flagged_reason": t.flagged_reason}


def beneficiaries(db: OrmSession) -> list[dict]:
    """Payees the transfer form offers: internal accounts + external beneficiaries."""
    internal = [{"number": a.number, "name": a.holder, "kind": "internal"}
                for a in db.query(BankAccount).order_by(BankAccount.id).all()]
    external = [{"number": b["number"], "name": b["name"], "kind": "external",
                 "watchlist": b["watchlist"]} for b in EXTERNAL_BENEFICIARIES]
    return internal + external


class TransferError(Exception):
    pass


def _payee_name(db: OrmSession, number: str) -> str:
    dst = _acct(db, number)
    if dst:
        return dst.holder
    return _BENE.get(number, {}).get("name", "External beneficiary")


def transfer(db: OrmSession, from_number: str, to_number: str, amount: float,
             mode: str, maker: str, session_risk: float = 0.0) -> dict:
    """Move funds. High-value → maker-checker HELD; suspicious → fraud FLAGGED.

    Returns {status, message, transaction, alert}. `alert` (or None) tells the
    caller to raise a SOC alert + flash the screens for HELD/FLAGGED outcomes.
    """
    if amount <= 0:
        raise TransferError("Amount must be greater than zero.")
    if from_number == to_number:
        raise TransferError("Source and destination accounts must differ.")
    src = _acct(db, from_number)
    if src is None:
        raise TransferError("Source account not found.")
    if src.status != "ACTIVE":
        raise TransferError(f"Source account is {src.status} — cannot debit.")
    dst = _acct(db, to_number)  # None = external beneficiary
    if dst is not None and dst.status == "FROZEN":
        raise TransferError("Destination account is FROZEN — cannot credit.")
    if amount > src.balance and src.acc_type != "Loan":
        raise TransferError("Insufficient balance.")

    payee = _payee_name(db, to_number)
    desc = f"{mode} transfer · {src.holder} → {payee}"

    # decide the outcome (fraud checks first, then the high-value hold)
    status, reason = "CLEARED", None
    if to_number in SUSPICIOUS:
        status, reason = "FLAGGED", "beneficiary on the fraud watchlist"
    elif amount >= FRAUD_VALUE:
        status, reason = "FLAGGED", f"unusually large transfer (₹{amount:,.0f})"
    elif session_risk >= 70:
        status, reason = "FLAGGED", f"initiated from a high-risk privileged session (score {session_risk:.0f})"
    elif amount > HIGH_VALUE:
        status, reason = "HELD", f"exceeds the ₹{HIGH_VALUE:,.0f} maker-checker limit"

    if status == "CLEARED":
        _settle(src, dst, amount)   # money moves only when cleared

    tx = BankTransaction(description=desc, from_number=from_number, to_number=to_number,
                         amount=amount, mode=mode, status=status, maker=maker,
                         flagged_reason=reason)
    db.add(tx)
    db.commit()

    messages = {
        "CLEARED": f"₹{amount:,.0f} transferred to {payee} and cleared.",
        "HELD": f"₹{amount:,.0f} to {payee} — {reason}. Held for a second approver.",
        "FLAGGED": f"⚠ ₹{amount:,.0f} to {payee} FLAGGED as suspected fraud — {reason}. "
                   "Money held; SOC alerted.",
    }
    alert = None
    if status in ("HELD", "FLAGGED"):
        alert = {"severity": "CRITICAL" if status == "FLAGGED" else "WARNING",
                 "action": status,
                 "text": f"{maker}: {mode} ₹{amount:,.0f} to {payee} — {status} ({reason})"}
    return {"status": status, "message": messages[status], "transaction": _tx_dict(tx), "alert": alert}


def _authorize_checker(tx: BankTransaction, checker: str, checker_role: str,
                       expected_status: str) -> None:
    """Enforce segregation of duties before a second officer acts on a transfer."""
    if tx is None or tx.status != expected_status:
        raise TransferError(f"No {expected_status.lower()} transaction with that id.")
    if checker == tx.maker:
        raise TransferError(
            "Maker-checker: the approving officer must be different from the maker "
            f"('{tx.maker}' initiated this transfer).")
    if checker_role not in APPROVER_ROLES:
        raise TransferError(
            f"Role '{checker_role}' is not authorized to sign off transfers "
            f"(needs one of: {', '.join(sorted(APPROVER_ROLES))}).")


def approve(db: OrmSession, tx_id: int, checker: str, checker_role: str = "OFFICER") -> dict:
    """A second, authorized officer approves a HELD transfer — money now moves."""
    tx = db.get(BankTransaction, tx_id)
    _authorize_checker(tx, checker, checker_role, "HELD")
    src, dst = _acct(db, tx.from_number), _acct(db, tx.to_number)  # dst None = external payee
    if src is None:
        raise TransferError("Source account not found.")
    if not (src.acc_type == "Loan" or tx.amount <= src.balance):
        raise TransferError("Insufficient balance at approval time.")
    _settle(src, dst, tx.amount)
    tx.status, tx.checker = "CLEARED", checker
    db.commit()
    return {"status": "CLEARED", "transaction": _tx_dict(tx)}


def reject(db: OrmSession, tx_id: int, checker: str, checker_role: str = "OFFICER") -> dict:
    """A second, authorized officer rejects a HELD transfer — money never moves."""
    tx = db.get(BankTransaction, tx_id)
    _authorize_checker(tx, checker, checker_role, "HELD")
    tx.status, tx.checker = "REJECTED", checker
    db.commit()
    return {"status": "REJECTED", "transaction": _tx_dict(tx)}


def resolve_flag(db: OrmSession, tx_id: int, officer: str, officer_role: str,
                 decision: str) -> dict:
    """Resolve a FLAGGED (suspected-fraud) transfer.

    decision='clear'   -> a reviewed false-positive: release and settle it.
    decision='confirm' -> confirmed fraud: block permanently; money never moves.
    Segregation of duties applies: the reviewing officer must be authorized and
    different from the maker who initiated the transfer.
    """
    tx = db.get(BankTransaction, tx_id)
    _authorize_checker(tx, officer, officer_role, "FLAGGED")
    if decision == "clear":
        src, dst = _acct(db, tx.from_number), _acct(db, tx.to_number)
        if src is None:
            raise TransferError("Source account not found.")
        if not (src.acc_type == "Loan" or tx.amount <= src.balance):
            raise TransferError("Insufficient balance at clearing time.")
        _settle(src, dst, tx.amount)
        tx.status, tx.checker = "CLEARED", officer
    elif decision == "confirm":
        tx.status, tx.checker = "BLOCKED", officer
    else:
        raise TransferError("decision must be 'clear' or 'confirm'.")
    db.commit()
    return {"status": tx.status, "transaction": _tx_dict(tx)}


def _settle(src: BankAccount, dst: BankAccount | None, amount: float) -> None:
    """Debit the source; credit the destination if it is an internal account.
    An external beneficiary (dst is None) simply leaves the bank."""
    src.balance -= amount
    if dst is not None:
        dst.balance += amount
