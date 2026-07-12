"""ORM entities for Prahari."""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db import Base


class User(Base):
    """A privileged user (admin, DBA, contractor...)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))  # DBA / SYSADMIN / NET_ADMIN / APP_ADMIN / CONTRACTOR / SOC_ANALYST
    account_type: Mapped[str] = mapped_column(String(16), default="EMPLOYEE")  # EMPLOYEE / ANALYST
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_dormant: Mapped[bool] = mapped_column(Boolean, default=False)
    is_vendor: Mapped[bool] = mapped_column(Boolean, default=False)
    # PAM access control: when a (vendor/contractor) grant lapses. NULL = permanent staff.
    access_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    events: Mapped[list["Event"]] = relationship(back_populates="user")
    sessions: Mapped[list["Session"]] = relationship(back_populates="user")


class Session(Base):
    """One login-to-logout activity window for a user."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100, set in Phase 2
    risk_reasons: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON breakdown
    status: Mapped[str] = mapped_column(String(16), default="CLOSED")  # ACTIVE / CLOSED / BLOCKED
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    geo: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Analyst triage outcome: APPROVED / DISMISSED once a human has reviewed the flag.
    # Set by the SOC Approve/Dismiss actions so a reviewed session reads as resolved
    # (the risk_score is kept as the immutable record of what actually happened).
    review_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")
    events: Mapped[list["Event"]] = relationship(back_populates="session")
    commands: Mapped[list["SessionCommand"]] = relationship(back_populates="session")


class SessionCommand(Base):
    """Privileged-session recording: the replayable command trail of a session (PAM)."""

    __tablename__ = "session_commands"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("sessions.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    command: Mapped[str] = mapped_column(Text)          # e.g. "SELECT * FROM customers LIMIT 5000"
    action_type: Mapped[str] = mapped_column(String(32))
    resource: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(16), default="EXECUTED")  # EXECUTED / DENIED / HELD

    session: Mapped[Session] = relationship(back_populates="commands")


class Event(Base):
    """A single privileged action."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32))  # LOGIN/DB_QUERY/DB_EXPORT/CONFIG_CHANGE/PRIV_CHANGE/FILE_ACCESS/LOGOUT
    resource: Mapped[str] = mapped_column(String(128))
    records_touched: Mapped[int] = mapped_column(Integer, default=0)
    source_ip: Mapped[str] = mapped_column(String(45))
    geo: Mapped[str] = mapped_column(String(64))
    device: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)

    user: Mapped[User] = relationship(back_populates="events")
    session: Mapped[Session | None] = relationship(back_populates="events")


class Alert(Base):
    """A detection alert raised for a session/user (Phase 2+)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))  # INFO/WARNING/CRITICAL
    action_taken: Mapped[str] = mapped_column(String(32), default="NONE")  # ALLOW/STEP_UP_MFA/MAKER_CHECKER/BLOCK
    insider_type: Mapped[str | None] = mapped_column(String(16), nullable=True)  # malicious/negligent/compromised
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    # Banking alerts point back to their transaction so resolving the transfer
    # (approve/reject/clear/confirm) can clear the alert from the SOC feed.
    ref_txn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLogEntry(Base):
    """Hash-chained, PQC-signed audit record (signing lands in Phase 4)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)


class VaultItem(Base):
    """PQC-wrapped credential (encryption lands in Phase 4)."""

    __tablename__ = "vault_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(String(64))
    kem_ciphertext: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)


class CredentialCheckout(Base):
    """A time-boxed checkout of a vault credential by a privileged user (PAM workflow)."""

    __tablename__ = "credential_checkouts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))          # vault item checked out
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    session_id: Mapped[int | None] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    checked_out_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")  # ACTIVE/EXPIRED/DENIED
    risk_at_checkout: Mapped[float] = mapped_column(Float, default=0.0)
    denied_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)


class JitGrant(Base):
    """A just-in-time privilege-elevation grant: requested, approved, time-boxed, auto-expiring."""

    __tablename__ = "jit_grants"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    privilege: Mapped[str] = mapped_column(String(128))     # resource the elevation covers
    justification: Mapped[str] = mapped_column(String(300))
    duration_minutes: Mapped[int] = mapped_column(Integer, default=15)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    status: Mapped[str] = mapped_column(String(16), default="PENDING")  # PENDING/ACTIVE/DENIED/EXPIRED
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    user: Mapped[User] = relationship()


class BankAccount(Base):
    """A customer bank account the employee operates on (the 'real work' side)."""

    __tablename__ = "bank_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[str] = mapped_column(String(20), unique=True)
    holder: Mapped[str] = mapped_column(String(128))
    acc_type: Mapped[str] = mapped_column(String(16))   # Savings / Current / Loan
    branch: Mapped[str] = mapped_column(String(32))
    balance: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")  # ACTIVE/DORMANT/FROZEN


class BankTransaction(Base):
    """A ledger entry / money transfer, with a maker-checker + fraud status."""

    __tablename__ = "bank_transactions"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    description: Mapped[str] = mapped_column(String(200))
    from_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_number: Mapped[str | None] = mapped_column(String(20), nullable=True)
    amount: Mapped[float] = mapped_column(Float)
    mode: Mapped[str] = mapped_column(String(16))       # NEFT/RTGS/IMPS/UPI/TRANSFER
    status: Mapped[str] = mapped_column(String(16), default="CLEARED")  # CLEARED/HELD/FLAGGED/REJECTED/BLOCKED
    maker: Mapped[str] = mapped_column(String(64), default="system")
    # The second officer who approved/rejected/resolved it (maker-checker: must differ from maker).
    checker: Mapped[str | None] = mapped_column(String(64), nullable=True)
    flagged_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
