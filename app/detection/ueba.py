"""UEBA: behavioural analytics with an IsolationForest baseline, per-role peer
comparison, and per-user behavioural profiles.

Feature vector per session (fed to the IsolationForest):
  [login_hour, event_count, total_records, distinct_resources,
   config_changes, offsite_ip, new_device]

On top of the unsupervised forest, the model keeps a *per-user* behavioural
baseline (their own usual hours, devices, locations and data volumes) so it can
explain an anomaly in terms of "this is unusual for THIS person", which is the
essence of user-and-entity behaviour analytics.
"""
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session as OrmSession

from app.models.entities import Event, Session, User

FEATURE_NAMES = ["login hour", "actions", "records touched", "distinct resources",
                 "config/priv changes", "off-network", "new device"]


def extract_features(events: list[Event], known_devices: set[str] | None = None) -> list[float]:
    """Build one feature vector from a session's events."""
    if not events:
        return [0.0] * 7
    login_hour = min(e.timestamp for e in events).hour
    total_records = sum(e.records_touched for e in events)
    resources = {e.resource for e in events}
    config_changes = sum(1 for e in events if e.action_type in ("CONFIG_CHANGE", "PRIV_CHANGE"))
    offsite = 0.0 if all(e.source_ip.startswith("10.20.") for e in events) else 1.0
    new_device = 0.0
    if known_devices is not None:
        new_device = 0.0 if {e.device for e in events} <= known_devices else 1.0
    return [float(login_hour), float(len(events)), float(total_records),
            float(len(resources)), float(config_changes), offsite, new_device]


@dataclass
class UserBaseline:
    """One privileged user's learned normal behaviour."""
    n_sessions: int = 0
    records_mean: float = 0.0
    records_max: float = 0.0
    hours: set = field(default_factory=set)
    devices: set = field(default_factory=set)
    geos: set = field(default_factory=set)


@dataclass
class UebaResult:
    anomaly_score: float   # 0 (normal) - 100 (highly anomalous)
    peer_deviation: float  # x same-role peer average records
    self_deviation: float  # x this user's own average records
    summary: str
    factors: list[str] = field(default_factory=list)


class UebaModel:
    """IsolationForest baseline + per-user behavioural profiles."""

    def __init__(self) -> None:
        self._forest: IsolationForest | None = None
        self._baseline_scores: np.ndarray | None = None
        self.role_avg_records: dict[str, float] = {}
        self.user_devices: dict[int, set[str]] = {}
        self.user_baselines: dict[int, UserBaseline] = {}
        self.training_rows = 0
        self.training_sessions = 0

    @property
    def is_trained(self) -> bool:
        return self._forest is not None

    def train(self, db: OrmSession) -> int:
        """Fit on all closed historical sessions. Returns number of training rows."""
        rows: list[list[float]] = []
        role_records: dict[str, list[float]] = {}
        user_records: dict[int, list[float]] = {}
        sessions = 0
        # Baseline = closed historical sessions only; never live or blocked ones.
        for sess in db.query(Session).filter(Session.status == "CLOSED").all():
            events = sorted(sess.events, key=lambda e: e.timestamp)
            if not events:
                continue
            sessions += 1
            user = sess.user
            self.user_devices.setdefault(user.id, set()).update(e.device for e in events)
            bl = self.user_baselines.setdefault(user.id, UserBaseline())
            bl.n_sessions += 1
            bl.hours.add(min(e.timestamp for e in events).hour)
            bl.devices.update(e.device for e in events)
            bl.geos.update(e.geo for e in events if e.geo)
            recs = float(sum(e.records_touched for e in events))
            user_records.setdefault(user.id, []).append(recs)
            # Train on cumulative prefixes as well as the full session, so live
            # sessions (which arrive one action at a time) are in-distribution and
            # normal early activity doesn't look anomalous just for being short.
            for k in range(1, len(events) + 1):
                rows.append(extract_features(events[:k], self.user_devices[user.id]))
            role_records.setdefault(user.role, []).append(recs)
        if not rows:
            raise ValueError("no historical sessions to train on — run the seeder first")
        X = np.array(rows)
        self._forest = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
        self._forest.fit(X)
        self._baseline_scores = self._forest.score_samples(X)
        self.role_avg_records = {r: (sum(v) / len(v)) for r, v in role_records.items()}
        for uid, recs in user_records.items():
            bl = self.user_baselines[uid]
            bl.records_mean = sum(recs) / len(recs)
            bl.records_max = max(recs)
        self.training_rows = len(rows)
        self.training_sessions = sessions
        return len(rows)

    def _anomaly(self, feats: list[float]) -> float:
        raw = float(self._forest.score_samples(np.array([feats]))[0])
        med = float(np.median(self._baseline_scores))
        p1 = float(np.percentile(self._baseline_scores, 1))
        span = max(med - p1, 1e-6)
        return float(np.clip((med - raw) / span, 0.0, 1.0) * 100.0)

    def score_session(self, user: User, events: list[Event]) -> UebaResult:
        """Anomaly-score one session against the baseline + the user's own profile."""
        if not self.is_trained:
            raise RuntimeError("UEBA model not trained")
        feats = extract_features(events, self.user_devices.get(user.id, set()))
        anomaly = self._anomaly(feats)

        peer_avg = self.role_avg_records.get(user.role) or 1.0
        session_records = float(sum(e.records_touched for e in events))
        peer_dev = session_records / max(peer_avg, 1.0)

        bl = self.user_baselines.get(user.id)
        self_dev = session_records / max(bl.records_mean, 1.0) if bl and bl.records_mean else 0.0

        parts = [f"behaviour anomaly {anomaly:.0f}/100 vs learned baseline"]
        if peer_dev >= 3:
            parts.append(f"touched {peer_dev:.0f}x more records than {user.role} peers")

        # Per-user (self) behavioural factors — the UEBA "unusual for THIS person" layer.
        factors: list[str] = []
        if bl and bl.n_sessions:
            if self_dev >= 3 and session_records > 0:
                factors.append(f"{session_records:.0f} records — {self_dev:.0f}x this account's own average")
            hrs = {e.timestamp.hour for e in events if e.action_type != "LOGOUT"}
            odd = sorted(h for h in hrs if h not in bl.hours)
            if odd:
                factors.append(f"active at {odd[0]:02d}:00 — outside this account's usual hours")
            devs = {e.device for e in events if e.device}
            if devs and not devs <= bl.devices:
                factors.append(f"device {sorted(devs - bl.devices)[0]} never used by this account")
            geos = {e.geo for e in events if e.geo}
            if geos and not geos <= bl.geos:
                factors.append(f"location {sorted(geos - bl.geos)[0]} not seen for this account")
        return UebaResult(anomaly, peer_dev, self_dev, "; ".join(parts + factors), factors)

    def feature_breakdown(self, user: User, events: list[Event]) -> list[dict]:
        """Per-feature values vs this user's typical range — for the Model Insights view."""
        feats = extract_features(events, self.user_devices.get(user.id, set()))
        bl = self.user_baselines.get(user.id)
        typical = {
            0: f"{min(bl.hours):02d}:00–{max(bl.hours):02d}:00" if bl and bl.hours else "—",
            2: f"~{bl.records_mean:.0f} (max {bl.records_max:.0f})" if bl else "—",
            5: "on-network", 6: "known device",
        }
        anomalous = {
            0: bool(bl and bl.hours and int(feats[0]) not in bl.hours and feats[1] > 0),
            2: bool(bl and bl.records_mean and feats[2] > max(2 * bl.records_mean, bl.records_max)),
            5: feats[5] > 0, 6: feats[6] > 0,
        }
        out = []
        for i, name in enumerate(FEATURE_NAMES):
            val = feats[i]
            if i in (5, 6):
                shown = "yes" if val > 0 else "no"
            else:
                shown = f"{val:.0f}"
            out.append({"name": name, "value": shown, "typical": typical.get(i, "role baseline"),
                        "anomalous": bool(anomalous.get(i, False))})
        return out

    def model_card(self) -> dict:
        return {
            "algorithm": "IsolationForest (unsupervised anomaly detection)",
            "estimators": 100,
            "features": FEATURE_NAMES,
            "training_sessions": self.training_sessions,
            "training_vectors": self.training_rows,
            "users_profiled": len(self.user_baselines),
            "roles_profiled": len(self.role_avg_records),
        }
