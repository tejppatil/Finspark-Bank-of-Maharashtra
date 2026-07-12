"""Seed the database with users + baseline normal history.

Usage: python -m app.simulator.seed [--days 14] [--fresh]
"""
import argparse
import os

from app.bank import seed_bank
from app.config import settings
from app.models.db import SessionLocal, init_db
from app.simulator.normal import seed_users, simulate_history


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Prahari baseline data")
    parser.add_argument("--days", type=int, default=14, help="days of history")
    parser.add_argument("--fresh", action="store_true", help="delete existing SQLite DB first")
    args = parser.parse_args()

    if args.fresh and settings.database_url.startswith("sqlite:///"):
        path = settings.database_url.removeprefix("sqlite:///")
        if os.path.exists(path):
            os.remove(path)

    init_db()
    db = SessionLocal()
    try:
        users = seed_users(db)
        n = simulate_history(db, days=args.days)
        seed_bank(db)
        print(f"Seeded {len(users)} users, {n} events over {args.days} days of history, "
              "plus bank accounts + ledger.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
