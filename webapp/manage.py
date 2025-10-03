from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.database import Base, engine
from shared.services import ensure_admin_user

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "pasha500k")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Hehetoto123")


def migrate() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_admin_user(ADMIN_USERNAME, ADMIN_PASSWORD)
    print("Database schema created/updated. Admin credentials ensured.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Management utility for VPN webapp")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("migrate", help="Create database schema")

    args = parser.parse_args()
    if args.command == "migrate":
        migrate()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
