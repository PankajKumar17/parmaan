import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings
from app.core.security import hash_password
from app.core.self_integrity import check_self_integrity
from app.db.models import Base, User
from app.db.session import create_database
from sqlalchemy import select


def main():
    parser = argparse.ArgumentParser(description="Create a PRAMAAN dashboard user offline")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    email = args.email.strip().lower()
    if len(email) > 254 or "@" not in email or any(char.isspace() for char in email):
        parser.error("A valid email address is required")
    check_self_integrity()
    settings = Settings.from_environment()
    password = getpass.getpass("Password (12-256 characters): ")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match")
    encoded = hash_password(password)
    engine, factory = create_database(settings.database_url)
    try:
        Base.metadata.create_all(engine)
        with factory.begin() as session:
            if session.scalar(select(User).where(User.email == email)) is not None:
                parser.error("User already exists")
            session.add(User(email=email, hashed_password=encoded))
        print("User created")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
