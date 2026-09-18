from collections.abc import Generator
import sqlite3

from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import ConnectionPoolEntry, StaticPool


def create_database(database_url: str) -> tuple[Engine, sessionmaker[Session]]:
    url = make_url(database_url)
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")

    if url.get_backend_name() == "sqlite":
        memory = (
            url.database in {None, "", ":memory:"}
            or url.database == "file::memory:"
            or url.query.get("mode") == "memory"
        )
        options = {"check_same_thread": False}
        if memory:
            engine = create_engine(url, connect_args=options, poolclass=StaticPool)
        else:
            engine = create_engine(url, connect_args=options)

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(
            connection: sqlite3.Connection, connection_record: ConnectionPoolEntry
        ) -> None:
            cursor = connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()
    else:
        engine = create_engine(url)

    return engine, sessionmaker(bind=engine)


def get_session(request: Request) -> Generator[Session, None, None]:
    with request.app.state.session_factory() as session:
        yield session
