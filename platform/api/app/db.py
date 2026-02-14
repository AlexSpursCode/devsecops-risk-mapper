from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)


@contextmanager
def session_scope() -> Session:
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
