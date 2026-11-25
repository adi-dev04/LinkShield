from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import BASE_DIR


# SQLite database location
DATABASE_URL = f"sqlite:///{BASE_DIR / 'linkshield.db'}"


# Create database engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)


# Create database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# Base class for database models
Base = declarative_base()

from typing import Generator


def get_db() -> Generator:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()