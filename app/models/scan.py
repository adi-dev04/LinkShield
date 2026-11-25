from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.sql import func

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    scan_id = Column(String(50), unique=True, index=True, nullable=False)

    scan_type = Column(String(20), nullable=False)

    target = Column(String(1000), nullable=False)

    status = Column(String(20), default="completed")

    risk_level = Column(String(30), default="inconclusive")

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    file_name = Column(String(255), nullable=True)

    file_size = Column(Integer, nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(String(50), nullable=False, index=True)

    title = Column(String(255), nullable=False)

    description = Column(String(1000), nullable=False)

    severity = Column(String(20), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String(100), nullable=False)

    email = Column(String(255), unique=True, index=True, nullable=False)

    hashed_password = Column(String(255), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
