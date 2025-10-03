from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class VpnKey(Base):
    __tablename__ = "vpn_keys"
    __table_args__ = (UniqueConstraint("key", name="uq_vpn_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    max_sessions: Mapped[int] = mapped_column(Integer, default=1)
    current_sessions: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    owner_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    sessions: Mapped[list["VpnSession"]] = relationship("VpnSession", back_populates="key")

    @staticmethod
    def generate_key() -> str:
        return str(uuid.uuid4())


class AllowedDomain(Base):
    __tablename__ = "allowed_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_user_username"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    redeemed_key_id: Mapped[Optional[int]] = mapped_column(ForeignKey("vpn_keys.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    sessions: Mapped[list["VpnSession"]] = relationship("VpnSession", back_populates="user")


class VpnSession(Base):
    __tablename__ = "vpn_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    key_id: Mapped[Optional[int]] = mapped_column(ForeignKey("vpn_keys.id"), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    allocated_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    user: Mapped[Optional[User]] = relationship("User", back_populates="sessions")
    key: Mapped[Optional[VpnKey]] = relationship("VpnKey", back_populates="sessions")
