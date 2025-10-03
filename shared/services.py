from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import func, select

from .database import get_session
from .models import AllowedDomain, User, VpnKey, VpnSession
from .security import hash_password, verify_password

MODE_FULL = "full"
MODE_DOMAINS = "domains"

MODE_LIMITS_SECONDS = {
    MODE_FULL: 5 * 60 * 60,
    MODE_DOMAINS: 60 * 60,
}


@dataclass(slots=True)
class SessionInfo:
    session_id: int
    mode: str
    key_value: Optional[str]
    username: Optional[str]
    quota_seconds: Optional[int]
    started_at: datetime


def ensure_seed_domains(domains: Iterable[str]) -> None:
    with get_session() as session:
        for domain in domains:
            existing = session.scalar(select(AllowedDomain).where(AllowedDomain.domain == domain))
            if existing is None:
                session.add(AllowedDomain(domain=domain))


def ensure_admin_user(username: str, password: str) -> User:
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == username))
        password_hash = hash_password(password)
        if user is None:
            user = User(username=username, password_hash=password_hash, is_admin=True, is_unlimited=True)
            session.add(user)
        else:
            if not user.is_admin:
                user.is_admin = True
            if not verify_password(password, user.password_hash):
                user.password_hash = password_hash
            if not user.is_unlimited:
                user.is_unlimited = True
            session.add(user)
        return user


def create_user(username: str, password: str) -> User:
    with get_session() as session:
        existing = session.scalar(select(User).where(User.username == username))
        if existing is not None:
            raise ValueError("Пользователь с таким именем уже существует")
        user = User(username=username, password_hash=hash_password(password))
        session.add(user)
        return user


def authenticate_user(username: str, password: str) -> Optional[User]:
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == username))
        if user and verify_password(password, user.password_hash):
            return user
        return None


def create_key(label: Optional[str] = None, owner_email: Optional[str] = None, max_sessions: int = 1) -> VpnKey:
    key_value = VpnKey.generate_key()
    with get_session() as session:
        key = VpnKey(key=key_value, label=label, owner_email=owner_email, max_sessions=max_sessions)
        session.add(key)
    return key


def list_keys() -> list[VpnKey]:
    with get_session() as session:
        result = session.scalars(select(VpnKey)).all()
        return list(result)


def redeem_key_for_user(username: str, password: str, key_value: str) -> tuple[User, VpnKey]:
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == username))
        if user is None or not verify_password(password, user.password_hash):
            raise ValueError("Неверные учётные данные пользователя")
        key = session.scalar(select(VpnKey).where(VpnKey.key == key_value))
        if key is None or not key.is_active:
            raise ValueError("Ключ не существует или не активен")
        user.is_unlimited = True
        user.redeemed_key_id = key.id
        session.add(user)
        return user, key


def allowed_domains() -> list[str]:
    with get_session() as session:
        records = session.scalars(select(AllowedDomain).where(AllowedDomain.is_enabled == True)).all()  # noqa: E712
        return [record.domain for record in records]


def _today() -> datetime:
    return datetime.utcnow()


def _calculate_usage_seconds(session, user_id: int, mode: str, window_start: datetime) -> int:
    total = session.scalar(
        select(func.coalesce(func.sum(VpnSession.duration_seconds), 0)).where(
            VpnSession.user_id == user_id,
            VpnSession.mode == mode,
            VpnSession.started_at >= window_start,
        )
    )
    return int(total or 0)


def begin_session_with_key(key_value: str, mode: str) -> Optional[SessionInfo]:
    with get_session() as session:
        key = session.scalar(select(VpnKey).where(VpnKey.key == key_value))
        if key is None or not key.is_active:
            return None
        if key.current_sessions >= key.max_sessions:
            return None
        key.current_sessions += 1
        key.last_seen_at = datetime.utcnow()
        vpn_session = VpnSession(key=key, mode=mode)
        session.add(key)
        session.add(vpn_session)
        session.flush()
        return SessionInfo(
            session_id=vpn_session.id,
            mode=mode,
            key_value=key_value,
            username=None,
            quota_seconds=None,
            started_at=vpn_session.started_at,
        )


def begin_session_with_user(username: str, password: str, mode: str) -> Optional[SessionInfo]:
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == username))
        if user is None or not verify_password(password, user.password_hash):
            return None

        quota_seconds: Optional[int] = None
        if not user.is_unlimited:
            window_start = _today().replace(hour=0, minute=0, second=0, microsecond=0)
            used_seconds = _calculate_usage_seconds(session, user.id, mode, window_start)
            limit_seconds = MODE_LIMITS_SECONDS[mode]
            remaining = limit_seconds - used_seconds
            if remaining <= 0:
                return SessionInfo(
                    session_id=-1,
                    mode=mode,
                    key_value=None,
                    username=username,
                    quota_seconds=0,
                    started_at=datetime.utcnow(),
                )
            quota_seconds = remaining

        vpn_session = VpnSession(user=user, mode=mode, allocated_seconds=quota_seconds)
        session.add(vpn_session)
        session.flush()

        return SessionInfo(
            session_id=vpn_session.id,
            mode=mode,
            key_value=None,
            username=username,
            quota_seconds=quota_seconds,
            started_at=vpn_session.started_at,
        )


def end_session(info: SessionInfo) -> None:
    if info.session_id <= 0:
        return
    with get_session() as session:
        record = session.scalar(select(VpnSession).where(VpnSession.id == info.session_id))
        if record is None:
            return
        now = datetime.utcnow()
        duration = max(0, int((now - info.started_at).total_seconds()))
        if info.quota_seconds is not None:
            duration = min(duration, info.quota_seconds)
        record.ended_at = now
        record.duration_seconds = duration
        session.add(record)

        if info.key_value:
            key = session.scalar(select(VpnKey).where(VpnKey.key == info.key_value))
            if key:
                if key.current_sessions > 0:
                    key.current_sessions -= 1
                key.last_seen_at = now
                session.add(key)
