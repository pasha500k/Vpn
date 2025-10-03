from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from shared.database import Base, engine, get_session
from shared.models import AllowedDomain, User, VpnKey
from shared.services import (
    MODE_DOMAINS,
    MODE_FULL,
    MODE_LIMITS_SECONDS,
    allowed_domains as load_allowed_domains,
    create_key,
    create_user,
    ensure_admin_user,
    redeem_key_for_user,
)

APP_TITLE = "Launchpad VPN Control"

app = FastAPI(title=APP_TITLE, version="0.2.0")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

security = HTTPBasic()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "pasha500k")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Hehetoto123")


@app.on_event("startup")
async def startup() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_admin_user(ADMIN_USERNAME, ADMIN_PASSWORD)


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    username_ok = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    password_ok = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def get_db_session():
    with get_session() as session:
        yield session


async def render_home(request: Request, status_message: Optional[str] = None, status_level: str = "info"):
    domains = load_allowed_domains()
    limits = {
        MODE_FULL: MODE_LIMITS_SECONDS[MODE_FULL] // 3600,
        MODE_DOMAINS: MODE_LIMITS_SECONDS[MODE_DOMAINS] // 3600,
    }
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "domains": domains,
            "limits": limits,
            "status_message": status_message,
            "status_level": status_level,
            "app_title": APP_TITLE,
        },
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return await render_home(request)


@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    try:
        if len(username) < 3:
            raise ValueError("Имя пользователя должно содержать минимум 3 символа")
        if len(password) < 6:
            raise ValueError("Пароль должен содержать минимум 6 символов")
        create_user(username=username, password=password)
        message = "Профиль создан. Используйте его в клиенте для входа."
        return await render_home(request, status_message=message, status_level="success")
    except ValueError as exc:
        return await render_home(request, status_message=str(exc), status_level="error")


@app.post("/redeem", response_class=HTMLResponse)
async def redeem_key(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    key_value: str = Form(...),
):
    try:
        redeem_key_for_user(username=username, password=password, key_value=key_value)
        message = "Ключ успешно активирован. Доступ стал безлимитным."
        return await render_home(request, status_message=message, status_level="success")
    except ValueError as exc:
        return await render_home(request, status_message=str(exc), status_level="error")


@app.get("/admin", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session=Depends(get_db_session),
    admin_user: str = Depends(require_admin),
):
    keys = session.scalars(select(VpnKey)).all()
    domains = session.scalars(select(AllowedDomain).order_by(AllowedDomain.domain)).all()
    users = session.scalars(select(User).order_by(User.username)).all()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "keys": keys,
            "domains": domains,
            "admin_user": admin_user,
            "users": users,
        },
    )


@app.post("/keys", response_class=RedirectResponse, dependencies=[Depends(require_admin)])
async def create_key_view(
    label: Optional[str] = Form(default=None),
    email: Optional[str] = Form(default=None),
    max_sessions: int = Form(default=1),
):
    create_key(label=label, owner_email=email, max_sessions=max_sessions)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/domains", response_class=RedirectResponse, dependencies=[Depends(require_admin)])
async def create_domain_view(
    domain: str = Form(...),
    description: Optional[str] = Form(default=None),
):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    with get_session() as session:
        existing = session.scalar(select(AllowedDomain).where(AllowedDomain.domain == domain))
        if existing:
            existing.description = description
            existing.is_enabled = True
            session.add(existing)
        else:
            session.add(AllowedDomain(domain=domain, description=description))
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post(
    "/domains/{domain}/toggle",
    response_class=RedirectResponse,
    dependencies=[Depends(require_admin)],
)
async def toggle_domain(domain: str):
    with get_session() as session:
        record = session.scalar(select(AllowedDomain).where(AllowedDomain.domain == domain))
        if record is None:
            raise HTTPException(status_code=404, detail="Domain not found")
        record.is_enabled = not record.is_enabled
        session.add(record)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post(
    "/keys/{key_value}/toggle",
    response_class=RedirectResponse,
    dependencies=[Depends(require_admin)],
)
async def toggle_key(key_value: str):
    with get_session() as session:
        record = session.scalar(select(VpnKey).where(VpnKey.key == key_value))
        if record is None:
            raise HTTPException(status_code=404, detail="Key not found")
        record.is_active = not record.is_active
        session.add(record)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post(
    "/keys/{key_value}/reset",
    response_class=RedirectResponse,
    dependencies=[Depends(require_admin)],
)
async def reset_sessions(key_value: str):
    with get_session() as session:
        record = session.scalar(select(VpnKey).where(VpnKey.key == key_value))
        if record is None:
            raise HTTPException(status_code=404, detail="Key not found")
        record.current_sessions = 0
        session.add(record)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/keys/{key_value}")
async def api_validate_key(key_value: str):
    with get_session() as session:
        record = session.scalar(select(VpnKey).where(VpnKey.key == key_value))
        if record is None:
            raise HTTPException(status_code=404, detail="Invalid key")
        return {
            "key": record.key,
            "is_active": record.is_active,
            "max_sessions": record.max_sessions,
            "current_sessions": record.current_sessions,
            "label": record.label,
            "owner_email": record.owner_email,
            "last_seen_at": record.last_seen_at,
        }


@app.get("/api/domains")
async def api_domains():
    with get_session() as session:
        records = session.scalars(select(AllowedDomain).where(AllowedDomain.is_enabled == True)).all()  # noqa: E712
        return {"domains": [record.domain for record in records]}
