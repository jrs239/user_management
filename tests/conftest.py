# tests/conftest.py
import asyncio
import pytest
from types import SimpleNamespace
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app as real_app
from app.dependencies import get_db, get_email_service
from app.models.user_model import Base, User, UserRole
from app.services.email_service import EmailService

# ---------- Async event loop for pytest ----------
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# ---------- Test DB (SQLite in-memory) ----------
@pytest.fixture(scope="session")
async def test_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest.fixture()
async def session(test_engine):
    async_session = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as s:
        yield s
        await s.rollback()

# ---------- Dependency overrides ----------
class EmailSpy(EmailService):
    def __init__(self): pass
    async def send_pro_upgrade_notice(self, user):  # spy method
        self.last_user = user
        return None

@pytest.fixture()
def app(session):
    app: FastAPI = real_app

    async def _get_db_override():
        yield session
    app.dependency_overrides[get_db] = _get_db_override

    spy = EmailSpy()
    app.dependency_overrides[get_email_service] = lambda: spy

    yield app

    app.dependency_overrides.clear()

@pytest.fixture()
def email_spy(app):
    # retrieve the spy we installed above
    override = app.dependency_overrides[get_email_service]
    return override()

# ---------- Helpers ----------
@pytest.fixture()
async def user_factory(session):
    async def _make(
        email: str = None,
        role: UserRole = UserRole.AUTHENTICATED,
        is_pro: bool = False,
        first_name: str = "Jorge",
        last_name: str = "Doe",
    ):
        u = User(
            id=uuid4(),
            email=email or f"user_{uuid4().hex[:6]}@example.com",
            password_hash="$2b$12$Zolrf23B03EPU.zct..0YeRrMBGioFIODG/fVF5YIGdiOCikUHJKu",  # bcrypt for "password"
            role=role,
            nickname="testnick",
            first_name=first_name,
            last_name=last_name,
            is_email_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_pro=is_pro,
        )
        session.add(u)
        await session.commit()
        await session.refresh(u)
        return u
    return _make

@pytest.fixture()
async def client(app) -> AsyncClient:
    async with AsyncClient(app=app, base_url="http://test") as c:
        yield c

@pytest.fixture()
def bearer(user_factory):
    # builds an auth header for routes using get_current_user (we'll override via dependency later if needed)
    def _bearer_for(user):
        # We won't mint a JWT; your /users/me route reads get_current_user.
        # If your get_current_user strictly parses JWT, you can instead hit /login to get a real token.
        return {"Authorization": f"Bearer FAKE.{user.id}.TOKEN"}
    return _bearer_for
