import pytest
import asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Database, Base
from app.models.user_model import User, UserRole
from app.dependencies import get_db
from unittest.mock import AsyncMock
from typing import AsyncGenerator
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def test_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest.fixture
async def test_db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    async_session = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session

@pytest.fixture
async def client(test_db_session):
    async def override_get_db():
        yield test_db_session
    
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()

@pytest.fixture
async def user_factory(test_db_session):
    async def _make(**kwargs):
        user_columns = {col.name for col in User.__table__.columns}
        import uuid
        unique_id = str(uuid.uuid4())[:8]
        
        defaults = {
            "email": f"test{unique_id}@example.com",
            "first_name": "Test",
            "last_name": "User", 
            "nickname": f"test_user_{unique_id}",
            "role": UserRole.AUTHENTICATED,
            "hashed_password": pwd_context.hash("testpass123"),
            "email_verified": True,
            "is_professional": False,
            "failed_login_attempts": 0,
            "is_locked": False,
        }
        
        user_data = defaults.copy()
        user_data.update(kwargs)
        
        is_professional = user_data.pop("is_professional", None)
        is_pro = user_data.pop("is_pro", None)
        
        filtered_data = {k: v for k, v in user_data.items() if k in user_columns}
        u = User(**filtered_data)
        
        if hasattr(u, 'is_professional') and (is_professional is not None or is_pro is not None):
            u.is_professional = is_professional if is_professional is not None else is_pro
        
        test_db_session.add(u)
        await test_db_session.commit()
        await test_db_session.refresh(u)
        return u
    
    return _make

@pytest.fixture
async def auth_headers(user_factory):
    async def _make_headers(role=UserRole.AUTHENTICATED, **user_kwargs):
        user = await user_factory(role=role, **user_kwargs)
        
        token = "mock_token_for_testing"
        try:
            from app.services.jwt_service import create_access_token
            # Include sub, role, AND id (this is the key fix)
            token_data = {
                "sub": user.email, 
                "role": user.role.value,
                "id": str(user.id),
                "user_id": user.email  # Keep both for compatibility
            }
            token = create_access_token(data=token_data)
            print("Generated JWT token with id field")
        except ImportError:
            print("Using mock token")
        
        return {"Authorization": f"Bearer {token}"}, user
    
    return _make_headers

@pytest.fixture
async def admin_headers(auth_headers):
    headers, user = await auth_headers(role=UserRole.ADMIN)
    return headers, user

@pytest.fixture
async def user_headers(auth_headers):
    headers, user = await auth_headers(role=UserRole.AUTHENTICATED)
    return headers, user

@pytest.fixture
def mock_email_service():
    mock_service = AsyncMock()
    mock_service.send_pro_upgrade_notice = AsyncMock()
    return mock_service
