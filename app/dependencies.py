from builtins import Exception, dict, str
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings


def get_settings() -> Settings:
    """Return application settings."""
    return Settings()


def get_email_service() -> EmailService:
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)


async def get_db() -> AsyncSession:
    """Dependency that provides a database session for each request."""
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")


def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Decode JWT and normalize the shape to always return {"id": <uuid_str>, "role": <role>}.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    role = payload.get("role")
    if role is None:
        raise credentials_exception

    # Prefer explicit "id"
    user_id = payload.get("id")

    # Fallback: check "user_id"
    if not user_id:
        user_id = payload.get("user_id")

    # Last fallback: treat "sub" as UUID if possible
    if not user_id and "sub" in payload:
        try:
            _ = UUID(str(payload["sub"]))
            user_id = payload["sub"]
        except Exception:
            raise credentials_exception

    if not user_id:
        raise credentials_exception

    return {"id": str(user_id), "role": role}


def require_role(roles):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return current_user
    return role_checker
