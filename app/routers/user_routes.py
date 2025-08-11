"""
User management routes (FastAPI + Async SQLAlchemy).

Key points:
- Robust current_user handling: works with dict/JWT/object and resolves to a DB user.
- Secure endpoints via OAuth2PasswordBearer + role requirements.
- CRUD + HATEOAS links.
- PATCH /users/me accepts snake_case (and common camelCase) aliases.
"""

from typing import Any, Dict, Optional
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Response, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, get_email_service, require_role, get_settings
from app.schemas.token_schema import TokenResponse
from app.schemas.user_schemas import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.utils.link_generation import create_user_links, generate_pagination_links
from app.services.email_service import EmailService

router = APIRouter()
# Align tokenUrl with the actual path below ("/login")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
settings = get_settings()


# ---------------------------
# Helpers
# ---------------------------

async def _resolve_user_from_context(db: AsyncSession, current_user: Any):
    """
    Long-term fix: normalize whatever 'current_user' shape the auth dependency returns
    (dict of JWT claims, object with attributes, etc.) into a real DB user row.
    Priority:
      - UUID-like id/user_id -> get_by_id
      - email-like sub/email -> get_by_email
    """
    # 1) Extract possible identifiers
    uid = None
    email = None

    if isinstance(current_user, dict):
        uid = current_user.get("id") or current_user.get("user_id")
        email = current_user.get("email") or current_user.get("sub")
    else:
        uid = getattr(current_user, "id", None) or getattr(current_user, "user_id", None)
        email = getattr(current_user, "email", None) or getattr(current_user, "sub", None)

    # 2) Try by id first (if it looks like a UUID)
    user = None
    if uid:
        try:
            # Allow passing UUID or string UUID
            user = await UserService.get_by_id(db, UUID(str(uid)))
        except Exception:
            user = None

    # 3) Fallback to email (common "sub" in JWT is email)
    if not user and email and "@" in str(email):
        user = await UserService.get_by_email(db, str(email))

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or unknown user context")

    return user


def _normalize_patch_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept snake_case and some camelCase aliases and map to internal columns.
    """
    if not payload:
        return {}

    key_map = {
        "display_name": "nickname",
        "displayName": "nickname",
        "avatar_url": "profile_picture_url",
        "profilePictureUrl": "profile_picture_url",
        # pass-throughs below will be handled as-is if in allowed
    }

    allowed = {
        "nickname",
        "first_name",
        "last_name",
        "bio",
        "profile_picture_url",
        "linkedin_profile_url",
        "github_profile_url",
        "email",  # include only if business rules allow changing email here
    }

    out: Dict[str, Any] = {}
    for k, v in payload.items():
        mapped = key_map.get(k, k)
        if mapped in allowed:
            out[mapped] = v
    return out


def _to_user_response(user, request: Optional[Request] = None) -> UserResponse:
    return UserResponse.model_construct(
        id=user.id,
        nickname=user.nickname,
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        profile_picture_url=user.profile_picture_url,
        github_profile_url=user.github_profile_url,
        linkedin_profile_url=user.linkedin_profile_url,
        role=user.role,
        email=user.email,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        links=create_user_links(user.id, request) if request is not None else None,
    )


# ---------------------------
# Routes
# ---------------------------

@router.get("/users/me", response_model=UserResponse, tags=["User Management"])
async def get_current_user_profile(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
):
    """
    Get the current authenticated user's profile.
    Works whether the auth layer returns a dict of claims or an object.
    """
    user = await _resolve_user_from_context(db, current_user)
    return _to_user_response(user, request)


@router.patch("/users/me", response_model=UserResponse, tags=["User Management"])
async def patch_me(
    payload: Dict[str, Any] = Body(...),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
):
    """
    Partially update the current user's profile.
    Accepts snake_case (and some camelCase) keys and maps to internal fields.
    """
    update_data = _normalize_patch_payload(payload)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid fields to update")

    user = await _resolve_user_from_context(db, current_user)
    updated_user = await UserService.update(db, user.id, update_data)
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return _to_user_response(updated_user, request)


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    name="get_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def get_user(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: Any = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _to_user_response(user, request)


@router.put(
    "/users/{user_id}",
    response_model=UserResponse,
    name="update_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: Any = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _to_user_response(updated_user, request)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    name="delete_user",
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: Any = Depends(require_role(["ADMIN", "MANAGER"])),
):
    success = await UserService.delete(db, user_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/users/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["User Management Requires (Admin or Manager Roles)"],
    name="create_user",
)
async def create_user(
    user: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
    token: str = Depends(oauth2_scheme),
    current_user: Any = Depends(require_role(["ADMIN", "MANAGER"])),
):
    existing_user = await UserService.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    created_user = await UserService.create(db, user.model_dump(), email_service)
    if not created_user:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

    return _to_user_response(created_user, request)


@router.get(
    "/users/",
    response_model=UserListResponse,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def list_users(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(require_role(["ADMIN", "MANAGER"])),
):
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)

    items = [_to_user_response(u, request) for u in users]
    pagination_links = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=items,
        total=total_users,
        page=skip // limit + 1,
        size=len(items),
        links=pagination_links,
    )


# -------- Login & Registration --------

@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    if user:
        # user may already be a schema depending on implementation; adapt if needed
        return _to_user_response(user)
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")


@router.post("/login", response_model=TokenResponse, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account locked due to too many failed login attempts.")

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if user:
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={"sub": user.email, "role": str(user.role.name)},
            expires_delta=access_token_expires,
        )
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password.")
