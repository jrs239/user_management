from builtins import dict, int, len, str
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, get_email_service, require_role, get_settings
from app.schemas.token_schema import TokenResponse
from app.schemas.user_schemas import (
    UserCreate,
    UserListResponse,
    UserResponse,
    UserUpdate,
    UserProfileUpdate,
)
from app.services.user_service import UserService
from app.services.jwt_service import create_access_token
from app.utils.link_generation import create_user_links, generate_pagination_links
from app.services.email_service import EmailService

router = APIRouter()
# keep this consistent with dependencies.py
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")
settings = get_settings()


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
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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
        links=create_user_links(user.id, request),
    )


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
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),

):
    user_data = user_update.model_dump(exclude_unset=True)
    updated_user = await UserService.update(db, user_id, user_data)
    if not updated_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserResponse.model_construct(
        id=updated_user.id,
        bio=updated_user.bio,
        first_name=updated_user.first_name,
        last_name=updated_user.last_name,
        nickname=updated_user.nickname,
        email=updated_user.email,
        role=updated_user.role,
        last_login_at=updated_user.last_login_at,
        profile_picture_url=updated_user.profile_picture_url,
        github_profile_url=updated_user.github_profile_url,
        linkedin_profile_url=updated_user.linkedin_profile_url,
        created_at=updated_user.created_at,
        updated_at=updated_user.updated_at,
        links=create_user_links(updated_user.id, request),
    )


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
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),
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
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),

):
    existing_user = await UserService.get_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    created_user = await UserService.create(db, user.model_dump(), email_service)
    if not created_user:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

    return UserResponse.model_construct(
        id=created_user.id,
        bio=created_user.bio,
        first_name=created_user.first_name,
        last_name=created_user.last_name,
        profile_picture_url=created_user.profile_picture_url,
        nickname=created_user.nickname,
        email=created_user.email,
        role=created_user.role,
        last_login_at=created_user.last_login_at,
        created_at=created_user.created_at,
        updated_at=created_user.updated_at,
        links=create_user_links(created_user.id, request),
    )


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
    current_user: dict = Depends(require_role(["ADMIN", "MANAGER"])),

):
    total_users = await UserService.count(db)
    users = await UserService.list_users(db, skip, limit)

    user_responses = [UserResponse.model_validate(user) for user in users]
    pagination_links = generate_pagination_links(request, skip, limit, total_users)

    return UserListResponse(
        items=user_responses,
        total=total_users,
        page=skip // limit + 1,
        size=len(user_responses),
        links=pagination_links,
    )


@router.post("/register/", response_model=UserResponse, tags=["Login and Registration"])
async def register(
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db),
    email_service: EmailService = Depends(get_email_service),
):
    user = await UserService.register_user(session, user_data.model_dump(), email_service)
    if user:
        return user
    raise HTTPException(status_code=400, detail="Email already exists")


@router.post("/login/", response_model=TokenResponse, tags=["Login and Registration"])
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_db),
):
    if await UserService.is_account_locked(session, form_data.username):
        raise HTTPException(status_code=400, detail="Account locked due to too many failed login attempts.")

    user = await UserService.login_user(session, form_data.username, form_data.password)
    if user:
        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        # include "id" so get_current_user can read it
        access_token = create_access_token(
            data={"sub": user.email, "id": str(user.id), "role": str(user.role.name)},
            expires_delta=access_token_expires,
        )
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Incorrect email or password.")


# ----------------------------
# Profile + Pro Upgrade
# ----------------------------

from uuid import UUID as _UUID_type
from app.services.user_service import UserService as _USvc

async def _resolve_actor_uuid(db: AsyncSession, principal: dict) -> _UUID_type:
    raw = principal.get("id") or principal.get("user_id")
    if not raw:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        return _UUID_type(str(raw))
    except Exception:
        # treat as email and resolve
        user = await _USvc.get_by_email(db, str(raw))
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token principal")
        return user.id


@router.patch("/users/me", response_model=dict, tags=["User Profile"])
async def update_my_profile(
    payload: UserProfileUpdate,
    db: AsyncSession = Depends(get_db),
    me: dict = Depends(get_current_user),
):
    actor_uuid = await _resolve_actor_uuid(db, me)
    updated = await UserService.update_profile(
        session=db,
        actor_id=actor_uuid,
        target_id=actor_uuid,
        payload=payload,
    )
    if not updated:
        raise HTTPException(status_code=400, detail="Unable to update profile")
    return {"message": "Profile updated", "user_id": str(updated.id)}


@router.patch(
    "/users/{user_id}/profile",
    response_model=dict,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def admin_update_profile(
    user_id: UUID,
    payload: UserProfileUpdate,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_role(["ADMIN", "MANAGER"])),
):
    actor_uuid = await _resolve_actor_uuid(db, admin)
    updated = await UserService.update_profile(
        session=db,
        actor_id=actor_uuid,
        target_id=user_id,
        payload=payload,
    )
    if not updated:
        raise HTTPException(status_code=400, detail="Unable to update profile")
    return {"message": "Profile updated", "user_id": str(updated.id)}


@router.post(
    "/admin/users/{user_id}/upgrade-pro",
    response_model=dict,
    tags=["User Management Requires (Admin or Manager Roles)"],
)
async def admin_upgrade_to_pro(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: dict = Depends(require_role(["ADMIN", "MANAGER"])),
    email_service: EmailService = Depends(get_email_service),
):
    actor_uuid = await _resolve_actor_uuid(db, admin)
    upgraded_user = await UserService.upgrade_to_pro(
        session=db,
        actor_id=actor_uuid,
        target_id=user_id,
        email_service=email_service,
    )
    if not upgraded_user:
        raise HTTPException(status_code=400, detail="Unable to upgrade user")
    return {
        "message": "User upgraded to professional",
        "user_id": str(upgraded_user.id),
        "pro_since": upgraded_user.pro_since.isoformat() if getattr(upgraded_user, "pro_since", None) else None,
        "pro_upgraded_by": str(upgraded_user.pro_upgraded_by) if getattr(upgraded_user, "pro_upgraded_by", None) else None,
    }
