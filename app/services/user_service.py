from datetime import datetime, timezone
from typing import Optional, Dict, List
from uuid import UUID
import logging

from pydantic import ValidationError
from sqlalchemy import func, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_settings
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserCreate, UserUpdate, UserProfileUpdate  # ← added
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from app.services.email_service import EmailService

settings = get_settings()
logger = logging.getLogger(__name__)


class UserService:
    # ---------------------------
    # Internal helpers
    # ---------------------------
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        """
        Execute a write/update query with commit + rollback safety.
        """
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        """
        Run a SELECT for User with simple filter_by(**filters).
        """
        try:
            result = await session.execute(select(User).filter_by(**filters))
            return result.scalars().first()
        except SQLAlchemyError as e:
            logger.error(f"Database error during fetch: {e}")
            return None

    # ---------------------------
    # Getters
    # ---------------------------
    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    # ---------------------------
    # CRUD
    # ---------------------------
    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        user_data: Dict[str, str],
        email_service: EmailService
    ) -> Optional[User]:
        try:
            validated_data = UserCreate(**user_data).model_dump()

            # Email uniqueness
            existing_user = await cls.get_by_email(session, validated_data["email"])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            # Determine role BEFORE inserting (so pending row doesn't affect the count)
            user_count = await cls.count(session)
            intended_role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS

            # Hash password
            validated_data["hashed_password"] = hash_password(validated_data.pop("password"))

            # Handle nickname: respect provided if unique; otherwise generate one
            requested_nick = validated_data.pop("nickname", None)
            if requested_nick:
                if await cls.get_by_nickname(session, requested_nick):
                    logger.info("Provided nickname is taken; generating a unique one.")
                    nickname = generate_nickname()
                    while await cls.get_by_nickname(session, nickname):
                        nickname = generate_nickname()
                else:
                    nickname = requested_nick
            else:
                nickname = generate_nickname()
                while await cls.get_by_nickname(session, nickname):
                    nickname = generate_nickname()
            validated_data["nickname"] = nickname

            # Build user with role/verification fields
            new_user = User(**validated_data)
            new_user.role = intended_role
            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True
                new_user.verification_token = None
            else:
                new_user.email_verified = False
                new_user.verification_token = generate_verification_token()

            # Persist (PK assigned on flush if DB-generated)
            session.add(new_user)
            await session.flush()
            await session.refresh(new_user)

            # Commit state (including token) before attempting email
            await session.commit()
            await session.refresh(new_user)

            # Send verification email for non-admins; don't fail the whole request if email fails in dev
            if new_user.role != UserRole.ADMIN:
                try:
                    await email_service.send_verification_email(new_user)
                    logger.info(f"Created ANONYMOUS user {new_user.id}; verification email sent.")
                except Exception as e:
                    logger.warning(f"Email send failed (ignored in dev): {e}")
            else:
                logger.info(f"Created ADMIN user {new_user.id} (auto-verified).")

            return new_user

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            await session.rollback()
            return None
        except Exception as e:
            logger.error(f"Unexpected error during user creation: {e}")
            await session.rollback()
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)
            if "password" in validated_data:
                validated_data["hashed_password"] = hash_password(validated_data.pop("password"))

            query = (
                update(User)
                .where(User.id == user_id)
                .values(**validated_data)
                .execution_options(synchronize_session="fetch")
            )
            await cls._execute_query(session, query)

            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                await session.refresh(updated_user)
                logger.info(f"User {user_id} updated successfully.")
                return updated_user

            logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            await session.rollback()
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        try:
            await session.delete(user)
            await session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            await session.rollback()
            return False

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        try:
            result = await session.execute(select(User).offset(skip).limit(limit))
            return result.scalars().all()
        except SQLAlchemyError as e:
            logger.error(f"Error listing users: {e}")
            return []

    # ---------------------------
    # Auth flows
    # ---------------------------
    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        # Resolve provider -> instance
        email_service = get_email_service() if callable(get_email_service) else get_email_service
        return await cls.create(session, user_data, email_service)

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if not user:
            return None

        # Require verification and unlocked status
        if user.email_verified is False:
            return None
        if user.is_locked:
            return None

        # Password check
        if verify_password(password, user.hashed_password):
            user.failed_login_attempts = 0
            user.last_login_at = datetime.now(timezone.utc)
            session.add(user)
            await session.commit()
            return user

        # Failed auth path
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.is_locked = True
        session.add(user)
        await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return bool(user.is_locked) if user else False

    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            return False
        try:
            user.hashed_password = hash_password(new_password)
            user.failed_login_attempts = 0
            user.is_locked = False
            session.add(user)
            await session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(f"Error resetting password for {user_id}: {e}")
            await session.rollback()
            return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            return False
        if not user.verification_token or user.verification_token != token:
            return False

        user.email_verified = True
        user.verification_token = None  # Clear the token once used

        # Only promote anonymous users (don't downgrade admins, etc.)
        if user.role == UserRole.ANONYMOUS:
            user.role = UserRole.AUTHENTICATED

        session.add(user)
        await session.commit()
        return True

    # ---------------------------
    # Profile & Pro (NEW)
    # ---------------------------
    @classmethod
    async def update_profile(
        cls,
        session: AsyncSession,
        actor_id: UUID,
        target_id: UUID,
        payload: UserProfileUpdate
    ) -> Optional[User]:
        """
        Update profile fields (first_name, last_name, bio, location).
        - Self can update self.
        - Admin/Manager can update anyone.
        """
        try:
            if actor_id != target_id:
                actor = await cls.get_by_id(session, actor_id)
                if actor is None or actor.role not in {UserRole.ADMIN, UserRole.MANAGER}:
                    raise PermissionError("Forbidden")

            data = payload.model_dump(exclude_unset=True)
            if not data:
                return await cls.get_by_id(session, target_id)

            stmt = (
                update(User)
                .where(User.id == target_id)
                .values(**data)
                .returning(User)
            )
            result = await session.execute(stmt)
            await session.commit()
            updated = result.scalar_one_or_none()
            if updated:
                await session.refresh(updated)
            return updated

        except PermissionError:
            raise
        except SQLAlchemyError as e:
            logger.error(f"DB error during profile update: {e}")
            await session.rollback()
            return None
        except Exception as e:
            logger.error(f"Unexpected error during profile update: {e}")
            await session.rollback()
            return None

    @classmethod
    async def upgrade_to_pro(
        cls,
        session: AsyncSession,
        actor_id: UUID,
        target_id: UUID,
        email_service: EmailService
    ) -> Optional[User]:
        """
        Upgrade a user to professional status.
        - Only Admin/Manager can perform.
        - Sets is_professional=True, professional_status_updated_at=now, pro_upgraded_by=actor_id
        - Sends notification email (best-effort).
        """
        try:
            actor = await cls.get_by_id(session, actor_id)
            if actor is None or actor.role not in {UserRole.ADMIN, UserRole.MANAGER}:
                raise PermissionError("Forbidden")

            now = datetime.now(timezone.utc)
            stmt = (
                update(User)
                .where(User.id == target_id)
                .values(
                    is_professional=True,
                    professional_status_updated_at=now,
                    pro_upgraded_by=actor_id
                )
                .returning(User)
            )
            result = await session.execute(stmt)
            await session.commit()
            user = result.scalar_one_or_none()
            if not user:
                return None

            # Best-effort email (don't fail upgrade if email fails)
            try:
                if hasattr(email_service, "send_pro_upgrade_notice"):
                    await email_service.send_pro_upgrade_notice(
                        email=user.email,
                        first_name=getattr(user, "first_name", None)
                    )
            except Exception as e:
                logger.warning(f"send_pro_upgrade_notice failed (ignored): {e}")

            return user

        except PermissionError:
            raise
        except SQLAlchemyError as e:
            logger.error(f"DB error during pro upgrade: {e}")
            await session.rollback()
            return None
        except Exception as e:
            logger.error(f"Unexpected error during pro upgrade: {e}")
            await session.rollback()
            return None

    # ---------------------------
    # Utility
    # ---------------------------
    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        result = await session.execute(select(func.count()).select_from(User))
        return int(result.scalar() or 0)

    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user or not user.is_locked:
            return False
        try:
            user.is_locked = False
            user.failed_login_attempts = 0
            session.add(user)
            await session.commit()
            return True
        except SQLAlchemyError as e:
            logger.error(f"Error unlocking user {user_id}: {e}")
            await session.rollback()
            return False
