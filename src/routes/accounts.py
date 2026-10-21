from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from schemas import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime (SQLite drops timezone data)."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    """Create an inactive user and the token used to activate the account."""

    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == str(user_data.email))
        )
        if result.scalars().first() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        user_group = group_result.scalars().first()
        if user_group is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )

        user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=cast(int, user_group.id),
        )
        db.add(user)
        await db.flush()
        db.add(ActivationTokenModel(user_id=cast(int, user.id)))
        await db.commit()
        await db.refresh(user)
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema.model_validate(user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Activate an account when its email and activation token are valid."""

    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == str(activation_data.email))
        )
        user = user_result.scalars().first()

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )
        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        token_result = await db.execute(
            select(ActivationTokenModel).where(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == activation_data.token,
            )
        )
        token_record = token_result.scalars().first()
        if (
            token_record is None
            or _as_utc(cast(datetime, token_record.expires_at))
            <= datetime.now(timezone.utc)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True
        await db.delete(token_record)
        await db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Create a fresh reset token without revealing whether an account exists."""

    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == str(reset_data.email))
        )
        user = user_result.scalars().first()

        if user is not None and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
            await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while requesting a password reset.",
        )

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Replace an active user's password after validating a one-use reset token."""

    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == str(reset_data.email))
        )
        user = user_result.scalars().first()

        token_record = None
        if user is not None:
            token_result = await db.execute(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            token_record = token_result.scalars().first()

        token_is_valid = (
            user is not None
            and user.is_active
            and token_record is not None
            and token_record.token == reset_data.token
            and _as_utc(cast(datetime, token_record.expires_at))
            > datetime.now(timezone.utc)
        )
        if not token_is_valid:
            if token_record is not None:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = reset_data.password
        await db.delete(token_record)
        await db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    """Authenticate a user and persist a newly issued refresh token."""

    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == str(login_data.email))
        )
        user = user_result.scalars().first()
        if user is None or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        token_data = {"user_id": cast(int, user.id)}
        access_token = jwt_manager.create_access_token(token_data)
        refresh_token = jwt_manager.create_refresh_token(token_data)
        db.add(
            RefreshTokenModel.create(
                user_id=cast(int, user.id),
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token,
            )
        )
        await db.commit()
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """Issue a new access token for a valid, stored refresh token."""

    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    user_id = payload.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    token_result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )
    token_record = token_result.scalars().first()
    if token_record is None or token_record.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    if (
        _as_utc(cast(datetime, token_record.expires_at))
        <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    if user_result.scalars().first() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=access_token)
