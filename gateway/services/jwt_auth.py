"""
Data443 LLM Gateway - JWT Authentication Layer

Validates JWT tokens on incoming requests.
Supports configurable token issuer and secret.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.security.utils import get_authorization_scheme_param
from loguru import logger

from jose import jwt, JWTError

from gateway.core.config import settings

_DEFAULT_TOKEN_EXPIRY_HOURS = 1


class JWTAuth:
    """JWT authentication handler."""

    def __init__(
        self,
        secret: Optional[str] = None,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
    ):
        configured_secret = secret if secret is not None else settings.jwt_secret
        self.secret = (configured_secret or "").strip()
        self.algorithm = "HS256"
        self.issuer = issuer or settings.jwt_issuer
        self.audience = audience or settings.jwt_audience

    def create_token(
        self,
        user_id: str,
        additional_claims: Optional[dict] = None,
        expires_hours: Optional[int] = None,
    ) -> str:
        """Create a JWT token with mandatory expiration."""
        if not self.secret:
            raise ValueError("JWT secret is not configured")

        exp_hours = expires_hours if expires_hours is not None else _DEFAULT_TOKEN_EXPIRY_HOURS
        now = datetime.now(timezone.utc)
        claims = {
            "sub": user_id,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + timedelta(hours=max(1, exp_hours)),
        }

        if additional_claims:
            claims.update(additional_claims)

        token = jwt.encode(
            claims,
            self.secret,
            algorithm=self.algorithm
        )

        logger.info(f"Created token for user: {user_id}")
        return token

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify a JWT token including signature, issuer, audience, and expiry."""
        if not self.secret:
            logger.error("JWT verification requested but JWT secret is not configured")
            return None

        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={"require_exp": True, "verify_exp": True},
            )
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            return None


# JWT Bearer token scheme
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = HTTPBearer(),
    jwt_auth: JWTAuth = None
) -> Optional[str]:
    """
    Get current user from JWT token in Authorization header.

    Args:
        credentials: HTTP Bearer credentials
        jwt_auth: JWT authentication handler

    Returns:
        User ID from token, or raises HTTPException if invalid
    """
    if jwt_auth is None:
        # Initialize if not provided (will use settings)
        jwt_auth = JWTAuth()

    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_error

    token = credentials.credentials

    # Verify token
    payload = jwt_auth.verify_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired JWT token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token: missing subject",
        )

    logger.debug(f"Authenticated user: {user_id}")
    return user_id


async def get_current_user_from_request(
    request: Request,
    jwt_auth: JWTAuth = None,
) -> Optional[str]:
    """
    Get current user from Authorization header in a Request.

    Args:
        request: FastAPI Request
        jwt_auth: JWT authentication handler

    Returns:
        User ID from token, or raises HTTPException if invalid
    """
    if jwt_auth is None:
        jwt_auth = JWTAuth()

    auth_header = request.headers.get("authorization") or request.headers.get("Authorization", "")
    scheme, token = get_authorization_scheme_param(auth_header)

    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not scheme or scheme.lower() != "bearer" or not token:
        raise credentials_error

    payload = jwt_auth.verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired JWT token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid JWT token: missing subject",
        )

    logger.debug(f"Authenticated user: {user_id}")
    return user_id


async def optional_auth(
    credentials: HTTPAuthorizationCredentials = HTTPBearer(),
    jwt_auth: JWTAuth = None
) -> Optional[str]:
    """
    Optional authentication - returns user if token valid, None if not provided or invalid.

    Args:
        credentials: HTTP Bearer credentials
        jwt_auth: JWT authentication handler

    Returns:
        User ID from token, or None if not authenticated
    """
    if jwt_auth is None:
        jwt_auth = JWTAuth()

    if not credentials:
        logger.debug("No authentication provided")
        return None

    token = credentials.credentials
    payload = jwt_auth.verify_token(token)

    if payload is None:
        logger.warning("Invalid JWT token provided")
        return None

    return payload.get("sub")


# Global JWT auth instance
jwt_auth_handler = JWTAuth()


def get_jwt_auth() -> JWTAuth:
    """Get global JWT auth handler instance."""
    return jwt_auth_handler
