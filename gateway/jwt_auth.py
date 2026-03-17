"""
Data443 LLM Gateway - JWT Authentication Layer

Validates JWT tokens on incoming requests.
Supports configurable token issuer and secret.
"""

from typing import Optional
from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger

# python-jose is the JWT library (jose provides jwt alias)
# Using type: ignore to suppress Pylance warnings for jose module
try:
    from jose import jwt, JWTError
except ImportError:
    # Fallback to python-jose if jose is not available
    from python_jose import jwt, JWTError
    logger.info("Using python-jose library")

from config.settings import settings


class JWTAuth:
    """JWT authentication handler."""

    def __init__(self):
        self.secret = settings.jwt_secret if settings.jwt_secret else "default-secret-key-change-in-production"
        self.algorithm = "HS256"
        self.issuer = settings.jwt_issuer
        self.audience = settings.jwt_audience

    def create_token(
        self,
        user_id: str,
        additional_claims: Optional[dict] = None
    ) -> str:  # type: ignore
        """
        Create a JWT token.

        Args:
            user_id: User identifier
            additional_claims: Additional claims to include in token

        Returns:
            JWT token string
        """
        claims = {
            "sub": user_id,
            "iss": self.issuer,
            "aud": self.audience,
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

    def verify_token(self, token: str) -> Optional[dict]:  # type: ignore
        """
        Verify a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded claims dict, or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience
            )
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            return None

    def decode_token(self, token: str) -> Optional[dict]:  # type: ignore
        """
        Decode JWT token without verification (for debugging).

        Args:
            token: JWT token string

        Returns:
            Decoded claims dict, or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                options={"verify_signature": False}
            )
            return payload
        except JWTError as e:
            logger.error(f"JWT decode failed: {str(e)}")
            return None


# JWT Bearer token scheme
security = HTTPBearer()


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
    """Get the global JWT auth handler instance."""
    return jwt_auth_handler
