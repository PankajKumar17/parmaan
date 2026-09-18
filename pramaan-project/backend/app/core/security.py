import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import User
from app.db.session import get_session

ITERATIONS = 600_000
ISSUER = "pramaan"
AUDIENCE = "pramaan-dashboard"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain between 12 and 256 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return "$".join(("pbkdf2_sha256", str(ITERATIONS), salt.hex(), base64.b64encode(digest).decode()))


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt, expected = encoded.split("$")
        if scheme != "pbkdf2_sha256" or int(iterations) != ITERATIONS or len(password) > 256:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)
        return hmac.compare_digest(actual, base64.b64decode(expected, validate=True))
    except (ValueError, TypeError):
        return False


def issue_token(user: User, settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": user.id, "iat": now, "nbf": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "iss": ISSUER, "aud": AUDIENCE, "jti": secrets.token_hex(16),
    }, settings.jwt_secret_key, algorithm="HS256")


def current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    unauthorized = HTTPException(401, "Invalid or expired credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(
            token, request.app.state.settings.jwt_secret_key, algorithms=["HS256"],
            audience=AUDIENCE, issuer=ISSUER,
            options={"require": ["sub", "exp", "iat", "nbf", "jti", "iss", "aud"]},
        )
    except jwt.InvalidTokenError:
        raise unauthorized from None
    user = session.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise unauthorized
    return user
