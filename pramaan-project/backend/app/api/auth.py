from collections import OrderedDict, deque
from threading import Lock
from time import monotonic

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import current_user, hash_password, issue_token, verify_password
from app.db.models import User
from app.db.session import get_session

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginLimiter:
    def __init__(self):
        self.entries = OrderedDict()
        self.lock = Lock()

    def check(self, client: str):
        now = monotonic()
        with self.lock:
            attempts = self.entries.setdefault(client, deque())
            while attempts and attempts[0] < now - 60:
                attempts.popleft()
            if len(attempts) >= 10:
                raise HTTPException(429, "Too many login attempts", headers={"Retry-After": "60"})
            attempts.append(now)
            self.entries.move_to_end(client)
            if len(self.entries) > 10_000:
                self.entries.popitem(last=False)


def initialize_auth(app):
    app.state.login_limiter = LoginLimiter()
    app.state.dummy_password_hash = hash_password("unusable-" + __import__("secrets").token_hex(32))


@router.post("/login")
def login(
    request: Request,
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    request.app.state.login_limiter.check(request.client.host if request.client else "unknown")
    if len(form.username) > 254 or len(form.password) > 256:
        raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    user = session.scalar(select(User).where(User.email == form.username.strip().lower()))
    encoded = user.hashed_password if user else request.app.state.dummy_password_hash
    valid = verify_password(form.password, encoded)
    if not valid or user is None or not user.is_active:
        raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {"access_token": issue_token(user, request.app.state.settings), "token_type": "bearer"}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "is_active": user.is_active}
