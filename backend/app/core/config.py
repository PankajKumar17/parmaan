import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_secret_key: str
    access_token_minutes: int = 30
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)

    def __post_init__(self):
        if len(self.jwt_secret_key.encode()) < 32:
            raise ValueError("JWT_SECRET_KEY must contain at least 32 bytes")
        if not 1 <= self.access_token_minutes <= 60:
            raise ValueError("Access token lifetime must be between 1 and 60 minutes")
        if not self.database_url:
            raise ValueError("DATABASE_URL is required")

    @classmethod
    def from_environment(cls):
        return cls(
            database_url=os.environ.get("DATABASE_URL", "sqlite:///./pramaan.db"),
            jwt_secret_key=os.environ.get("JWT_SECRET_KEY", ""),
            cors_origins=tuple(
                origin.strip() for origin in os.environ.get(
                    "CORS_ORIGINS", "http://localhost:5173"
                ).split(",") if origin.strip()
            ),
        )
