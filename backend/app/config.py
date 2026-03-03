"""Application configuration."""

import warnings
from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    """Application settings."""

    database_url: str = "postgresql+asyncpg://defender:CHANGE_ME@localhost:5432/defender_explorer"
    vdm_path: str = "/data/vdm"
    admin_imports_enabled: bool = True

    # Pagination defaults
    default_page_size: int = 50
    max_page_size: int = 500

    # API settings
    api_prefix: str = "/api"

    # API key for admin write operations (set via ADMIN_API_KEY env var)
    admin_api_key: str = ""

    # CORS settings - comma-separated list of allowed origins
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @field_validator('admin_api_key')
    @classmethod
    def check_api_key(cls, v: str) -> str:
        if not v:
            warnings.warn(
                "ADMIN_API_KEY not set - admin write endpoints will return 503",
                UserWarning,
            )
        return v

    @field_validator('database_url')
    @classmethod
    def check_not_default_db(cls, v: str) -> str:
        if 'CHANGE_ME' in v:
            warnings.warn(
                "Using default database password - not suitable for production",
                UserWarning
            )
        return v

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
