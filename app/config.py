from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    netbox_url: str = Field(..., min_length=1)
    netbox_token: str = Field(..., min_length=1)
    sync_api_key: str = Field(..., min_length=1)
    default_site_id: int = 1
    request_timeout: float = 30.0
    log_level: str = "INFO"

    @field_validator("netbox_url")
    @classmethod
    def normalize_netbox_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("NETBOX_URL must start with http:// or https://")
        return normalized

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.strip().upper()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

