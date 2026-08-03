import ipaddress
from functools import lru_cache
from typing import Union

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
    default_role_id: int = 2
    default_access_point_role_id: int = 7
    request_timeout: float = 30.0
    zabbix_url: str | None = None
    zabbix_token: str | None = None
    zabbix_timeout: float = 30.0
    log_level: str = "INFO"
    allowed_client_cidrs: str = "127.0.0.1/32,10.0.0.0/24,10.254.0.0/24,10.0.0.115/32"

    @field_validator("netbox_url")
    @classmethod
    def normalize_netbox_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("NETBOX_URL must start with http:// or https://")
        return normalized

    @field_validator("zabbix_url")
    @classmethod
    def normalize_zabbix_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        if not normalized:
            return None
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("ZABBIX_URL must start with http:// or https://")
        return normalized

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("allowed_client_cidrs")
    @classmethod
    def normalize_allowed_client_cidrs(cls, value: str) -> str:
        networks = []
        for item in value.split(","):
            cleaned = item.strip()
            if not cleaned:
                continue
            networks.append(str(ipaddress.ip_network(cleaned, strict=False)))
        if not networks:
            raise ValueError("allowed_client_cidrs must contain at least one CIDR")
        return ",".join(networks)

    def allowed_client_networks(self) -> list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        return [ipaddress.ip_network(item.strip(), strict=False) for item in self.allowed_client_cidrs.split(",") if item.strip()]

    def zabbix_configured(self) -> bool:
        return bool(self.zabbix_url and self.zabbix_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
