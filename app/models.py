from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from .utils import is_ipv4_only_hostname, normalize_ip_input


class SyncDeviceRequest(BaseModel):
    hostid: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)
    display_name: str | None = None
    ip: str = Field(..., min_length=1)
    fabricante: str = Field(..., min_length=1)
    modelo: str = Field(..., min_length=1)
    site_id: int = Field(..., gt=0)
    role_id: int = Field(..., gt=0)
    zabbix_status: str | None = None

    @field_validator("hostid", "hostname", "ip", "fabricante", "modelo")
    @classmethod
    def strip_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Field cannot be empty")
        return cleaned

    @field_validator("display_name")
    @classmethod
    def strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return normalize_ip_input(value)

    def normalized_device_name(self) -> str:
        return self.display_name or self.hostname

    def is_blocked_for_auto_create(self) -> bool:
        lowered = self.hostname.lower()
        return (
            self.hostname.startswith("DISC_")
            or lowered.startswith("discovered")
            or is_ipv4_only_hostname(self.hostname)
        )

