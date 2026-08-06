from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any


_slug_re = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_value.lower().strip()
    slug = _slug_re.sub("-", lowered).strip("-")
    return slug or "unnamed"


def is_ipv4_only_hostname(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).version == 4
    except ValueError:
        return False


def normalize_ip_input(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("IP is required")

    candidate = cleaned if "/" in cleaned else f"{cleaned}/32"
    interface = ipaddress.ip_interface(candidate)
    if interface.version != 4:
        raise ValueError("Only IPv4 addresses are supported")
    return str(interface)


def merge_custom_fields(existing: dict[str, Any] | None, hostid: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    merged = dict(existing or {})
    merged["zabbix_hostid"] = hostid
    if extra:
        for key, value in extra.items():
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            merged[key] = value
    return merged


def truthy_string(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_auth_header(token: str) -> str:
    cleaned = token.strip()
    if cleaned.lower().startswith(("bearer ", "token ")):
        return cleaned
    return f"Token {cleaned}"
