from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from .utils import normalize_auth_header


_ROLE_KEYWORDS = {
    7: ("access point", "wireless", "ap-", "-ap", "_ap", "ap "),
}


@dataclass(slots=True)
class ZabbixHostSnapshot:
    hostid: str
    host: str
    name: str
    status: int
    description: str
    inventory: dict[str, Any]
    interfaces: list[dict[str, Any]]
    items: list[dict[str, Any]]

    @property
    def visible_name(self) -> str:
        return (self.name or self.host or self.hostid).strip()

    @property
    def technical_name(self) -> str:
        return (self.host or self.name or self.hostid).strip()

    @property
    def enabled(self) -> bool:
        return self.status == 0

    @property
    def netbox_status(self) -> str:
        return "active" if self.enabled else "planned"

    def primary_ip(self) -> str | None:
        for interface in self._sorted_interfaces():
            ip = str(interface.get("ip", "")).strip()
            useip = str(interface.get("useip", "")).strip()
            if useip == "1" and ip:
                return ip
        for interface in self._sorted_interfaces():
            ip = str(interface.get("ip", "")).strip()
            if ip:
                return ip
        return None

    def infer_manufacturer(self) -> str | None:
        for key in ("vendor", "hardware", "type", "os_short"):
            value = _clean_text(self.inventory.get(key))
            if value:
                return value
        sys_descr = self._item_lastvalue("sysDescr")
        if sys_descr:
            return sys_descr.split()[0].strip(",;") or None
        return None

    def infer_model(self) -> str | None:
        for key in ("model", "hardware", "type_full", "hardware_full", "os_full"):
            value = _clean_text(self.inventory.get(key))
            if value:
                return value
        sys_descr = self._item_lastvalue("sysDescr")
        if sys_descr:
            return _truncate(sys_descr, 128)
        return None

    def infer_serial(self) -> str | None:
        for key in ("serialno_a", "serialno_b"):
            value = _clean_text(self.inventory.get(key))
            if value:
                return value
        return None

    def infer_role_id(self, default_role_id: int, access_point_role_id: int = 7) -> int:
        haystack_parts = [
            self.visible_name,
            self.technical_name,
            _clean_text(self.inventory.get("vendor")) or "",
            _clean_text(self.inventory.get("hardware")) or "",
            _clean_text(self.inventory.get("type")) or "",
            _clean_text(self.inventory.get("os_short")) or "",
        ]
        haystack = " ".join(part for part in haystack_parts if part).lower()
        for role_id, keywords in _ROLE_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                return role_id
        return default_role_id if default_role_id > 0 else access_point_role_id

    def inventory_summary(self) -> str:
        summary_bits: list[str] = []
        for label, keys in (
            ("vendor", ("vendor",)),
            ("model", ("model", "hardware", "type_full")),
            ("serial", ("serialno_a", "serialno_b")),
            ("os", ("os_full", "os", "software_full")),
            ("hardware", ("hardware_full",)),
            ("location", ("location",)),
        ):
            value = self._first_inventory_value(*keys)
            if value:
                summary_bits.append(f"{label}={value}")

        cpu = self._first_item_value("system.cpu.num", "hrProcessorLoad")
        memory = self._first_item_value("vm.memory.size[total]", "hrMemorySize")
        storage = self._first_item_value("vfs.fs.size[", "hrStorage")
        interface_count = len([item for item in self.interfaces if _clean_text(item.get("ip")) or _clean_text(item.get("dns"))])

        if cpu:
            summary_bits.append(f"cpu={cpu}")
        if memory:
            summary_bits.append(f"memory={memory}")
        if storage:
            summary_bits.append(f"storage={storage}")
        if interface_count:
            summary_bits.append(f"interfaces={interface_count}")

        primary_ip = self.primary_ip()
        if primary_ip:
            summary_bits.append(f"primary_ip={primary_ip}")

        if not summary_bits:
            return "No Zabbix inventory details available."
        return "; ".join(summary_bits)

    def comments_summary(self) -> str:
        interface_bits = []
        for interface in self._sorted_interfaces():
            label = _interface_label(interface)
            if label:
                interface_bits.append(label)
        details = [
            f"zabbix_hostid={self.hostid}",
            f"host={self.technical_name}",
            f"visible_name={self.visible_name}",
            f"status={'enabled' if self.enabled else 'disabled'}",
        ]
        if self.description:
            details.append(f"description={_truncate(self.description, 240)}")
        details.append(self.inventory_summary())
        if interface_bits:
            details.append("interfaces=" + " | ".join(interface_bits))
        return " | ".join(part for part in details if part)

    def _sorted_interfaces(self) -> list[dict[str, Any]]:
        return sorted(
            self.interfaces,
            key=lambda item: (
                int(_safe_int(item.get("main")) is not None and _safe_int(item.get("main")) != 0) * -1,
                int(_safe_int(item.get("useip")) is not None and _safe_int(item.get("useip")) != 0) * -1,
                _clean_text(item.get("interfaceid")) or "",
            ),
        )

    def _item_lastvalue(self, *needles: str) -> str | None:
        needle_set = tuple(needle.lower() for needle in needles)
        for item in self.items:
            key = _clean_text(item.get("key_")) or ""
            name = _clean_text(item.get("name")) or ""
            haystack = f"{key} {name}".lower()
            if any(needle in haystack for needle in needle_set):
                value = _clean_text(item.get("lastvalue"))
                if value:
                    return value
        return None

    def _first_item_value(self, *needles: str) -> str | None:
        needle_set = tuple(needle.lower() for needle in needles)
        for item in self.items:
            key = _clean_text(item.get("key_")) or ""
            name = _clean_text(item.get("name")) or ""
            haystack = f"{key} {name}".lower()
            if any(needle in haystack for needle in needle_set):
                value = _clean_text(item.get("lastvalue"))
                if value:
                    return _truncate(value, 160)
        return None

    def _first_inventory_value(self, *keys: str) -> str | None:
        for key in keys:
            value = _clean_text(self.inventory.get(key))
            if value:
                return _truncate(value, 160)
        return None


class ZabbixClientError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, payload: Any | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class ZabbixClient:
    def __init__(self, base_url: str, token: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            headers={
                "Authorization": normalize_auth_header(token),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def healthcheck(self) -> bool:
        try:
            await self._rpc("host.get", {"output": ["hostid"], "limit": 1})
            return True
        except ZabbixClientError:
            return False

    async def count_hosts(self) -> int:
        result = await self._rpc(
            "host.get",
            {
                "output": ["hostid"],
                "countOutput": True,
                "monitored_hosts": True,
            },
        )
        if isinstance(result, int):
            return result
        if isinstance(result, str):
            try:
                return int(result)
            except ValueError:
                return 0
        if isinstance(result, list):
            return len(result)
        return 0

    async def list_problems(self, limit: int = 50) -> list[dict[str, Any]]:
        result = await self._rpc(
            "problem.get",
            {
                "output": "extend",
                "selectHosts": ["hostid", "host", "name"],
                "selectTags": "extend",
                "selectAcknowledges": "extend",
                "sortfield": ["clock", "eventid"],
                "sortorder": "DESC",
                "limit": limit,
            },
        )
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        return []

    async def count_problems(self) -> int:
        result = await self._rpc(
            "problem.get",
            {
                "output": ["eventid"],
                "countOutput": True,
            },
        )
        if isinstance(result, int):
            return result
        if isinstance(result, str):
            try:
                return int(result)
            except ValueError:
                return 0
        if isinstance(result, list):
            return len(result)
        return 0

    async def get_host_snapshot(self, hostid: str) -> ZabbixHostSnapshot:
        result = await self._rpc(
            "host.get",
            {
                "hostids": hostid,
                "output": "extend",
                "selectInterfaces": "extend",
                "selectInventory": "extend",
                "selectItems": "extend",
            },
        )
        if not isinstance(result, list) or len(result) != 1:
            raise ZabbixClientError(f"Expected one Zabbix host for hostid {hostid}", status_code=404, payload=result)
        host = result[0]
        if not isinstance(host, dict):
            raise ZabbixClientError("Zabbix host response was not an object", payload=host)
        return ZabbixHostSnapshot(
            hostid=_clean_text(host.get("hostid")) or str(hostid),
            host=_clean_text(host.get("host")) or "",
            name=_clean_text(host.get("name")) or "",
            status=_safe_int(host.get("status")) or 0,
            description=_clean_text(host.get("description")) or "",
            inventory=host.get("inventory") if isinstance(host.get("inventory"), dict) else {},
            interfaces=host.get("interfaces") if isinstance(host.get("interfaces"), list) else [],
            items=host.get("items") if isinstance(host.get("items"), list) else [],
        )

    async def _rpc(self, method: str, params: Any) -> Any:
        response = await self._client.post("", json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
        if response.status_code >= 400:
            raise ZabbixClientError(f"Zabbix request failed with status {response.status_code}", status_code=response.status_code, payload=response.text)
        payload = response.json()
        if isinstance(payload, dict) and "error" in payload:
            error = payload["error"]
            message = "Zabbix request failed"
            code = None
            if isinstance(error, dict):
                message = f"{message}: {error.get('message') or error.get('data') or error}"
                code = error.get("code")
            raise ZabbixClientError(message, status_code=code, payload=payload)
        if isinstance(payload, dict) and "result" in payload:
            return payload["result"]
        raise ZabbixClientError("Zabbix response was not valid JSON-RPC", payload=payload)


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _interface_label(interface: dict[str, Any]) -> str | None:
    ip = _clean_text(interface.get("ip"))
    dns = _clean_text(interface.get("dns"))
    port = _clean_text(interface.get("port"))
    interface_type = _safe_int(interface.get("type"))
    main = _safe_int(interface.get("main"))
    type_label = {1: "agent", 2: "snmp", 3: "ipmi", 4: "jmx"}.get(interface_type, "iface")
    endpoint = ip or dns
    if not endpoint:
        return None
    bits = [type_label, endpoint]
    if port:
        bits.append(f"port={port}")
    if main == 1:
        bits.append("main")
    return " ".join(bits)
