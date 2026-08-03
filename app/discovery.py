from __future__ import annotations

import asyncio
import ipaddress
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
)


DISCOVERY_STATE_PATH = Path("data") / "discovery_last_scan.json"
DISCOVERY_GROUPS_PATH = Path("data") / "discovery_groups.json"


SNMP_VARIABLES = (
    ("sys_descr", ("SNMPv2-MIB", "sysDescr", 0)),
    ("sys_name", ("SNMPv2-MIB", "sysName", 0)),
    ("sys_object_id", ("SNMPv2-MIB", "sysObjectID", 0)),
    ("if_number", ("IF-MIB", "ifNumber", 0)),
    ("hr_memory_size", ("HOST-RESOURCES-MIB", "hrMemorySize", 0)),
    ("ucd_load_1", ("UCD-SNMP-MIB", "laLoad", 1)),
)


DISCOVERY_GROUPS: dict[str, dict[str, list[str]]] = {
    "switches": {
        "core": ["core", "distribution", "backbone", "core switch"],
        "access": ["access", "edge", "switch"],
        "wireless": ["ap", "access point", "wireless"],
    },
    "servers": {
        "hypervisor": ["vmware", "esxi", "hyper-v", "proxmox", "hypervisor"],
        "physical": ["server", "rack server", "blade", "hpe proliant", "dell", "lenovo"],
    },
    "hosts": {
        "mobile": ["mobile", "smartphone", "cell", "celular", "android", "ios"],
        "notebook": ["notebook", "laptop", "ultrabook"],
        "tablet": ["tablet", "ipad"],
        "desktop": ["desktop", "workstation", "pc", "windows 10", "windows 11"],
        "fixed": ["printer", "camera", "phone", "ip phone", "tv", "tv box", "terminal"],
    },
}


@dataclass(slots=True)
class DiscoveredDevice:
    ip: str
    reachable: bool
    sys_descr: str = ""
    sys_name: str = ""
    sys_object_id: str = ""
    if_number: str = ""
    hr_memory_size: str = ""
    ucd_load_1: str = ""
    group: str = "hosts"
    subgroup: str = "fixed"
    include: bool = True
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_last_scan() -> dict[str, Any]:
    return _load_json(DISCOVERY_STATE_PATH, default=_default_scan_state())


def save_last_scan(payload: dict[str, Any]) -> None:
    _save_json(DISCOVERY_STATE_PATH, payload)


def load_group_selections() -> dict[str, Any]:
    return _load_json(DISCOVERY_GROUPS_PATH, default={"devices": []})


def save_group_selections(payload: dict[str, Any]) -> None:
    _save_json(DISCOVERY_GROUPS_PATH, payload)


async def scan_network(
    network: str,
    community: str,
    *,
    timeout: float = 1.0,
    retries: int = 0,
    max_hosts: int = 128,
    concurrency: int = 32,
) -> dict[str, Any]:
    net = ipaddress.ip_network(network.strip(), strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 networks are supported for discovery")
    if not net.is_private:
        raise ValueError("Discovery is restricted to private IPv4 networks")
    if net.num_addresses > max_hosts:
        raise ValueError(f"Network too large. Limit is {max_hosts} addresses.")

    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for ip in net.hosts():
        tasks.append(asyncio.create_task(_scan_single_ip(str(ip), community, timeout=timeout, retries=retries, semaphore=semaphore)))

    devices = [device for device in await asyncio.gather(*tasks) if device is not None]
    payload = {
        "network": str(net),
        "count": len(devices),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "devices": [device.as_dict() for device in devices],
    }
    save_last_scan(payload)
    return payload


async def _scan_single_ip(
    ip: str,
    community: str,
    *,
    timeout: float,
    retries: int,
    semaphore: asyncio.Semaphore,
) -> DiscoveredDevice | None:
    async with semaphore:
        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
            var_binds = [
                ObjectType(ObjectIdentity(*oid_parts))
                for _, oid_parts in SNMP_VARIABLES
            ]
            error_indication, error_status, error_index, result = await get_cmd(
                engine,
                CommunityData(community, mpModel=1),
                transport,
                ContextData(),
                *var_binds,
            )
            if error_indication or error_status:
                return None

            values = _extract_values(result)
            sys_descr = values.get("sys_descr", "")
            sys_name = values.get("sys_name", "")
            sys_object_id = values.get("sys_object_id", "")
            if_number = values.get("if_number", "")
            hr_memory_size = values.get("hr_memory_size", "")
            ucd_load_1 = values.get("ucd_load_1", "")

            if not any((sys_descr, sys_name, sys_object_id, if_number, hr_memory_size, ucd_load_1)):
                return None

            group, subgroup, notes = classify_discovered_device(sys_descr=sys_descr, sys_name=sys_name, sys_object_id=sys_object_id)
            return DiscoveredDevice(
                ip=ip,
                reachable=True,
                sys_descr=sys_descr,
                sys_name=sys_name,
                sys_object_id=sys_object_id,
                if_number=if_number,
                hr_memory_size=hr_memory_size,
                ucd_load_1=ucd_load_1,
                group=group,
                subgroup=subgroup,
                notes=notes,
            )
        finally:
            engine.close_dispatcher()


def classify_discovered_device(*, sys_descr: str, sys_name: str, sys_object_id: str) -> tuple[str, str, str]:
    text = " ".join(part for part in (sys_descr, sys_name, sys_object_id) if part).lower()
    for group, subgroups in DISCOVERY_GROUPS.items():
        for subgroup, keywords in subgroups.items():
            if any(keyword in text for keyword in keywords):
                return group, subgroup, f"Matched {group}/{subgroup}"
    return "hosts", "fixed", "Defaulted to hosts/fixed"


def _extract_values(result: tuple[Any, ...]) -> dict[str, str]:
    extracted: dict[str, str] = {}
    for (key, _), var_bind in zip(SNMP_VARIABLES, result, strict=False):
        try:
            extracted[key] = var_bind[1].prettyPrint().strip()
        except Exception:
            extracted[key] = ""
    return extracted


def _default_scan_state() -> dict[str, Any]:
    return {
        "network": "",
        "count": 0,
        "scanned_at": "",
        "devices": [],
    }


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return data if isinstance(data, dict) else default


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

