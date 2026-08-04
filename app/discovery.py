from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import re

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
LOGGER = logging.getLogger(__name__)


SNMP_VARIABLES = (
    ("sys_descr", ("1.3.6.1.2.1.1.1.0",)),
    ("sys_name", ("1.3.6.1.2.1.1.5.0",)),
    ("sys_object_id", ("1.3.6.1.2.1.1.2.0",)),
    ("if_number", ("1.3.6.1.2.1.2.1.0",)),
    ("hr_memory_size", ("1.3.6.1.2.1.25.2.2.0",)),
    ("ucd_load_1", ("1.3.6.1.4.1.2021.10.1.3.1",)),
)


DISCOVERY_GROUPS: dict[str, dict[str, list[str]]] = {
    "routers": {
        "core": ["routeros", "ccr", "router", "gateway", "edge router", "wan"],
        "distribution": ["distribution", "backbone"],
    },
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
    manufacturer: str = ""
    model: str = ""
    device_type: str = ""
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
    max_hosts: int = 4096,
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

    results = await asyncio.gather(*tasks, return_exceptions=True)
    devices = []
    for result in results:
        if isinstance(result, Exception):
            LOGGER.debug("SNMP discovery task failed: %s", result)
            continue
        if result is not None:
            devices.append(result)
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
        engine: SnmpEngine | None = None
        try:
            engine = SnmpEngine()
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

            profile = infer_device_profile(sys_descr=sys_descr, sys_name=sys_name, sys_object_id=sys_object_id)
            group, subgroup, notes = classify_discovered_device(
                sys_descr=sys_descr,
                sys_name=sys_name,
                sys_object_id=sys_object_id,
                manufacturer=profile["manufacturer"],
                model=profile["model"],
                device_type=profile["device_type"],
            )
            return DiscoveredDevice(
                ip=ip,
                reachable=True,
                manufacturer=profile["manufacturer"],
                model=profile["model"],
                device_type=profile["device_type"],
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
        except Exception as exc:
            LOGGER.debug("SNMP discovery failed for %s: %s", ip, exc)
            return None
        finally:
            if engine is not None:
                engine.close_dispatcher()


def infer_device_profile(*, sys_descr: str, sys_name: str, sys_object_id: str) -> dict[str, str]:
    text = " ".join(part for part in (sys_descr, sys_name, sys_object_id) if part).lower()
    enterprise = _enterprise_hint(sys_object_id)

    manufacturer = enterprise.get("manufacturer") or _guess_manufacturer(text)
    model = enterprise.get("model") or _guess_model(sys_descr, sys_name, manufacturer)
    device_type = enterprise.get("device_type") or _guess_device_type(text, manufacturer, model)

    if "printer" in device_type:
        group, subgroup = "hosts", "fixed"
    elif device_type == "router":
        group, subgroup = "switches", "core"
    elif device_type == "wireless_ap":
        group, subgroup = "switches", "wireless"
    elif device_type == "server_management":
        group, subgroup = "servers", "physical"
    elif device_type == "server":
        group, subgroup = "servers", "physical"
    elif device_type == "switch":
        group = "switches"
        subgroup = "core" if any(token in text for token in ("core", "backbone", "ccr", "distribution")) else "access"
    elif device_type == "host":
        group, subgroup = "hosts", "fixed"
    else:
        group, subgroup = "hosts", "fixed"

    notes = f"Matched {group}/{subgroup} via {manufacturer or 'unknown'} {model or 'unknown'} {device_type or 'unknown'}"
    return {
        "manufacturer": manufacturer,
        "model": model,
        "device_type": device_type,
        "group": group,
        "subgroup": subgroup,
        "notes": notes,
    }


def classify_discovered_device(
    *,
    sys_descr: str,
    sys_name: str,
    sys_object_id: str,
    manufacturer: str = "",
    model: str = "",
    device_type: str = "",
) -> tuple[str, str, str]:
    if not (manufacturer and model and device_type):
        profile = infer_device_profile(sys_descr=sys_descr, sys_name=sys_name, sys_object_id=sys_object_id)
        manufacturer = manufacturer or profile["manufacturer"]
        model = model or profile["model"]
        device_type = device_type or profile["device_type"]
        group = profile["group"]
        subgroup = profile["subgroup"]
        notes = profile["notes"]
        return group, subgroup, notes

    profile_text = " ".join(part for part in (manufacturer, model, device_type, sys_descr, sys_name, sys_object_id) if part).lower()
    for group, subgroups in DISCOVERY_GROUPS.items():
        for subgroup, keywords in subgroups.items():
            if any(keyword in profile_text for keyword in keywords):
                return group, subgroup, f"Matched {group}/{subgroup} via {manufacturer or 'unknown'} {model or 'unknown'} {device_type or 'unknown'}"
    return "hosts", "fixed", f"Defaulted to hosts/fixed via {manufacturer or 'unknown'} {model or 'unknown'} {device_type or 'unknown'}"


def _enterprise_hint(sys_object_id: str) -> dict[str, str]:
    text = _normalize(sys_object_id)
    match = re.search(r"(\d+(?:\.\d+)*)", text)
    if not match:
        return {}
    oid = match.group(1)
    hints = {
        "1.3.6.1.4.1.14988": {"manufacturer": "MikroTik", "device_type": "router", "model": "CCR"},
        "1.3.6.1.4.1.26138": {"manufacturer": "Intelbras", "device_type": "switch"},
        "1.3.6.1.4.1.42397": {"manufacturer": "Grandstream", "device_type": "wireless_ap"},
        "1.3.6.1.4.1.11863": {"manufacturer": "TP-Link", "device_type": "switch"},
        "1.3.6.1.4.1.674": {"manufacturer": "Dell", "device_type": "server_management"},
        "1.3.6.1.4.1.2435": {"manufacturer": "Brother", "device_type": "printer"},
        "1.3.6.1.4.1.1248": {"manufacturer": "Epson", "device_type": "printer"},
        "1.3.6.1.4.1.11": {"manufacturer": "HP", "device_type": "printer"},
        "1.3.6.1.4.1.8072": {"manufacturer": "Linux/Net-SNMP", "device_type": "host"},
    }
    for prefix, profile in hints.items():
        if oid.startswith(prefix):
            return profile
    return {}


def _guess_manufacturer(text: str) -> str:
    if any(token in text for token in ("mikrotik", "routeros", "ccr")):
        return "MikroTik"
    if "intelbras" in text:
        return "Intelbras"
    if "grandstream" in text or "gwn" in text:
        return "Grandstream"
    if "tp-link" in text or "tplink" in text or "sg" in text:
        return "TP-Link"
    if "dell" in text or "idrac" in text:
        return "Dell"
    if "brother" in text or text.startswith("brn"):
        return "Brother"
    if "epson" in text:
        return "Epson"
    if text.startswith("hp") or "hewlett" in text:
        return "HP"
    return "Generico"


def _guess_model(sys_descr: str, sys_name: str, manufacturer: str) -> str:
    combined = " ".join(part for part in (sys_descr, sys_name) if part).strip()
    patterns = [
        r"(CCR\d+[A-Z0-9+\-]*)",
        r"(SG\d+[A-Z0-9+\-]*)",
        r"(S\d{4}[A-Z0-9+\-]*)",
        r"(GWN\d+[A-Z0-9+\-]*)",
        r"(iDRAC[-A-Z0-9]*)",
        r"(BRN\d+[A-Z0-9]*)",
        r"(EPSON\d+[A-Z0-9]*)",
    ]
    for pattern in patterns:
        match = re.search(pattern, combined, re.IGNORECASE)
        if match:
            return match.group(1)
    if manufacturer and manufacturer.lower() in combined.lower():
        return combined
    return sys_name or sys_descr or ""


def _guess_device_type(text: str, manufacturer: str, model: str) -> str:
    if any(token in text for token in ("printer", "print server", "brother", "epson", "hp ethernet multi-environment")):
        return "printer"
    if any(token in text for token in ("routeros", "gateway", "router", "ccr")):
        return "router"
    if any(token in text for token in ("idrac", "ilo", "bmc", "management controller")):
        return "server_management"
    if any(token in text for token in ("access point", "wireless", "ap", "gwn")):
        return "wireless_ap"
    if any(token in text for token in ("switch", "sg", "s2", "omada", "cisco catalyst", "intelbras@switch")):
        return "switch"
    if any(token in text for token in ("server", "hypervisor", "proliant", "r720", "r730", "poweredge", "lenovo", "hpe")):
        return "server"
    return "host"


def _normalize(value: Any) -> str:
    return "" if value is None else str(value).strip()


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
