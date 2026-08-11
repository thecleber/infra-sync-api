from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shutil
import subprocess
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
    walk_cmd,
)


DISCOVERY_STATE_PATH = Path("data") / "discovery_last_scan.json"
DISCOVERY_GROUPS_PATH = Path("data") / "discovery_groups.json"
DISCOVERY_PROGRESS_PATH = Path("data") / "discovery_scan_progress.json"
LOGGER = logging.getLogger(__name__)
_SCAN_PROGRESS_LOCK = asyncio.Lock()


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
    "printers": {
        "office": ["printer", "print server", "brother", "epson", "kyocera", "document solutions printing system", "laserjet", "deskjet"],
        "label": ["label printer", "zebra", "thermal", "etiqueta"],
    },
    "aps": {
        "indoor": ["access point", "ap", "wireless", "wifi"],
        "outdoor": ["outdoor ap", "extreme ap", "ubiquiti", "cpe"],
    },
    "cameras": {
        "ip": ["camera", "cctv", "ip cam", "ip camera", "hikvision", "dahua", "intelbras vhd"],
        "ptz": ["ptz", "speed dome", "dome camera", "bullet camera"],
    },
    "recorders": {
        "nvr": ["nvr", "network video recorder"],
        "dvr": ["dvr", "digital video recorder"],
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
    mac_address: str = ""
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


def load_scan_progress() -> dict[str, Any]:
    return _load_json(DISCOVERY_PROGRESS_PATH, default=_default_scan_progress_state())


def save_scan_progress(payload: dict[str, Any]) -> None:
    previous = load_scan_progress()
    _save_json(DISCOVERY_PROGRESS_PATH, _merge_progress_state(previous, payload))


async def scan_network(
    network: str,
    community: str,
    *,
    timeout: float = 1.0,
    retries: int = 0,
    max_hosts: int = 4096,
    concurrency: int = 32,
) -> dict[str, Any]:
    async with _SCAN_PROGRESS_LOCK:
        net = ipaddress.ip_network(network.strip(), strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 networks are supported for discovery")
        if not net.is_private:
            raise ValueError("Discovery is restricted to private IPv4 networks")

        hosts = [str(ip) for ip in net.hosts()]
        total_hosts = len(hosts)
        scan_id = datetime.now(timezone.utc).isoformat()
        progress_state = {
            **_default_scan_progress_state(),
            "scan_id": scan_id,
            "network": str(net),
            "status": "running",
            "phase": "host_discovery",
            "message": "Descobrindo hosts vivos via ARP/Nmap",
            "total_hosts": total_hosts,
            "processed_hosts": 0,
            "alive_hosts": 0,
            "found_devices": 0,
            "percentage": 0,
            "started_at": scan_id,
            "updated_at": scan_id,
        }
        save_scan_progress(progress_state)

        live_hosts = await _discover_live_hosts_with_nmap(net)
        progress_state = {
            **progress_state,
            "phase": "snmp_scan",
            "message": f"{len(live_hosts)} hosts vivos localizados por ARP/Nmap",
            "alive_hosts": len(live_hosts),
            "percentage": 15 if total_hosts else 100,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        save_scan_progress(progress_state)

        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(_scan_single_ip(ip, community, timeout=timeout, retries=retries, semaphore=semaphore))
            for ip in hosts
        ]

        snmp_devices: list[DiscoveredDevice] = []
        processed_hosts = 0
        try:
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                except Exception as exc:
                    LOGGER.debug("SNMP discovery task failed: %s", exc)
                    result = None
                processed_hosts += 1
                if result is not None:
                    snmp_devices.append(result)
                progress_state = {
                    **progress_state,
                    "status": "running",
                    "phase": "snmp_scan",
                    "message": f"{processed_hosts} de {total_hosts} hosts processados",
                    "processed_hosts": processed_hosts,
                    "alive_hosts": len(live_hosts),
                    "found_devices": len(snmp_devices),
                    "percentage": int((processed_hosts / total_hosts) * 100) if total_hosts else 100,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "last_ip": result.ip if result is not None else "",
                }
                save_scan_progress(progress_state)
        except Exception as exc:
            progress_state = {
                **progress_state,
                "status": "failed",
                "phase": "snmp_scan",
                "message": str(exc),
                "processed_hosts": processed_hosts,
                "alive_hosts": len(live_hosts),
                "found_devices": len(snmp_devices),
                "percentage": int((processed_hosts / total_hosts) * 100) if total_hosts else 100,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            save_scan_progress(progress_state)
            raise

        combined_devices = _merge_inventory(live_hosts, snmp_devices)
        payload = {
            "network": str(net),
            "count": len(combined_devices),
            "alive_hosts": len(live_hosts),
            "snmp_devices": len(snmp_devices),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "devices": [device.as_dict() for device in combined_devices],
        }
        save_last_scan(payload)
        progress_state = {
            **progress_state,
            "status": "completed",
            "phase": "complete",
            "message": "Varredura concluida",
            "processed_hosts": total_hosts,
            "alive_hosts": len(live_hosts),
            "found_devices": len(snmp_devices),
            "percentage": 100 if total_hosts else 0,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        save_scan_progress(progress_state)
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
            mac_address = await _fetch_mac_address(ip, community, timeout=timeout, retries=retries)

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
                mac_address=mac_address,
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


async def _discover_live_hosts_with_nmap(net: ipaddress.IPv4Network) -> list[dict[str, str]]:
    if shutil.which("nmap") is None:
        LOGGER.debug("nmap not available; skipping ARP/Nmap host discovery")
        return []

    command = [
        "nmap",
        "-sn",
        "-n",
        "-PR",
        "-oG",
        "-",
        str(net),
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
    except FileNotFoundError:
        return []

    if process.returncode != 0:
        LOGGER.debug("nmap host discovery failed: %s", stderr.decode("utf-8", errors="replace").strip())
        return []

    discovered = _parse_nmap_grepable_output(stdout.decode("utf-8", errors="replace"))
    arp_macs = _collect_arp_cache_macs(net)
    for host in discovered:
        ip = _normalize(host.get("ip"))
        if not ip:
            continue
        if not _normalize(host.get("mac_address")):
            host["mac_address"] = arp_macs.get(ip, "")
    return discovered


def _parse_nmap_grepable_output(output: str) -> list[dict[str, str]]:
    discovered: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("Host:") or "Status: Up" not in line:
            continue
        match = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+)\s*(?:\((.*?)\))?.*Status:\s+Up", line)
        if not match:
            continue
        ip = match.group(1)
        hostname = (match.group(2) or "").strip()
        mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:\-\.]{12,20})(?:\s+\((.*?)\))?", line)
        mac_address = _normalize_mac(mac_match.group(1)) if mac_match else ""
        mac_vendor = (mac_match.group(2) or "").strip() if mac_match else ""
        discovered.append({"ip": ip, "sys_name": hostname, "source": "nmap", "mac_address": mac_address, "mac_vendor": mac_vendor})
    return discovered


def _collect_arp_cache_macs(net: ipaddress.IPv4Network) -> dict[str, str]:
    if shutil.which("ip") is None:
        return {}
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", str(net)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return {}
    if result.returncode != 0:
        return {}
    macs: dict[str, str] = {}
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9A-Fa-f:\-\.]{12,20})", line)
        if not match:
            continue
        mac = _normalize_mac(match.group(2))
        if mac:
            macs[match.group(1)] = mac
    return macs


def _merge_inventory(live_hosts: list[dict[str, str]], snmp_devices: list[DiscoveredDevice]) -> list[DiscoveredDevice]:
    inventory: dict[str, DiscoveredDevice] = {}

    for host in live_hosts:
        ip = _normalize(host.get("ip"))
        if not ip:
            continue
        inventory[ip] = DiscoveredDevice(
            ip=ip,
            reachable=True,
            sys_name=_normalize(host.get("sys_name")),
            mac_address=_normalize_mac(_normalize(host.get("mac_address"))),
            device_type="host",
            group="hosts",
            subgroup="fixed",
            include=True,
            notes="Descoberto via ARP/Nmap",
        )

    for device in snmp_devices:
        existing = inventory.get(device.ip)
        if existing is None:
            inventory[device.ip] = device
            continue
        inventory[device.ip] = DiscoveredDevice(
            ip=device.ip,
            reachable=True,
            manufacturer=device.manufacturer or existing.manufacturer,
            model=device.model or existing.model,
            device_type=device.device_type or existing.device_type,
            mac_address=_normalize_mac(device.mac_address or existing.mac_address),
            sys_descr=device.sys_descr or existing.sys_descr,
            sys_name=device.sys_name or existing.sys_name,
            sys_object_id=device.sys_object_id or existing.sys_object_id,
            if_number=device.if_number or existing.if_number,
            hr_memory_size=device.hr_memory_size or existing.hr_memory_size,
            ucd_load_1=device.ucd_load_1 or existing.ucd_load_1,
            group=device.group or existing.group,
            subgroup=device.subgroup or existing.subgroup,
            include=device.include,
            notes=f"{existing.notes}; SNMP ok".strip("; "),
        )

    return sorted(inventory.values(), key=lambda item: ipaddress.ip_address(item.ip))


async def _fetch_mac_address(ip: str, community: str, *, timeout: float, retries: int) -> str:
    engine: SnmpEngine | None = None
    try:
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
        async for error_indication, error_status, error_index, var_binds in walk_cmd(
            engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.6")),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=32,
        ):
            if error_indication or error_status:
                return ""
            for var_bind in var_binds:
                if len(var_bind) < 2:
                    continue
                mac = _normalize_mac(var_bind[1].prettyPrint())
                if mac:
                    return mac
        return ""
    except Exception:
        return ""
    finally:
        if engine is not None:
            engine.close_dispatcher()


def infer_device_profile(*, sys_descr: str, sys_name: str, sys_object_id: str) -> dict[str, str]:
    text = " ".join(part for part in (sys_descr, sys_name, sys_object_id) if part).lower()
    enterprise = _enterprise_hint(sys_object_id)

    manufacturer = enterprise.get("manufacturer") or _guess_manufacturer(text)
    model = enterprise.get("model") or _guess_model(sys_descr, sys_name, manufacturer)
    device_type = enterprise.get("device_type") or _guess_device_type(text, manufacturer, model)

    if device_type == "printer":
        group, subgroup = "printers", "office"
    elif device_type == "camera":
        group, subgroup = "cameras", "ip"
    elif device_type == "recorder":
        recorder_subgroup = "dvr" if "dvr" in text else "nvr"
        group, subgroup = "recorders", recorder_subgroup
    elif device_type == "wireless_ap":
        group, subgroup = "aps", "indoor"
    elif device_type == "router":
        group, subgroup = "switches", "core"
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
        "1.3.6.1.4.1.39136": {"manufacturer": "Hikvision"},
        "1.3.6.1.4.1.39165": {"manufacturer": "Hikvision"},
        "1.3.6.1.4.1.50001": {"manufacturer": "Hikvision"},
        "1.3.6.1.4.1.674": {"manufacturer": "Dell", "device_type": "server_management"},
        "1.3.6.1.4.1.2435": {"manufacturer": "Brother", "device_type": "printer"},
        "1.3.6.1.4.1.1248": {"manufacturer": "Epson", "device_type": "printer"},
        "1.3.6.1.4.1.1347": {"manufacturer": "Kyocera", "device_type": "printer"},
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
    if "hikvision" in text:
        return "Hikvision"
    if "dahua" in text:
        return "Dahua"
    if "tp-link" in text or "tplink" in text or "sg" in text:
        return "TP-Link"
    if "dell" in text or "idrac" in text:
        return "Dell"
    if "brother" in text or text.startswith("brn"):
        return "Brother"
    if "epson" in text:
        return "Epson"
    if "kyocera" in text or "document solutions printing system" in text:
        return "Kyocera"
    if text.startswith("hp") or "hewlett" in text:
        return "HP"
    return "Generico"


def _looks_like_hikvision_switch(text: str, manufacturer: str, model: str = "") -> bool:
    normalized = " ".join(part for part in (text, manufacturer, model) if part).lower()
    if "hikvision" not in normalized:
        return False
    if any(
        token in normalized
        for token in (
            "switch",
            "network switch",
            "managed switch",
            "unmanaged switch",
            "poe switch",
            "industrial switch",
            "layer 2 switch",
            "layer 3 switch",
        )
    ):
        return True
    return bool(re.search(r"\bds-3[et][a-z0-9][a-z0-9\-/()]*\b", normalized, re.IGNORECASE))


def _guess_model(sys_descr: str, sys_name: str, manufacturer: str) -> str:
    combined = " ".join(part for part in (sys_descr, sys_name) if part).strip()
    patterns = [
        r"\b(DS-3[ET][A-Z0-9][A-Z0-9\-/()]*?)\b",
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
    if any(token in text for token in ("printer", "print server", "brother", "epson", "kyocera", "document solutions printing system", "hp ethernet multi-environment", "laserjet", "deskjet")):
        return "printer"
    if any(token in text for token in ("nvr", "network video recorder", "dvr", "digital video recorder", "xvr")):
        return "recorder"
    if _looks_like_hikvision_switch(text, manufacturer, model):
        return "switch"
    if any(token in text for token in ("switch", "sg", "s2", "omada", "cisco catalyst", "intelbras@switch")):
        return "switch"
    if any(token in text for token in ("camera", "cctv", "hikvision", "dahua", "intelbras vhd", "ip cam")):
        return "camera"
    if any(token in text for token in ("routeros", "gateway", "router", "ccr")):
        return "router"
    if any(token in text for token in ("idrac", "ilo", "bmc", "management controller")):
        return "server_management"
    if any(token in text for token in ("access point", "wireless", "ap", "gwn")):
        return "wireless_ap"
    if any(token in text for token in ("server", "hypervisor", "proliant", "r720", "r730", "poweredge", "lenovo", "hpe")):
        return "server"
    return "host"


def _normalize(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _normalize_mac(value: Any) -> str:
    cleaned = _normalize(value)
    if not cleaned:
        return ""
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        cleaned = cleaned[2:]
        lowered = cleaned.lower()
    if lowered in {"00:00:00:00:00:00", "000000000000", "ff:ff:ff:ff:ff:ff"}:
        return ""
    hex_only = "".join(ch for ch in cleaned if ch.isalnum())
    if len(hex_only) == 12:
        return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).upper()
    return cleaned.upper()


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


def _default_scan_progress_state() -> dict[str, Any]:
    return {
        "scan_id": "",
        "network": "",
        "status": "idle",
        "phase": "idle",
        "message": "",
        "total_hosts": 0,
        "processed_hosts": 0,
        "alive_hosts": 0,
        "found_devices": 0,
        "percentage": 0,
        "started_at": "",
        "updated_at": "",
        "finished_at": "",
        "last_ip": "",
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


def _merge_progress_state(previous: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    merged = {**_default_scan_progress_state(), **previous, **payload}
    if previous.get("scan_id") and previous.get("scan_id") == payload.get("scan_id"):
        for key in ("processed_hosts", "alive_hosts", "found_devices", "percentage"):
            merged[key] = max(int(previous.get(key) or 0), int(merged.get(key) or 0))
        merged["total_hosts"] = max(int(previous.get("total_hosts") or 0), int(merged.get("total_hosts") or 0))
    return merged
