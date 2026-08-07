from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass, asdict, field
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
    walk_cmd,
)


SNMP_PROBE_STATE_PATH = Path("data") / "snmp_last_probe.json"


SCALAR_VARIABLES = (
    ("sys_descr", ("1.3.6.1.2.1.1.1.0",)),
    ("sys_name", ("1.3.6.1.2.1.1.5.0",)),
    ("sys_object_id", ("1.3.6.1.2.1.1.2.0",)),
    ("if_number", ("1.3.6.1.2.1.2.1.0",)),
    ("hr_memory_size", ("1.3.6.1.2.1.25.2.2.0",)),
)


WALK_COLUMNS = {
    "if_name": ("1.3.6.1.2.1.31.1.1.1.1",),
    "if_descr": ("1.3.6.1.2.1.2.2.1.2",),
    "if_alias": ("1.3.6.1.2.1.31.1.1.1.18",),
    "if_phys_address": ("1.3.6.1.2.1.2.2.1.6",),
    "if_admin_status": ("1.3.6.1.2.1.2.2.1.7",),
    "if_oper_status": ("1.3.6.1.2.1.2.2.1.8",),
    "if_speed": ("1.3.6.1.2.1.2.2.1.5",),
    "if_in_octets": ("1.3.6.1.2.1.2.2.1.10",),
    "if_out_octets": ("1.3.6.1.2.1.2.2.1.16",),
    "if_hc_in_octets": ("1.3.6.1.2.1.31.1.1.1.6",),
    "if_hc_out_octets": ("1.3.6.1.2.1.31.1.1.1.10",),
    "hr_processor_load": ("1.3.6.1.2.1.25.3.3.1.2",),
}

LLDP_REMOTE_COLUMNS = {
    "remote_chassis_id_subtype": "1.0.8802.1.1.2.1.4.1.1.4",
    "remote_chassis_id": "1.0.8802.1.1.2.1.4.1.1.5",
    "remote_port_id_subtype": "1.0.8802.1.1.2.1.4.1.1.6",
    "remote_port_id": "1.0.8802.1.1.2.1.4.1.1.7",
    "remote_port_desc": "1.0.8802.1.1.2.1.4.1.1.8",
    "remote_sys_name": "1.0.8802.1.1.2.1.4.1.1.9",
}

BRIDGE_PORT_INDEX_OID = "1.3.6.1.2.1.17.1.4.1.2"
BRIDGE_FDB_PORT_OID = "1.3.6.1.2.1.17.4.3.1.2"
BRIDGE_FDB_STATUS_OID = "1.3.6.1.2.1.17.4.3.1.3"


STATUS_MAP = {
    "1": "up",
    "2": "down",
    "3": "testing",
    "4": "unknown",
    "5": "dormant",
    "6": "notPresent",
    "7": "lowerLayerDown",
}


@dataclass(slots=True)
class SnmpPortSnapshot:
    index: str
    name: str = ""
    description: str = ""
    alias: str = ""
    mac_address: str = ""
    admin_status: str = ""
    oper_status: str = ""
    speed_bps: str = ""
    in_octets: str = ""
    out_octets: str = ""
    in_rate_bps: str = ""
    out_rate_bps: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SnmpDeviceSnapshot:
    ip: str
    reachable: bool
    sys_descr: str = ""
    sys_name: str = ""
    sys_object_id: str = ""
    if_number: str = ""
    hr_memory_size: str = ""
    processor_load_average: str = ""
    processor_loads: list[str] = field(default_factory=list)
    ports: list[SnmpPortSnapshot] = field(default_factory=list)
    lldp_neighbors: list[dict[str, Any]] = field(default_factory=list)
    bridge_port_map: list[dict[str, Any]] = field(default_factory=list)
    bridge_fdb: list[dict[str, Any]] = field(default_factory=list)
    collected_at: str = ""
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["ports"] = [port.as_dict() for port in self.ports]
        return payload


class SnmpProbeError(RuntimeError):
    pass


def load_last_probe() -> dict[str, Any]:
    return _load_json(SNMP_PROBE_STATE_PATH, default=_default_probe_state())


def save_last_probe(payload: dict[str, Any]) -> None:
    _save_json(SNMP_PROBE_STATE_PATH, payload)


async def probe_device(
    ip: str,
    community: str,
    *,
    timeout: float = 1.0,
    retries: int = 0,
    max_ports: int = 48,
) -> dict[str, Any]:
    address = _normalize_private_ipv4(ip)
    scalar_values = await _fetch_scalar_values(address, community, timeout=timeout, retries=retries)
    ports = await _fetch_ports(address, community, timeout=timeout, retries=retries, max_ports=max_ports)
    lldp_neighbors = await _fetch_lldp_neighbors(address, community, timeout=timeout, retries=retries, max_rows=max_ports)
    bridge_port_map = await _fetch_bridge_port_map(address, community, timeout=timeout, retries=retries, max_rows=max_ports)
    bridge_fdb = await _fetch_bridge_fdb(address, community, timeout=timeout, retries=retries, max_rows=max_ports)
    processor_loads = await _fetch_column(address, community, WALK_COLUMNS["hr_processor_load"], timeout=timeout, retries=retries, max_rows=max_ports)
    processor_values = [value for _, value in processor_loads if value.isdigit()]
    cpu_average = ""
    if processor_values:
        cpu_average = f"{round(sum(int(item) for item in processor_values) / len(processor_values), 2)}"

    snapshot = SnmpDeviceSnapshot(
        ip=address,
        reachable=True,
        sys_descr=scalar_values.get("sys_descr", ""),
        sys_name=scalar_values.get("sys_name", ""),
        sys_object_id=scalar_values.get("sys_object_id", ""),
        if_number=scalar_values.get("if_number", ""),
        hr_memory_size=scalar_values.get("hr_memory_size", ""),
        processor_load_average=cpu_average,
        processor_loads=processor_values,
        ports=ports,
        lldp_neighbors=lldp_neighbors,
        bridge_port_map=bridge_port_map,
        bridge_fdb=bridge_fdb,
        collected_at=datetime.now(timezone.utc).isoformat(),
        notes=_build_notes(scalar_values, ports, processor_values, lldp_neighbors, bridge_fdb),
    )
    payload = snapshot.as_dict()
    _persist_probe_snapshot(payload)
    return payload


async def _fetch_scalar_values(ip: str, community: str, *, timeout: float, retries: int) -> dict[str, str]:
    engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
        var_binds = [ObjectType(ObjectIdentity(*oid_parts)) for _, oid_parts in SCALAR_VARIABLES]
        error_indication, error_status, error_index, result = await get_cmd(
            engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            *var_binds,
        )
        if error_indication:
            raise SnmpProbeError(str(error_indication))
        if error_status:
            raise SnmpProbeError(str(error_status))
        extracted: dict[str, str] = {}
        for (key, _), var_bind in zip(SCALAR_VARIABLES, result, strict=False):
            extracted[key] = _clean_value(var_bind)
        return extracted
    finally:
        engine.close_dispatcher()


async def _fetch_ports(
    ip: str,
    community: str,
    *,
    timeout: float,
    retries: int,
    max_ports: int,
) -> list[SnmpPortSnapshot]:
    columns = {}
    for key in ("if_name", "if_descr", "if_alias", "if_phys_address", "if_admin_status", "if_oper_status", "if_speed", "if_in_octets", "if_out_octets", "if_hc_in_octets", "if_hc_out_octets"):
        try:
            columns[key] = await _fetch_column(ip, community, WALK_COLUMNS[key], timeout=timeout, retries=retries, max_rows=max_ports)
        except Exception:
            columns[key] = []

    port_indexes = sorted(
        {
            index
            for column_rows in columns.values()
            for index, _ in column_rows
            if index
        },
        key=_index_sort_key,
    )

    previous = _load_previous_ports(ip)
    current_ts = datetime.now(timezone.utc)
    ports: list[SnmpPortSnapshot] = []
    for index in port_indexes[:max_ports]:
        port = SnmpPortSnapshot(
            index=index,
            name=_lookup_column(columns["if_name"], index),
            description=_lookup_column(columns["if_descr"], index),
            alias=_lookup_column(columns["if_alias"], index),
            mac_address=_normalize_mac(_lookup_column(columns["if_phys_address"], index)),
            admin_status=_human_status(_lookup_column(columns["if_admin_status"], index)),
            oper_status=_human_status(_lookup_column(columns["if_oper_status"], index)),
            speed_bps=_human_bandwidth(_lookup_column(columns["if_speed"], index)),
            in_octets=_first_non_empty(
                _lookup_column(columns["if_hc_in_octets"], index),
                _lookup_column(columns["if_in_octets"], index),
            ),
            out_octets=_first_non_empty(
                _lookup_column(columns["if_hc_out_octets"], index),
                _lookup_column(columns["if_out_octets"], index),
            ),
        )
        prev_port = previous.get(index)
        if prev_port:
            port.in_rate_bps = _calc_rate(prev_port.get("in_octets"), port.in_octets, prev_port.get("collected_at"), current_ts)
            port.out_rate_bps = _calc_rate(prev_port.get("out_octets"), port.out_octets, prev_port.get("collected_at"), current_ts)
        ports.append(port)

    return ports


def _lldp_index_key(oid: str) -> tuple[str, str] | None:
    parts = oid.split(".")
    if len(parts) < 3:
        return None
    return parts[-2], parts[-1]


async def _fetch_lldp_neighbors(
    ip: str,
    community: str,
    *,
    timeout: float,
    retries: int,
    max_rows: int,
) -> list[dict[str, Any]]:
    columns: dict[str, list[tuple[tuple[str, str], str]]] = {}
    for key, oid in LLDP_REMOTE_COLUMNS.items():
        try:
            columns[key] = await _fetch_indexed_column(ip, community, oid, timeout=timeout, retries=retries, max_rows=max_rows, index_parser=_lldp_index_key)
        except Exception:
            columns[key] = []

    neighbors: dict[tuple[str, str], dict[str, str]] = {}
    for key, rows in columns.items():
        for index, value in rows:
            if not index:
                continue
            neighbors.setdefault(index, {})[key] = value

    payload: list[dict[str, Any]] = []
    for (local_port_index, remote_index), data in neighbors.items():
        remote_sys_name = _clean_text(data.get("remote_sys_name"))
        remote_port_id = _clean_text(data.get("remote_port_id"))
        remote_port_desc = _clean_text(data.get("remote_port_desc"))
        remote_chassis_id = _normalize_mac(_clean_text(data.get("remote_chassis_id")))
        remote_chassis_id_subtype = _clean_text(data.get("remote_chassis_id_subtype"))
        remote_port_id_subtype = _clean_text(data.get("remote_port_id_subtype"))
        if not any((remote_sys_name, remote_port_id, remote_port_desc, remote_chassis_id)):
            continue
        payload.append(
            {
                "local_port_index": local_port_index,
                "remote_index": remote_index,
                "remote_sys_name": remote_sys_name,
                "remote_port_id": remote_port_id,
                "remote_port_desc": remote_port_desc,
                "remote_chassis_id": remote_chassis_id,
                "remote_chassis_id_subtype": remote_chassis_id_subtype,
                "remote_port_id_subtype": remote_port_id_subtype,
            }
        )
    return payload


def _bridge_port_index(oid: str) -> str | None:
    parts = oid.split(".")
    if not parts:
        return None
    return parts[-1]


def _bridge_fdb_mac_index(oid: str) -> str | None:
    parts = oid.split(".")
    if len(parts) < 6:
        return None
    tail = parts[-6:]
    if not all(part.isdigit() for part in tail):
        return None
    return ":".join(f"{int(part):02X}" for part in tail)


async def _fetch_bridge_port_map(
    ip: str,
    community: str,
    *,
    timeout: float,
    retries: int,
    max_rows: int,
) -> list[dict[str, Any]]:
    try:
        rows = await _fetch_indexed_column(ip, community, BRIDGE_PORT_INDEX_OID, timeout=timeout, retries=retries, max_rows=max_rows, index_parser=_bridge_port_index)
    except Exception:
        rows = []
    payload: list[dict[str, Any]] = []
    for bridge_port, if_index in rows:
        payload.append({"bridge_port": bridge_port, "if_index": if_index})
    return payload


async def _fetch_bridge_fdb(
    ip: str,
    community: str,
    *,
    timeout: float,
    retries: int,
    max_rows: int,
) -> list[dict[str, Any]]:
    columns: dict[str, list[tuple[str, str]]] = {}
    for key, oid in {
        "bridge_port": BRIDGE_FDB_PORT_OID,
        "status": BRIDGE_FDB_STATUS_OID,
    }.items():
        try:
            columns[key] = await _fetch_indexed_column(ip, community, oid, timeout=timeout, retries=retries, max_rows=max_rows, index_parser=_bridge_fdb_mac_index)
        except Exception:
            columns[key] = []

    rows: dict[str, dict[str, str]] = {}
    for key, values in columns.items():
        for mac_address, value in values:
            if not mac_address:
                continue
            rows.setdefault(mac_address, {})[key] = value

    payload: list[dict[str, Any]] = []
    for mac_address, data in rows.items():
        bridge_port = _clean_text(data.get("bridge_port"))
        if not bridge_port:
            continue
        payload.append(
            {
                "mac_address": mac_address,
                "bridge_port": bridge_port,
                "status": _clean_text(data.get("status")),
            }
        )
    return payload


async def _fetch_indexed_column(
    ip: str,
    community: str,
    oid: str,
    *,
    timeout: float,
    retries: int,
    max_rows: int,
    index_parser,
) -> list[tuple[Any, str]]:
    engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
        results: list[tuple[Any, str]] = []
        async for error_indication, error_status, error_index, var_binds in walk_cmd(
            engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=max_rows,
        ):
            if error_indication:
                raise SnmpProbeError(str(error_indication))
            if error_status:
                raise SnmpProbeError(str(error_status))
            for var_bind in var_binds:
                if len(var_bind) < 2:
                    continue
                index = index_parser(var_bind[0].prettyPrint())
                value = _clean_value(var_bind[1])
                if index is None or not value:
                    continue
                results.append((index, value))
                if len(results) >= max_rows:
                    return results
        return results
    finally:
        engine.close_dispatcher()


async def _fetch_column(
    ip: str,
    community: str,
    oid_parts: tuple[str, str, int] | tuple[str, str],
    *,
    timeout: float,
    retries: int,
    max_rows: int,
) -> list[tuple[str, str]]:
    engine = SnmpEngine()
    try:
        transport = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=retries)
        results: list[tuple[str, str]] = []
        async for error_indication, error_status, error_index, var_binds in walk_cmd(
            engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(*oid_parts)),
            lexicographicMode=False,
            lookupMib=False,
            maxRows=max_rows,
        ):
            if error_indication:
                raise SnmpProbeError(str(error_indication))
            if error_status:
                raise SnmpProbeError(str(error_status))
            for var_bind in var_binds:
                if len(var_bind) < 2:
                    continue
                oid = var_bind[0].prettyPrint()
                value = var_bind[1].prettyPrint().strip()
                if not value or value.startswith("No Such") or "No more variables" in value:
                    continue
                results.append((_extract_index(oid), value))
                if len(results) >= max_rows:
                    return results
        return results
    finally:
        engine.close_dispatcher()


def _build_notes(scalars: dict[str, str], ports: list[SnmpPortSnapshot], processor_values: list[str], lldp_neighbors: list[dict[str, Any]], bridge_fdb: list[dict[str, Any]]) -> str:
    parts = []
    if scalars.get("sys_name"):
        parts.append(f"sysName={scalars['sys_name']}")
    if scalars.get("if_number"):
        parts.append(f"interfaces={scalars['if_number']}")
    if processor_values:
        parts.append(f"cpu_cores={len(processor_values)}")
        parts.append(f"cpu_avg={round(sum(int(value) for value in processor_values) / len(processor_values), 2)}")
    if ports:
        active_ports = len([port for port in ports if port.oper_status == "up"])
        parts.append(f"active_ports={active_ports}")
    if lldp_neighbors:
        parts.append(f"lldp_neighbors={len(lldp_neighbors)}")
    if bridge_fdb:
        parts.append(f"bridge_fdb={len(bridge_fdb)}")
    return " | ".join(parts)


def _normalize_private_ipv4(ip: str) -> str:
    address = ipaddress.ip_address(ip.strip())
    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported")
    if not address.is_private:
        raise ValueError("SNMP probe is restricted to private IPv4 addresses")
    return str(address)


def _extract_index(oid: str) -> str:
    return oid.rsplit(".", 1)[-1] if "." in oid else oid


def _index_sort_key(index: str) -> tuple[int, str]:
    try:
        return (0, f"{int(index):08d}")
    except ValueError:
        return (1, index)


def _lookup_column(rows: list[tuple[str, str]], index: str) -> str:
    for row_index, value in rows:
        if row_index == index:
            return value
    return ""


def _first_non_empty(*values: str) -> str:
    for value in values:
        cleaned = _clean_text(value)
        if cleaned:
            return cleaned
    return ""


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    cleaned = str(value).strip()
    if cleaned.startswith("No Such") or "No more variables" in cleaned:
        return ""
    return cleaned


def _clean_value(var_bind: Any) -> str:
    value: Any | None = None
    if isinstance(var_bind, (tuple, list)) and len(var_bind) >= 2:
        value = var_bind[1]
    else:
        try:
            value = var_bind[1]
        except Exception:
            value = None
    if value is not None:
        if hasattr(value, "prettyPrint"):
            return _clean_text(value.prettyPrint())
        return _clean_text(value)
    if hasattr(var_bind, "prettyPrint"):
        pretty = _clean_text(var_bind.prettyPrint())
        if " = " in pretty:
            return _clean_text(pretty.split(" = ", 1)[1])
        return pretty
    return _clean_text(var_bind)


def _normalize_mac(value: str) -> str:
    cleaned = _clean_text(value)
    if not cleaned:
        return ""
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        cleaned = cleaned[2:]
        lowered = cleaned.lower()
    if lowered in {"00:00:00:00:00:00", "000000000000"}:
        return ""
    hex_only = "".join(ch for ch in cleaned if ch.isalnum())
    if len(hex_only) == 12:
        return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).upper()
    return cleaned


def _human_status(value: str) -> str:
    cleaned = _clean_text(value)
    if not cleaned:
        return ""
    return STATUS_MAP.get(cleaned, cleaned)


def _human_bandwidth(value: str) -> str:
    cleaned = _clean_text(value)
    if not cleaned:
        return ""
    try:
        number = float(cleaned)
    except ValueError:
        return cleaned
    if number >= 1_000_000_000:
        return f"{number / 1_000_000_000:.2f} Gbps"
    if number >= 1_000_000:
        return f"{number / 1_000_000:.2f} Mbps"
    if number >= 1_000:
        return f"{number / 1_000:.2f} Kbps"
    return f"{int(number)} bps"


def _calc_rate(previous_value: Any, current_value: Any, previous_timestamp: Any, current_timestamp: datetime) -> str:
    try:
        prev = int(str(previous_value).strip())
        curr = int(str(current_value).strip())
    except (TypeError, ValueError):
        return ""
    try:
        prev_time = datetime.fromisoformat(str(previous_timestamp))
    except ValueError:
        return ""
    elapsed = (current_timestamp - prev_time).total_seconds()
    if elapsed <= 0:
        return ""
    delta = max(0, curr - prev)
    return f"{round((delta * 8) / elapsed, 2)}"


def _load_previous_ports(ip: str) -> dict[str, dict[str, Any]]:
    state = load_last_probe()
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    for device in devices:
        if isinstance(device, dict) and device.get("ip") == ip:
            ports = device.get("ports") if isinstance(device.get("ports"), list) else []
            return {str(port.get("index")): port for port in ports if isinstance(port, dict)}
    return {}


def _persist_probe_snapshot(snapshot: dict[str, Any]) -> None:
    state = load_last_probe()
    state["last_probe"] = snapshot
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    ip = str(snapshot.get("ip", "")).strip()
    ports = snapshot.get("ports") if isinstance(snapshot.get("ports"), list) else []
    lldp_neighbors = snapshot.get("lldp_neighbors") if isinstance(snapshot.get("lldp_neighbors"), list) else []
    bridge_port_map = snapshot.get("bridge_port_map") if isinstance(snapshot.get("bridge_port_map"), list) else []
    bridge_fdb = snapshot.get("bridge_fdb") if isinstance(snapshot.get("bridge_fdb"), list) else []
    timestamp = snapshot.get("collected_at") or datetime.now(timezone.utc).isoformat()
    snmp_mac_address = next(
        (_normalize_mac(port.get("mac_address")) for port in ports if isinstance(port, dict) and _normalize_mac(port.get("mac_address"))),
        "",
    )
    updated = False
    for device in devices:
        if isinstance(device, dict) and device.get("ip") == ip:
            device.update({
                "ip": ip,
                "ports": ports,
                "lldp_neighbors": lldp_neighbors,
                "bridge_port_map": bridge_port_map,
                "bridge_fdb": bridge_fdb,
                "collected_at": timestamp,
                "sys_name": _clean_text(snapshot.get("sys_name")),
                "sys_descr": _clean_text(snapshot.get("sys_descr")),
                "snmp_mac_address": snmp_mac_address,
            })
            updated = True
            break
    if not updated:
        devices.append({
            "ip": ip,
            "ports": ports,
            "lldp_neighbors": lldp_neighbors,
            "bridge_port_map": bridge_port_map,
            "bridge_fdb": bridge_fdb,
            "collected_at": timestamp,
            "sys_name": _clean_text(snapshot.get("sys_name")),
            "sys_descr": _clean_text(snapshot.get("sys_descr")),
            "snmp_mac_address": snmp_mac_address,
        })
    state["devices"] = devices
    save_last_probe(state)


def _default_probe_state() -> dict[str, Any]:
    return {"devices": []}


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
