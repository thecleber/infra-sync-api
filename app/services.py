from __future__ import annotations

import contextlib
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

from .models import SyncDeviceRequest
from .netbox_client import NetBoxClient, NetBoxClientError
from .utils import merge_custom_fields, slugify
from .zabbix_client import ZabbixClient, ZabbixHostSnapshot


class SyncError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass(slots=True)
class SyncOutcome:
    success: bool
    action: str
    device_id: int | None
    device_name: str | None
    manufacturer_id: int | None
    device_type_id: int | None
    interface_id: int | None
    ip_address_id: int | None
    created_manufacturer: bool = False
    created_device_type: bool = False
    created_device: bool = False
    created_interface: bool = False
    created_ip: bool = False
    warnings: list[str] = field(default_factory=list)
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "action": self.action,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "manufacturer_id": self.manufacturer_id,
            "device_type_id": self.device_type_id,
            "interface_id": self.interface_id,
            "ip_address_id": self.ip_address_id,
            "created_manufacturer": self.created_manufacturer,
            "created_device_type": self.created_device_type,
            "created_device": self.created_device,
            "created_interface": self.created_interface,
            "created_ip": self.created_ip,
            "warnings": self.warnings,
            "message": self.message,
        }


async def sync_device(payload: SyncDeviceRequest, client: NetBoxClient, default_site_id: int, dry_run: bool = False) -> SyncOutcome:
    warnings: list[str] = []
    ports = _normalize_snmp_ports(payload.ports)
    scan_custom_fields, scan_summary = _build_scan_metadata(ports)
    device_name = payload.normalized_device_name()
    manufacturer_slug = slugify(payload.fabricante)
    device_type_slug = slugify(f"{payload.fabricante}-{payload.modelo}")

    await _validate_site_and_role(client, payload.site_id or default_site_id, payload.role_id)

    manufacturer = await client.find_manufacturer_by_slug(manufacturer_slug)
    created_manufacturer = False
    if manufacturer is None and not dry_run:
        manufacturer = await _create_or_refetch(
            lambda: client.create_manufacturer(
                payload.fabricante,
                manufacturer_slug,
                "Criado automaticamente pela integracao Zabbix/n8n.",
            ),
            lambda: client.find_manufacturer_by_slug(manufacturer_slug),
        )
        created_manufacturer = True

    if manufacturer is None:
        warnings.append("Manufacturer would be created automatically.")

    manufacturer_id = manufacturer.get("id") if manufacturer else None

    device_type = None
    if manufacturer_id:
        device_types = await client.find_device_types(payload.modelo)
        for candidate in device_types:
            candidate_manufacturer = candidate.get("manufacturer")
            candidate_manufacturer_id = (
                candidate_manufacturer.get("id") if isinstance(candidate_manufacturer, dict) else candidate_manufacturer
            )
            if candidate_manufacturer_id == manufacturer_id and candidate.get("model") == payload.modelo:
                device_type = candidate
                break

    created_device_type = False
    if device_type is None and manufacturer_id and not dry_run:
        device_type = await _create_or_refetch(
            lambda: client.create_device_type(
                slug=device_type_slug,
                manufacturer_id=manufacturer_id,
                model=payload.modelo,
                description="Criado automaticamente pela integracao Zabbix/n8n.",
            ),
            lambda: _find_device_type(client, payload.modelo, manufacturer_id),
        )
        created_device_type = True

    if device_type is None:
        warnings.append("Device type would be created automatically.")

    device_type_id = device_type.get("id") if device_type else None

    device = None
    if payload.netbox_device_id:
        with contextlib.suppress(NetBoxClientError):
            device = await client.get_device(payload.netbox_device_id)
    if device is None:
        device = await _find_device(client, payload.hostid, device_name)
    created_device = False
    current_custom_fields: dict[str, Any] = {}
    if device is not None:
        warnings = [
            warning
            for warning in warnings
            if warning not in {"Manufacturer would be created automatically.", "Device type would be created automatically."}
        ]
        if manufacturer_id is None:
            existing_device_type = device.get("device_type")
            existing_manufacturer = None
            if isinstance(existing_device_type, dict):
                existing_manufacturer = existing_device_type.get("manufacturer")
                if device_type is None:
                    device_type = existing_device_type
                if device_type_id is None and existing_device_type.get("id"):
                    device_type_id = existing_device_type.get("id")
            if isinstance(existing_manufacturer, dict):
                manufacturer_id = existing_manufacturer.get("id") or manufacturer_id
            elif isinstance(existing_manufacturer, int):
                manufacturer_id = existing_manufacturer or manufacturer_id
        current_custom_fields = dict(device.get("custom_fields") or {})
        merged_custom_fields = merge_custom_fields(current_custom_fields, payload.hostid, scan_custom_fields)
        if not dry_run:
            update_payload: dict[str, Any] = {
                "custom_fields": merged_custom_fields,
                "description": merge_sync_marker(
                    device.get("description"),
                    payload.hostid,
                    device_name,
                    "updated",
                ),
            }
            merged_comments = merge_sync_notes(payload.comments_summary, scan_summary) if (payload.comments_summary or scan_summary) else ""
            if merged_comments:
                update_payload["comments"] = merge_sync_notes(device.get("comments"), merged_comments)
            if payload.serial:
                current_serial = str(device.get("serial") or "").strip()
                if current_serial != payload.serial:
                    update_payload["serial"] = payload.serial
            current_status = device.get("status")
            current_status_value = current_status.get("value") if isinstance(current_status, dict) else current_status
            if payload.netbox_status:
                if current_status_value != payload.netbox_status:
                    update_payload["status"] = payload.netbox_status
            elif current_status_value == "planned":
                update_payload["status"] = "active"
            if payload.site_id:
                update_payload["site"] = payload.site_id
            if payload.role_id:
                update_payload["role"] = payload.role_id
            if device_type_id:
                update_payload["device_type"] = device_type_id
            desired_site_id = _extract_related_id(device.get("site")) or payload.site_id or default_site_id
            if device_name and device.get("name") != device_name:
                name_available = await _device_name_is_available(client, device["id"], device_name, desired_site_id)
                if not name_available:
                    warnings.append(f"Device name {device_name} already exists in the site; keeping current name.")
                else:
                    update_payload["name"] = device_name
            device = await _update_device_with_scan_fallback(client, device["id"], update_payload, warnings)
    else:
        if payload.is_blocked_for_auto_create():
            return SyncOutcome(
                success=False,
                action="blocked",
                device_id=None,
                device_name=device_name,
                manufacturer_id=manufacturer_id,
                device_type_id=device_type_id,
                interface_id=None,
                ip_address_id=None,
                warnings=warnings + ["Auto creation blocked by hostname policy."],
                message="Device creation blocked because hostname is not eligible for auto creation.",
            )
        if dry_run:
            warnings.append("Device would be created automatically.")
        else:
            device_payload = {
                "name": device_name,
                "device_type": device_type_id,
                "role": payload.role_id,
                "site": payload.site_id or default_site_id,
                "status": payload.netbox_status or "planned",
                "custom_fields": merge_custom_fields({}, payload.hostid, scan_custom_fields),
                "description": merge_sync_marker(
                    None,
                    payload.hostid,
                    device_name,
                    "created",
                ),
            }
            merged_comments = merge_sync_notes(payload.comments_summary, scan_summary) if (payload.comments_summary or scan_summary) else ""
            if merged_comments:
                device_payload["comments"] = merged_comments
            if payload.serial:
                device_payload["serial"] = payload.serial
            device = await _create_device_with_scan_fallback(
                client,
                device_payload,
                warnings,
                lambda: _find_device(client, payload.hostid, device_name),
            )
            created_device = True

    if device is None:
        return SyncOutcome(
            success=True,
            action="dry-run" if dry_run else "noop",
            device_id=None,
            device_name=device_name,
            manufacturer_id=manufacturer_id,
            device_type_id=device_type_id,
            interface_id=None,
            ip_address_id=None,
            created_manufacturer=created_manufacturer,
            created_device_type=created_device_type,
            created_device=created_device,
            warnings=warnings,
            message="Dry-run completed." if dry_run else "No device changes were necessary.",
        )

    management_interface = await _resolve_management_interface(client, device["id"])
    any_interface = await _resolve_any_device_interface(client, device["id"])
    interface = management_interface or any_interface
    mac_interface = management_interface or any_interface
    created_interface = False
    if management_interface is None and not dry_run:
        interface_payload = {
            "device": device["id"],
            "name": "mgmt0",
            "type": "virtual",
            "enabled": True,
        }
        management_interface = await _create_or_refetch(
            lambda: client.create_interface(interface_payload),
            lambda: _resolve_management_interface(client, device["id"]),
        )
        if payload.mac_address and management_interface is not None:
            management_interface = await _ensure_interface_primary_mac(
                client,
                management_interface,
                payload.mac_address,
                dry_run=dry_run,
                warnings=warnings,
            )
        created_interface = True
        interface = management_interface or interface
    elif management_interface is None:
        warnings.append("Interface mgmt0 would be created.")
    if payload.mac_address and mac_interface is not None:
        mac_interface = await _ensure_interface_primary_mac(
            client,
            mac_interface,
            payload.mac_address,
            dry_run=dry_run,
            warnings=warnings,
        )
    elif payload.mac_address:
        warnings.append("Interface mgmt0 would receive the discovered MAC address.")

    ip_address = await client.find_ip_address(payload.ip)
    created_ip = False
    if ip_address is None and not dry_run and management_interface is not None:
        ip_address = await _create_or_refetch(
            lambda: client.create_ip_address(
                {
                    "address": payload.ip,
                    "status": "active",
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": management_interface["id"],
                }
            ),
            lambda: client.find_ip_address(payload.ip),
        )
        created_ip = True
    elif ip_address is None:
        warnings.append("IP address would be created.")

    if not dry_run:
        if ip_address is not None and interface is not None:
            desired_assignment = {
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": management_interface["id"] if management_interface is not None else interface["id"],
            }
            if (
                ip_address.get("assigned_object_type") != desired_assignment["assigned_object_type"]
                or ip_address.get("assigned_object_id") != desired_assignment["assigned_object_id"]
            ):
                ip_address = await client.update_ip_address(ip_address["id"], desired_assignment)

        if ip_address is not None and _extract_related_id(device.get("primary_ip4")) != ip_address.get("id"):
            device = await _update_device_with_scan_fallback(
                client,
                device["id"],
                {
                    "primary_ip4": ip_address["id"],
                    "custom_fields": merge_custom_fields(device.get("custom_fields"), payload.hostid, scan_custom_fields),
                },
                warnings,
            )

    if ports:
        synced_interfaces, interface_warnings = await _sync_snmp_interfaces(
            client,
            device["id"],
            ports,
            dry_run=dry_run,
        )
        warnings.extend(interface_warnings)
        if synced_interfaces and interface is None:
            interface = synced_interfaces[0]

    return SyncOutcome(
        success=True,
        action="dry-run" if dry_run else ("created" if created_device else "updated"),
        device_id=device.get("id"),
        device_name=device.get("name"),
        manufacturer_id=manufacturer_id,
        device_type_id=device_type.get("id") if device_type else None,
        interface_id=interface.get("id") if interface else None,
        ip_address_id=ip_address.get("id") if ip_address else None,
        created_manufacturer=created_manufacturer,
        created_device_type=created_device_type,
        created_device=created_device,
        created_interface=created_interface,
        created_ip=created_ip,
        warnings=warnings,
        message="Dry-run completed." if dry_run else "Synchronization completed successfully.",
    )


async def _resolve_management_interface(client: NetBoxClient, device_id: int) -> dict[str, Any] | None:
    interface = await client.find_interface(device_id, "mgmt0")
    if interface is not None:
        return interface
    return None


async def _resolve_any_device_interface(client: NetBoxClient, device_id: int) -> dict[str, Any] | None:
    list_interfaces = getattr(client, "list_interfaces", None)
    if list_interfaces is None:
        return None

    with contextlib.suppress(Exception):
        interfaces = await list_interfaces({"device_id": device_id, "limit": 200})
        if interfaces:
            return sorted(
                interfaces,
                key=lambda item: (
                    str(item.get("name") or "").lower(),
                    int(item.get("id") or 0),
                ),
            )[0]
    return None


async def _sync_snmp_interfaces(
    client: NetBoxClient,
    device_id: int,
    ports: list[dict[str, Any]],
    *,
    dry_run: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    synced_interfaces: list[dict[str, Any]] = []
    for port in ports:
        interface_name = _snmp_interface_name(port)
        if not interface_name:
            continue
        desired_description = _snmp_interface_description(port)
        desired_mac = _normalize_snmp_mac(port.get("mac_address"))
        desired_enabled = _snmp_interface_enabled(port)
        desired_type = _snmp_interface_type(port)

        interface = await client.find_interface(device_id, interface_name)
        if interface is None:
            if dry_run:
                warnings.append(f"Interface {interface_name} would be created.")
                continue
            interface_payload: dict[str, Any] = {
                "device": device_id,
                "name": interface_name,
                "type": desired_type,
                "enabled": desired_enabled,
            }
            if desired_description:
                interface_payload["description"] = desired_description
            interface = await client.create_interface(interface_payload)
            if desired_mac:
                interface = await _ensure_interface_primary_mac(
                    client,
                    interface,
                    desired_mac,
                    dry_run=dry_run,
                    warnings=warnings,
                )
        else:
            update_payload: dict[str, Any] = {}
            current_description = str(interface.get("description") or "").strip()
            if desired_description and current_description != desired_description:
                update_payload["description"] = desired_description
            current_enabled = interface.get("enabled")
            if isinstance(current_enabled, bool) and current_enabled != desired_enabled:
                update_payload["enabled"] = desired_enabled
            elif current_enabled is None:
                update_payload["enabled"] = desired_enabled
            if update_payload and not dry_run:
                interface = await client.update_interface(interface["id"], update_payload)
            elif update_payload:
                warnings.append(f"Interface {interface_name} would be updated.")
            if desired_mac:
                interface = await _ensure_interface_primary_mac(
                    client,
                    interface,
                    desired_mac,
                    dry_run=dry_run,
                    warnings=warnings,
                )
        if isinstance(interface, dict):
            synced_interfaces.append(interface)
    return synced_interfaces, warnings


async def _ensure_interface_primary_mac(
    client: NetBoxClient,
    interface: dict[str, Any],
    desired_mac: str,
    *,
    dry_run: bool,
    warnings: list[str],
) -> dict[str, Any]:
    desired_mac = str(desired_mac).strip().upper()
    if not desired_mac:
        return interface
    current_mac = _extract_interface_mac(interface)
    if current_mac == desired_mac:
        return interface
    interface_id = _extract_related_id(interface.get("id"))
    if interface_id is None:
        return interface
    if dry_run:
        warnings.append(f"Interface {interface.get('name') or interface.get('display') or interface_id} would receive the discovered MAC address.")
        return interface

    mac_record = await _ensure_mac_address_record(client, desired_mac, interface_id)
    if mac_record is None:
        warnings.append(f"MAC {desired_mac} could not be linked to interface {interface_id}.")
        return interface
    return await client.update_interface(interface_id, {"primary_mac_address": {"id": mac_record["id"]}})


async def _ensure_mac_address_record(client: NetBoxClient, mac_address: str, interface_id: int) -> dict[str, Any] | None:
    find_mac_addresses = getattr(client, "find_mac_addresses", None)
    if find_mac_addresses is not None:
        try:
            existing_records = await find_mac_addresses(mac_address)
        except Exception:
            existing_records = []
        for record in existing_records:
            if not isinstance(record, dict):
                continue
            assigned_object = record.get("assigned_object")
            if _extract_related_id(assigned_object) == interface_id:
                return record
            update_mac_address = getattr(client, "update_mac_address", None)
            if update_mac_address is not None:
                try:
                    return await update_mac_address(
                        int(record["id"]),
                        {
                            "assigned_object_type": "dcim.interface",
                            "assigned_object_id": interface_id,
                        },
                    )
                except Exception:
                    continue
    create_mac_address = getattr(client, "create_mac_address", None)
    if create_mac_address is None:
        return None
    return await create_mac_address(
        {
            "mac_address": mac_address,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": interface_id,
            "description": "synced by infra-sync-api",
        }
    )


def _extract_interface_mac(interface: dict[str, Any]) -> str:
    primary_mac_address = interface.get("primary_mac_address")
    if isinstance(primary_mac_address, dict):
        mac_address = primary_mac_address.get("mac_address")
        if isinstance(mac_address, str):
            return mac_address.strip().upper()
    mac_address = interface.get("mac_address")
    if isinstance(mac_address, str):
        return mac_address.strip().upper()
    return ""


def _normalize_snmp_ports(ports: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not ports:
        return []
    normalized: list[dict[str, Any]] = []
    for port in ports:
        if isinstance(port, dict):
            normalized.append(port)
    return normalized


def _snmp_interface_name(port: dict[str, Any]) -> str:
    for key in ("name", "index"):
        value = str(port.get(key) or "").strip()
        if value:
            return value
    return ""


def _snmp_interface_description(port: dict[str, Any]) -> str:
    for key in ("alias", "description"):
        value = str(port.get(key) or "").strip()
        if value:
            return value
    return ""


def _snmp_interface_enabled(port: dict[str, Any]) -> bool:
    oper_status = str(port.get("oper_status") or "").strip().lower()
    if oper_status:
        return oper_status == "up"
    admin_status = str(port.get("admin_status") or "").strip().lower()
    if admin_status:
        return admin_status == "up"
    return True


def _snmp_interface_type(port: dict[str, Any]) -> str:
    name = str(port.get("name") or "").strip().lower()
    description = str(port.get("description") or "").strip().lower()
    alias = str(port.get("alias") or "").strip().lower()
    text = " ".join(part for part in (name, description, alias) if part)
    if any(token in text for token in ("mgmt", "management", "loopback")):
        return "virtual"
    speed = _snmp_port_speed_gbps(port.get("speed_bps"))
    if speed >= 10:
        return "10gbase-t"
    if speed >= 1:
        return "1000base-t"
    if speed >= 0.1:
        return "100base-tx"
    return "virtual"


def _snmp_port_speed_gbps(value: Any) -> float:
    text = str(value or "").strip().lower()
    if not text:
        return 0.0
    match = re.search(r"([\d.,]+)\s*(tbps|gbps|mbps|kbps|bps)", text)
    if not match:
        return 0.0
    numeric = float(match.group(1).replace(",", "."))
    unit = match.group(2)
    if unit == "tbps":
        return numeric * 1000.0
    if unit == "gbps":
        return numeric
    if unit == "mbps":
        return numeric / 1000.0
    if unit == "kbps":
        return numeric / 1_000_000.0
    return numeric / 1_000_000_000.0


def _normalize_snmp_mac(value: Any) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        cleaned = cleaned[2:]
        lowered = cleaned.lower()
    if lowered in {"00:00:00:00:00:00", "000000000000", "ff:ff:ff:ff:ff:ff"}:
        return ""
    normalized = "".join(ch for ch in cleaned if ch.isalnum())
    if len(normalized) == 12:
        return ":".join(normalized[i:i + 2] for i in range(0, 12, 2)).upper()
    return cleaned.upper()


async def _find_device(client: NetBoxClient, hostid: str, device_name: str) -> dict[str, Any] | None:
    by_hostid = await client.find_devices_by_hostid(hostid)
    if len(by_hostid) == 1:
        return by_hostid[0]
    if len(by_hostid) > 1:
        raise SyncError(f"Multiple devices matched hostid {hostid}", status_code=409)

    by_name = await client.find_devices_by_name(device_name)
    if len(by_name) == 1:
        return by_name[0]
    if len(by_name) > 1:
        raise SyncError(f"Multiple devices matched name {device_name}", status_code=409)
    return None


async def _find_device_type(client: NetBoxClient, model: str, manufacturer_id: int) -> dict[str, Any] | None:
    device_types = await client.find_device_types(model)
    for candidate in device_types:
        candidate_manufacturer = candidate.get("manufacturer")
        candidate_manufacturer_id = (
            candidate_manufacturer.get("id") if isinstance(candidate_manufacturer, dict) else candidate_manufacturer
        )
        if candidate_manufacturer_id == manufacturer_id and candidate.get("model") == model:
            return candidate
    return None


async def _create_or_refetch(create_fn, refetch_fn):
    try:
        return await create_fn()
    except NetBoxClientError as exc:
        if exc.status_code in {400, 409}:
            refetched = await refetch_fn()
            if refetched is not None:
                return refetched
        raise


async def _validate_site_and_role(client: NetBoxClient, site_id: int, role_id: int) -> None:
    try:
        await client.get_site(site_id)
    except NetBoxClientError as exc:
        if exc.status_code == 404:
            raise SyncError(f"Site {site_id} was not found in NetBox", status_code=404) from exc
        raise

    try:
        await client.get_device_role(role_id)
    except NetBoxClientError as exc:
        if exc.status_code == 404:
            raise SyncError(f"Device role {role_id} was not found in NetBox", status_code=404) from exc
        raise


async def _device_name_is_available(client: NetBoxClient, device_id: int, device_name: str, site_id: int | None) -> bool:
    if not device_name:
        return True
    find_devices_by_name = getattr(client, "find_devices_by_name", None)
    if find_devices_by_name is None:
        return True
    try:
        matches = await find_devices_by_name(device_name)
    except Exception:
        return True
    for match in matches:
        if not isinstance(match, dict):
            continue
        if match.get("id") == device_id:
            continue
        match_site_id = _extract_related_id(match.get("site"))
        if site_id is None or match_site_id is None or match_site_id == site_id:
            return False
    return True


def merge_sync_marker(existing_value: Any, hostid: str, device_name: str, action: str) -> str:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    marker = (
        f"[infra-sync-api] {action} at {timestamp}; "
        f"hostid={hostid}; device={device_name}; source=Zabbix/n8n"
    )
    existing = str(existing_value).strip() if existing_value else ""
    if not existing:
        return marker[:200]
    if marker in existing:
        return existing[:200]
    combined = f"{existing} | {marker}"
    if len(combined) <= 200:
        return combined
    return marker[:200]


def _extract_related_id(value: Any) -> int | None:
    if isinstance(value, dict):
        related_id = value.get("id")
        return related_id if isinstance(related_id, int) else None
    return value if isinstance(value, int) else None


def _build_scan_metadata(ports: list[dict[str, Any]]) -> tuple[dict[str, Any], str]:
    metadata: dict[str, Any] = {}
    notes: list[str] = []
    if ports:
        interface_count = len(ports)
        metadata["snmp_interface_count"] = interface_count
        notes.append(f"interfaces={interface_count}")
        first_mac = next((_normalize_snmp_mac(port.get("mac_address")) for port in ports if _normalize_snmp_mac(port.get("mac_address"))), "")
        if first_mac:
            metadata["snmp_mac_address"] = first_mac
            notes.append(f"mac={first_mac}")
    return metadata, " | ".join(notes)


def _looks_like_scan_custom_field_error(exc: NetBoxClientError, custom_field_keys: set[str]) -> bool:
    text = " ".join(
        str(part)
        for part in (
            exc,
            getattr(exc, "payload", None),
        )
        if part
    ).lower()
    return "custom_fields" in text or any(key.lower() in text for key in custom_field_keys)


async def _create_device_with_scan_fallback(
    client: NetBoxClient,
    payload: dict[str, Any],
    warnings: list[str],
    refetch_fn,
) -> dict[str, Any]:
    scan_custom_field_keys = {"snmp_interface_count", "snmp_mac_address"}
    try:
        return await _create_or_refetch(lambda: client.create_device(payload), refetch_fn)
    except NetBoxClientError as exc:
        if not payload.get("custom_fields") or not _looks_like_scan_custom_field_error(exc, scan_custom_field_keys):
            raise
        fallback_payload = dict(payload)
        fallback_payload["custom_fields"] = {
            key: value
            for key, value in dict(payload.get("custom_fields") or {}).items()
            if key not in scan_custom_field_keys
        }
        warnings.append("NetBox rejected scan custom fields; saved the scan summary in comments only.")
        return await _create_or_refetch(lambda: client.create_device(fallback_payload), refetch_fn)


async def _update_device_with_scan_fallback(
    client: NetBoxClient,
    device_id: int,
    payload: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    scan_custom_field_keys = {"snmp_interface_count", "snmp_mac_address"}
    try:
        return await client.update_device(device_id, payload)
    except NetBoxClientError as exc:
        if not payload.get("custom_fields") or not _looks_like_scan_custom_field_error(exc, scan_custom_field_keys):
            raise
        fallback_payload = dict(payload)
        fallback_payload["custom_fields"] = {
            key: value
            for key, value in dict(payload.get("custom_fields") or {}).items()
            if key not in scan_custom_field_keys
        }
        warnings.append("NetBox rejected scan custom fields; saved the scan summary in comments only.")
        return await client.update_device(device_id, fallback_payload)


def merge_sync_notes(existing_value: Any, addition: str) -> str:
    existing = str(existing_value).strip() if existing_value else ""
    addition = addition.strip()
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing} | {addition}"


async def sync_zabbix_host(
    hostid: str,
    zabbix_client: ZabbixClient,
    netbox_client: NetBoxClient,
    default_site_id: int,
    default_role_id: int,
    access_point_role_id: int,
    dry_run: bool = False,
    site_id: int | None = None,
    role_id: int | None = None,
) -> SyncOutcome:
    snapshot = await zabbix_client.get_host_snapshot(hostid)
    sync_role_id = role_id or snapshot.infer_role_id(default_role_id, access_point_role_id)
    sync_site_id = site_id or default_site_id
    primary_ip = snapshot.primary_ip()
    if not primary_ip:
        raise SyncError(f"Zabbix host {hostid} does not expose a usable primary IP", status_code=422)

    manufacturer = snapshot.infer_manufacturer() or snapshot.technical_name.split(".")[0] or "UNKNOWN"
    model = snapshot.infer_model() or snapshot.visible_name or snapshot.technical_name

    payload = SyncDeviceRequest(
        hostid=snapshot.hostid,
        hostname=snapshot.technical_name,
        display_name=snapshot.visible_name,
        ip=primary_ip,
        fabricante=manufacturer,
        modelo=model,
        site_id=sync_site_id,
        role_id=sync_role_id,
        zabbix_status=str(snapshot.status),
        serial=snapshot.infer_serial(),
        comments_summary=snapshot.comments_summary(),
        netbox_status=snapshot.netbox_status,
    )
    return await sync_device(payload, netbox_client, default_site_id, dry_run=dry_run)
