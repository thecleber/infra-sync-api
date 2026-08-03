from __future__ import annotations

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
        merged_custom_fields = merge_custom_fields(current_custom_fields, payload.hostid)
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
            if payload.comments_summary:
                update_payload["comments"] = merge_sync_notes(device.get("comments"), payload.comments_summary)
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
            if device_name and device.get("name") != device_name:
                update_payload["name"] = device_name
            device = await client.update_device(device["id"], update_payload)
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
                "custom_fields": merge_custom_fields({}, payload.hostid),
                "description": merge_sync_marker(
                    None,
                    payload.hostid,
                    device_name,
                    "created",
                ),
            }
            if payload.comments_summary:
                device_payload["comments"] = payload.comments_summary
            if payload.serial:
                device_payload["serial"] = payload.serial
            device = await _create_or_refetch(
                lambda: client.create_device(device_payload),
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

    interface = await client.find_interface(device["id"], "mgmt0")
    created_interface = False
    if interface is None and not dry_run:
        interface = await _create_or_refetch(
            lambda: client.create_interface(
                {
                    "device": device["id"],
                    "name": "mgmt0",
                    "type": "virtual",
                    "enabled": True,
                }
            ),
            lambda: client.find_interface(device["id"], "mgmt0"),
        )
        created_interface = True
    elif interface is None:
        warnings.append("Interface mgmt0 would be created.")

    ip_address = await client.find_ip_address(payload.ip)
    created_ip = False
    if ip_address is None and not dry_run and interface is not None:
        ip_address = await _create_or_refetch(
            lambda: client.create_ip_address(
                {
                    "address": payload.ip,
                    "status": "active",
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": interface["id"],
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
                "assigned_object_id": interface["id"],
            }
            if (
                ip_address.get("assigned_object_type") != desired_assignment["assigned_object_type"]
                or ip_address.get("assigned_object_id") != desired_assignment["assigned_object_id"]
            ):
                ip_address = await client.update_ip_address(ip_address["id"], desired_assignment)

        if ip_address is not None and _extract_related_id(device.get("primary_ip4")) != ip_address.get("id"):
            device = await client.update_device(
                device["id"],
                {
                    "primary_ip4": ip_address["id"],
                    "custom_fields": merge_custom_fields(device.get("custom_fields"), payload.hostid),
                },
            )

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


def merge_sync_marker(existing_value: Any, hostid: str, device_name: str, action: str) -> str:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    marker = (
        f"[infra-sync-api] {action} at {timestamp}; "
        f"hostid={hostid}; device={device_name}; source=Zabbix/n8n"
    )
    existing = str(existing_value).strip() if existing_value else ""
    if not existing:
        return marker
    if marker in existing:
        return existing
    return f"{existing} | {marker}"


def _extract_related_id(value: Any) -> int | None:
    if isinstance(value, dict):
        related_id = value.get("id")
        return related_id if isinstance(related_id, int) else None
    return value if isinstance(value, int) else None


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
