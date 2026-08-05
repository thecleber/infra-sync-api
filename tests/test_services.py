import asyncio

import pytest

from app.models import SyncDeviceRequest
from app.netbox_client import NetBoxClientError
from app.services import SyncError, sync_device, sync_zabbix_host
from app.zabbix_client import ZabbixHostSnapshot


class FakeClient:
    def __init__(self) -> None:
        self.created_device_payload = None
        self.created_interface_payload = None
        self.created_ip_payload = None
        self.updated_interface_payloads = []
        self.updated_device_payloads = []
        self.validated_site_id = None
        self.validated_role_id = None

    async def get_site(self, site_id: int):
        self.validated_site_id = site_id
        return {"id": site_id}

    async def get_device_role(self, role_id: int):
        self.validated_role_id = role_id
        return {"id": role_id}

    async def find_manufacturer_by_slug(self, slug: str):
        return None

    async def create_manufacturer(self, name: str, slug: str, description: str):
        return {"id": 11, "name": name, "slug": slug, "description": description}

    async def find_device_types(self, model: str):
        return []

    async def create_device_type(self, *, slug: str, manufacturer_id: int, model: str, description: str):
        return {"id": 22, "manufacturer": manufacturer_id, "model": model, "slug": slug, "description": description}

    async def find_devices_by_hostid(self, hostid: str):
        return []

    async def find_devices_by_name(self, name: str):
        return []

    async def create_device(self, payload):
        self.created_device_payload = payload
        return {
            "id": 33,
            "name": payload["name"],
            "custom_fields": payload["custom_fields"],
            "description": payload.get("description"),
            "comments": payload.get("comments"),
            "serial": payload.get("serial"),
            "status": {"value": payload.get("status", "planned")},
            "primary_ip4": None,
        }

    async def update_device(self, device_id: int, payload):
        self.updated_device_payloads.append(payload)
        merged = {
            "id": device_id,
            "name": "SW-CCO-GDS7830",
            "custom_fields": {"zabbix_hostid": "10917"},
            "description": payload.get("description"),
            "status": {"value": payload.get("status", "planned")},
        }
        merged["primary_ip4"] = payload.get("primary_ip4")
        return merged

    async def find_interface(self, device_id: int, name: str):
        return None

    async def create_interface(self, payload):
        self.created_interface_payload = payload
        return {"id": 44, **payload}

    async def list_interfaces(self, params=None):
        return []

    async def update_interface(self, interface_id: int, payload):
        self.updated_interface_payloads.append((interface_id, payload))
        return {"id": interface_id, **payload}

    async def find_ip_address(self, address: str):
        return None

    async def create_ip_address(self, payload):
        self.created_ip_payload = payload
        return {"id": 55, **payload}

    async def update_ip_address(self, ip_id: int, payload):
        return {"id": ip_id, **payload}


class MissingSiteClient(FakeClient):
    async def get_site(self, site_id: int):
        raise NetBoxClientError("missing site", status_code=404)


def test_sync_device_create_includes_comments_and_validates_site_and_role():
    payload = SyncDeviceRequest(
        hostid="10917",
        hostname="SW-CCO-GDS7830",
        display_name="SW-CCO-GDS7830",
        ip="10.0.0.24",
        fabricante="GENERICO",
        modelo="Switch Gerenciavel Generico",
        site_id=1,
        role_id=2,
    )
    client = FakeClient()

    outcome = asyncio.run(sync_device(payload, client, default_site_id=1, dry_run=False))

    assert outcome.success is True
    assert client.validated_site_id == 1
    assert client.validated_role_id == 2
    assert client.created_device_payload["description"].startswith("[infra-sync-api] created at ")
    assert "hostid=10917" in client.created_device_payload["description"]
    assert client.created_device_payload["custom_fields"] == {"zabbix_hostid": "10917"}
    assert client.created_interface_payload["name"] == "mgmt0"
    assert client.created_ip_payload["address"] == "10.0.0.24/32"


class ExistingDeviceClient(FakeClient):
    async def find_devices_by_hostid(self, hostid: str):
        return [{
            "id": 77,
            "name": "SW-CCO-GDS7830",
            "custom_fields": {"site_tag": "A", "zabbix_hostid": hostid},
            "description": "existing description",
            "status": {"value": "planned"},
            "primary_ip4": None,
        }]

    async def find_devices_by_name(self, name: str):
        return []

    async def find_interface(self, device_id: int, name: str):
        return {"id": 88, "device": device_id, "name": name}

    async def find_ip_address(self, address: str):
        return {"id": 99, "address": address, "assigned_object_type": "dcim.interface", "assigned_object_id": 88}


class ExistingDeviceWithoutMgmtInterfaceClient(FakeClient):
    async def find_devices_by_hostid(self, hostid: str):
        return [{
            "id": 77,
            "name": "KYOCERA-PRN-01",
            "custom_fields": {"site_tag": "A", "zabbix_hostid": hostid},
            "description": "existing description",
            "status": {"value": "planned"},
            "primary_ip4": None,
        }]

    async def find_devices_by_name(self, name: str):
        return []

    async def find_interface(self, device_id: int, name: str):
        return None

    async def list_interfaces(self, params=None):
        return [{"id": 188, "device": 77, "name": "ge-0/0/1", "mac_address": "00:11:22:33:44:55"}]

    async def find_ip_address(self, address: str):
        return {"id": 199, "address": address, "assigned_object_type": "dcim.interface", "assigned_object_id": 188}


class FakeZabbixClient:
    def __init__(self, snapshot: ZabbixHostSnapshot) -> None:
        self.snapshot = snapshot

    async def get_host_snapshot(self, hostid: str):
        return self.snapshot


def test_sync_zabbix_host_creates_enriched_device():
    snapshot = ZabbixHostSnapshot(
        hostid="10917",
        host="sw-cco-gds7830",
        name="SW-CCO-GDS7830",
        status=0,
        description="Zabbix managed switch",
        inventory={
            "vendor": "GENERIC",
            "model": "Switch Gerenciavel Generico",
            "serialno_a": "ABC123",
            "hardware_full": "Switch Gerenciavel Generico 24p",
            "os_full": "Zabbix SNMP inventory",
        },
        interfaces=[
            {"interfaceid": "1", "main": "1", "type": "2", "useip": "1", "ip": "10.0.0.24", "dns": "", "port": "161"},
        ],
        items=[
            {"key_": "system.cpu.num", "name": "CPU cores", "lastvalue": "4"},
            {"key_": "vm.memory.size[total]", "name": "Memory", "lastvalue": "8192"},
            {"key_": "vfs.fs.size[/,total]", "name": "Storage", "lastvalue": "120G"},
        ],
    )
    client = FakeClient()

    outcome = asyncio.run(
        sync_zabbix_host(
            "10917",
            FakeZabbixClient(snapshot),
            client,
            default_site_id=1,
            default_role_id=2,
            access_point_role_id=7,
            dry_run=False,
        )
    )

    assert outcome.success is True
    assert client.created_device_payload["status"] == "active"
    assert client.created_device_payload["serial"] == "ABC123"
    assert "vendor=GENERIC" in client.created_device_payload["comments"]
    assert "cpu=4" in client.created_device_payload["comments"]
    assert client.created_device_payload["name"] == "SW-CCO-GDS7830"
    assert client.created_device_payload["description"].startswith("[infra-sync-api] created at ")
    assert client.created_ip_payload["address"] == "10.0.0.24/32"


def test_sync_device_updates_existing_device_with_marker():
    payload = SyncDeviceRequest(
        hostid="10917",
        hostname="SW-CCO-GDS7830",
        display_name="SW-CCO-GDS7830",
        ip="10.0.0.24",
        fabricante="GENERICO",
        modelo="Switch Gerenciavel Generico",
        site_id=1,
        role_id=2,
    )
    client = ExistingDeviceClient()

    outcome = asyncio.run(sync_device(payload, client, default_site_id=1, dry_run=False))

    assert outcome.action == "updated"
    assert any(payload.get("status") == "active" for payload in client.updated_device_payloads)
    assert any(
        "[infra-sync-api] updated at " in payload.get("description", "")
        for payload in client.updated_device_payloads
    )


def test_sync_device_updates_mac_on_first_available_interface_when_mgmt0_missing():
    payload = SyncDeviceRequest(
        hostid="kyocera-01",
        hostname="KYOCERA-PRN-01",
        display_name="KYOCERA-PRN-01",
        ip="10.0.0.118",
        fabricante="Kyocera",
        modelo="KYOCERA Document Solutions Printing System",
        site_id=1,
        role_id=2,
        mac_address="AA:BB:CC:DD:EE:FF",
    )
    client = ExistingDeviceWithoutMgmtInterfaceClient()

    outcome = asyncio.run(sync_device(payload, client, default_site_id=1, dry_run=False))

    assert outcome.action == "updated"
    assert client.updated_interface_payloads[-1] == (188, {"mac_address": "AA:BB:CC:DD:EE:FF"})
    assert client.created_interface_payload is None


def test_sync_device_rejects_missing_site_in_netbox():
    payload = SyncDeviceRequest(
        hostid="10917",
        hostname="SW-CCO-GDS7830",
        display_name="SW-CCO-GDS7830",
        ip="10.0.0.24",
        fabricante="GENERICO",
        modelo="Switch Gerenciavel Generico",
        site_id=999,
        role_id=2,
    )

    with pytest.raises(SyncError, match="Site 999 was not found in NetBox"):
        asyncio.run(sync_device(payload, MissingSiteClient(), default_site_id=1, dry_run=False))
