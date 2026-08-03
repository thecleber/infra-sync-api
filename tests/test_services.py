import asyncio

import pytest

from app.models import SyncDeviceRequest
from app.netbox_client import NetBoxClientError
from app.services import SyncError, sync_device


class FakeClient:
    def __init__(self) -> None:
        self.created_device_payload = None
        self.created_interface_payload = None
        self.created_ip_payload = None
        self.updated_device_payload = None
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
        return {"id": 33, "name": payload["name"], "custom_fields": payload["custom_fields"], "primary_ip4": None}

    async def update_device(self, device_id: int, payload):
        self.updated_device_payload = payload
        merged = {"id": device_id, "name": "SW-CCO-GDS7830", "custom_fields": {"zabbix_hostid": "10917"}}
        merged["primary_ip4"] = payload.get("primary_ip4")
        return merged

    async def find_interface(self, device_id: int, name: str):
        return None

    async def create_interface(self, payload):
        self.created_interface_payload = payload
        return {"id": 44, **payload}

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
    assert client.created_device_payload["comments"] == "Criado automaticamente pela integracao Zabbix/n8n e ainda precisa de validacao."
    assert client.created_device_payload["custom_fields"] == {"zabbix_hostid": "10917"}
    assert client.created_interface_payload["name"] == "mgmt0"
    assert client.created_ip_payload["address"] == "10.0.0.24/32"


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
