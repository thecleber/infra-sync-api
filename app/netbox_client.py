from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any

import httpx

from .utils import normalize_auth_header


@dataclass(slots=True)
class NetBoxResult:
    data: dict[str, Any] | None
    created: bool = False


class NetBoxClientError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, payload: Any | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class NetBoxClient:
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
        for path in ("/api/status/", "/api/"):
            with contextlib.suppress(httpx.HTTPError):
                response = await self._client.get(path)
                if response.status_code < 500:
                    return True
        return False

    async def list(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        response = await self._client.get(path, params=params)
        self._raise_for_response(response)
        payload = response.json()
        if isinstance(payload, dict) and "results" in payload:
            results = payload["results"]
            return results if isinstance(results, list) else []
        if isinstance(payload, list):
            return payload
        return []

    async def get(self, path: str) -> dict[str, Any]:
        response = await self._client.get(path)
        self._raise_for_response(response)
        payload = response.json()
        if isinstance(payload, dict):
            return payload
        raise NetBoxClientError("NetBox detail response was not a JSON object", payload=payload)

    async def get_unique(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        results = await self.list(path, params=params)
        if len(results) == 1:
            return results[0]
        if len(results) > 1:
            raise NetBoxClientError(f"Multiple NetBox objects found for {path} with {params}", status_code=409)
        return None

    async def create(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(path, json=json)
        if response.status_code in {200, 201}:
            return response.json()
        self._raise_for_response(response)
        return {}

    async def update(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.patch(path, json=json)
        self._raise_for_response(response)
        return response.json()

    async def health_status(self) -> bool:
        return await self.healthcheck()

    async def find_manufacturer_by_slug(self, slug: str) -> dict[str, Any] | None:
        return await self.get_unique("/api/dcim/manufacturers/", params={"slug": slug})

    async def create_manufacturer(self, name: str, slug: str, description: str) -> dict[str, Any]:
        return await self.create(
            "/api/dcim/manufacturers/",
            {
                "name": name,
                "slug": slug,
                "description": description,
            },
        )

    async def find_device_types(self, model: str) -> list[dict[str, Any]]:
        return await self.list("/api/dcim/device-types/", params={"model": model})

    async def create_device_type(
        self,
        *,
        slug: str,
        manufacturer_id: int,
        model: str,
        description: str,
    ) -> dict[str, Any]:
        return await self.create(
            "/api/dcim/device-types/",
            {
                "manufacturer": manufacturer_id,
                "model": model,
                "slug": slug,
                "u_height": 0,
                "is_full_depth": False,
                "description": description,
            },
        )

    async def find_devices_by_hostid(self, hostid: str) -> list[dict[str, Any]]:
        return await self.list("/api/dcim/devices/", params={"cf_zabbix_hostid": hostid})

    async def find_devices_by_name(self, name: str) -> list[dict[str, Any]]:
        return await self.list("/api/dcim/devices/", params={"name": name})

    async def find_devices_by_ip(self, ip_value: str) -> list[dict[str, Any]]:
        ip_results = await self.list("/api/ipam/ip-addresses/", params={"address": ip_value})
        device_ids: list[dict[str, Any]] = []
        for item in ip_results:
            assigned_type = item.get("assigned_object_type")
            assigned_id = item.get("assigned_object_id")
            if assigned_type == "dcim.interface" and assigned_id:
                interface = await self.get(f"/api/dcim/interfaces/{assigned_id}/")
                if interface and interface.get("device"):
                    device_ids.append(interface["device"])
        return device_ids

    async def create_device(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.create("/api/dcim/devices/", payload)

    async def update_device(self, device_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.update(f"/api/dcim/devices/{device_id}/", payload)

    async def find_interface(self, device_id: int, name: str) -> dict[str, Any] | None:
        return await self.get_unique(
            "/api/dcim/interfaces/",
            params={"device_id": device_id, "name": name},
        )

    async def create_interface(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.create("/api/dcim/interfaces/", payload)

    async def find_ip_address(self, address: str) -> dict[str, Any] | None:
        return await self.get_unique("/api/ipam/ip-addresses/", params={"address": address})

    async def create_ip_address(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.create("/api/ipam/ip-addresses/", payload)

    async def update_ip_address(self, ip_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.update(f"/api/ipam/ip-addresses/{ip_id}/", payload)

    def _raise_for_response(self, response: httpx.Response) -> None:
        if response.is_success:
            return
        message = f"NetBox request failed with status {response.status_code}"
        with contextlib.suppress(ValueError):
            payload = response.json()
            detail = payload.get("detail") if isinstance(payload, dict) else None
            if detail:
                message = f"{message}: {detail}"
        raise NetBoxClientError(message, status_code=response.status_code, payload=response.text)
