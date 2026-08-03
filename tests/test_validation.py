import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock

from app.config import Settings, get_settings
from app.main import app
from app.discovery import classify_discovered_device
from app.models import SyncDeviceRequest
from app.netbox_client import NetBoxClient
from app.zabbix_client import ZabbixClient


def _mock_dashboard_clients(monkeypatch):
    monkeypatch.setattr(NetBoxClient, "health_status", AsyncMock(return_value=True))
    monkeypatch.setattr(NetBoxClient, "count", AsyncMock(side_effect=[7, 19, 23, 11, 5, 2, 4]))
    monkeypatch.setattr(ZabbixClient, "healthcheck", AsyncMock(return_value=True))
    monkeypatch.setattr(ZabbixClient, "count_hosts", AsyncMock(return_value=14))
    monkeypatch.setattr(ZabbixClient, "count_problems", AsyncMock(return_value=3))
    monkeypatch.setattr(ZabbixClient, "list_problems", AsyncMock(return_value=[{"name": "Link down", "severity": "4", "clock": "1710000000", "hosts": [{"name": "SW-ACCESS-LAN"}]}]))


def _mock_management_clients(monkeypatch):
    _mock_dashboard_clients(monkeypatch)
    monkeypatch.setattr(NetBoxClient, "list_devices", AsyncMock(return_value=[{
        "id": 101,
        "name": "SW-ACCESS-LAN",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "role": {"id": 2, "name": "Switch"},
        "device_type": {"id": 3, "model": "Cisco 2960"},
        "primary_ip4": {"id": 77, "address": "10.0.0.24/32"},
        "serial": "ABC123",
        "comments": "central switch",
        "custom_fields": {"zabbix_hostid": "10917"},
    }]))
    monkeypatch.setattr(NetBoxClient, "get_device", AsyncMock(return_value={
        "id": 101,
        "name": "SW-ACCESS-LAN",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "role": {"id": 2, "name": "Switch"},
        "device_type": {"id": 3, "model": "Cisco 2960"},
        "primary_ip4": {"id": 77, "address": "10.0.0.24/32"},
        "serial": "ABC123",
        "comments": "central switch",
        "custom_fields": {"zabbix_hostid": "10917"},
    }))
    monkeypatch.setattr(NetBoxClient, "list_vlans", AsyncMock(return_value=[{
        "id": 201,
        "vid": 10,
        "name": "CORP",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "description": "corporate vlan",
    }]))
    monkeypatch.setattr(NetBoxClient, "get_vlan", AsyncMock(return_value={
        "id": 201,
        "vid": 10,
        "name": "CORP",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "description": "corporate vlan",
    }))
    monkeypatch.setattr(NetBoxClient, "list_prefixes", AsyncMock(return_value=[{
        "id": 301,
        "prefix": "10.0.0.0/24",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "vlan": {"id": 201, "vid": 10, "name": "CORP"},
        "description": "main network",
    }]))
    monkeypatch.setattr(NetBoxClient, "get_prefix", AsyncMock(return_value={
        "id": 301,
        "prefix": "10.0.0.0/24",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "vlan": {"id": 201, "vid": 10, "name": "CORP"},
        "description": "main network",
    }))


def test_request_validation_and_blocklist():
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

    assert payload.ip == "10.0.0.24/32"
    assert payload.normalized_device_name() == "SW-CCO-GDS7830"
    assert payload.is_blocked_for_auto_create() is False


@pytest.mark.parametrize(
    "hostname",
    ["DISC_01", "Discovered Something", "10.0.0.24"],
)
def test_blocklist_hostnames(hostname):
    payload = SyncDeviceRequest(
        hostid="10917",
        hostname=hostname,
        ip="10.0.0.24",
        fabricante="GENERICO",
        modelo="Switch Gerenciavel Generico",
        site_id=1,
        role_id=2,
    )

    assert payload.is_blocked_for_auto_create() is True


def test_missing_required_role_id():
    with pytest.raises(ValidationError):
        SyncDeviceRequest(
            hostid="10917",
            hostname="SW-CCO-GDS7830",
            ip="10.0.0.24",
            fabricante="GENERICO",
            modelo="Switch Gerenciavel Generico",
            site_id=1,
        )


def test_root_renders_dashboard(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_dashboard_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/", follow_redirects=False)

    assert response.status_code == 200
    assert "Rede" in response.text
    assert "Configurar integrações" in response.text
    assert "Conectores centrais" in response.text


def test_dashboard_route_renders_dashboard(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_dashboard_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 200
    assert "Atalhos operacionais" in response.text
    assert "Varredura SNMP" in response.text


def test_root_head_returns_ok(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_dashboard_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.head("/", follow_redirects=False)

    assert response.status_code == 200


def test_settings_page_renders(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/settings", follow_redirects=False)

    assert response.status_code == 200
    assert "Configuracoes" in response.text
    assert "NetBox" in response.text


def test_discovery_classifier_switch():
    group, subgroup, notes = classify_discovered_device(
        sys_descr="Cisco IOS Software, Catalyst Switch",
        sys_name="SW-ACCESS-LAN",
        sys_object_id=".1.3.6.1.4.1.9",
    )

    assert group == "switches"
    assert subgroup in {"access", "core", "wireless"}
    assert "Matched" in notes


def test_discovery_page_renders(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/discovery", follow_redirects=False)

    assert response.status_code == 200
    assert "Descoberta SNMP" in response.text
    assert "Varredura SNMP" in response.text


def test_management_pages_render(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        devices = client.get("/devices", follow_redirects=False)
        vlans = client.get("/vlans", follow_redirects=False)
        networks = client.get("/networks", follow_redirects=False)
        alerts = client.get("/alerts", follow_redirects=False)
        reports = client.get("/reports", follow_redirects=False)

    assert devices.status_code == 200
    assert "Devices cadastrados" in devices.text
    assert vlans.status_code == 200
    assert "VLANs cadastradas" in vlans.text
    assert networks.status_code == 200
    assert "Redes e prefixes" in networks.text
    assert alerts.status_code == 200
    assert "Alertas ativos" in alerts.text
    assert reports.status_code == 200
    assert "Relatório executivo" in reports.text


def test_api_alerts_returns_json(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/api/alerts", follow_redirects=False)

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["alerts"][0]["name"] == "Link down"


def test_allowed_client_cidrs_normalize():
    settings = Settings(
        netbox_url="http://10.254.0.15:8000",
        netbox_token="Bearer test-token",
        sync_api_key="test-api-key",
        allowed_client_cidrs="127.0.0.1/32, 10.0.0.0/24,10.254.0.0/24,10.0.0.115/32",
    )

    assert settings.allowed_client_cidrs == "127.0.0.1/32,10.0.0.0/24,10.254.0.0/24,10.0.0.115/32"
    assert len(settings.allowed_client_networks()) == 4
