import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock

from app.config import Settings, get_settings
from app.main import app
from app.models import SyncDeviceRequest
from app.netbox_client import NetBoxClient
from app.zabbix_client import ZabbixClient


def _mock_dashboard_clients(monkeypatch):
    monkeypatch.setattr(NetBoxClient, "health_status", AsyncMock(return_value=True))
    monkeypatch.setattr(NetBoxClient, "count", AsyncMock(side_effect=[7, 19, 23, 11, 5, 2, 4]))
    monkeypatch.setattr(ZabbixClient, "healthcheck", AsyncMock(return_value=True))
    monkeypatch.setattr(ZabbixClient, "count_hosts", AsyncMock(return_value=14))


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


def test_allowed_client_cidrs_normalize():
    settings = Settings(
        netbox_url="http://10.254.0.15:8000",
        netbox_token="Bearer test-token",
        sync_api_key="test-api-key",
        allowed_client_cidrs="127.0.0.1/32, 10.0.0.0/24,10.254.0.0/24,10.0.0.115/32",
    )

    assert settings.allowed_client_cidrs == "127.0.0.1/32,10.0.0.0/24,10.254.0.0/24,10.0.0.115/32"
    assert len(settings.allowed_client_networks()) == 4
