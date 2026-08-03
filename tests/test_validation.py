import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.models import SyncDeviceRequest


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


def test_root_redirects_to_docs(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "/docs"


def test_root_head_redirects_to_docs(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.head("/", follow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"] == "/docs"
