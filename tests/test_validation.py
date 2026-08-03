import pytest
from pydantic import ValidationError

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

