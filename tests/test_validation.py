import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock

from app.config import Settings, get_settings
from app import new_main
from app import snmp_probe
from app.main import app
from app import discovery as discovery_module
from app.discovery import DiscoveredDevice, classify_discovered_device, scan_network
from app.models import SyncDeviceRequest
from app.netbox_client import NetBoxClient
from app.services import SyncOutcome, sync_device
from app.zabbix_client import ZabbixClient


def _mock_dashboard_clients(monkeypatch):
    monkeypatch.setattr(NetBoxClient, "health_status", AsyncMock(return_value=True))
    async def _count(path: str):
        mapping = {
            "/api/dcim/devices/": 7,
            "/api/dcim/interfaces/": 19,
            "/api/ipam/ip-addresses/": 23,
            "/api/ipam/prefixes/": 11,
            "/api/ipam/vlans/": 5,
            "/api/dcim/sites/": 2,
            "/api/dcim/racks/": 4,
        }
        return mapping.get(path, 0)

    monkeypatch.setattr(NetBoxClient, "count", AsyncMock(side_effect=_count))
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
    }, {
        "id": 102,
        "name": "NB-13-01",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "role": {"id": 3, "name": "Workstation"},
        "device_type": {
            "id": 4,
            "model": "IdeaPad 1 15IAU7",
            "manufacturer": {"id": 9, "name": "LENOVO"},
        },
        "primary_ip4": {"id": 78, "address": "10.0.0.143/32"},
        "serial": "PE0D7GMQ",
        "comments": "notebook corporativo",
        "custom_fields": {"zabbix_hostid": "11223"}
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
    monkeypatch.setattr(NetBoxClient, "list_interfaces", AsyncMock(return_value=[{
        "id": 501,
        "name": "ge-0/0/1",
        "description": "uplink core",
        "enabled": True,
        "type": {"value": "1000base-t"},
        "mode": {"value": "tagged"},
        "untagged_vlan": {"id": 201, "vid": 10, "name": "CORP"},
        "mac_address": "00:11:22:33:44:55",
    }]))
    monkeypatch.setattr(NetBoxClient, "list_ip_addresses", AsyncMock(return_value=[{
        "id": 601,
        "address": "10.0.0.24/32",
        "status": {"value": "active"},
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": 501,
        "tenant": {"name": "Operacao"},
        "role": {"name": "Primary"},
        "description": "IP de gerencia",
    }]))
    monkeypatch.setattr(NetBoxClient, "get_interface", AsyncMock(return_value={
        "id": 501,
        "name": "mgmt0",
        "device": {"id": 101, "name": "SW-ACCESS-LAN"},
    }))
    monkeypatch.setattr(NetBoxClient, "create_prefix", AsyncMock(return_value={
        "id": 901,
        "prefix": "10.0.0.0/24",
        "status": {"value": "active"},
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
    ["DISC_01", "disc_01", "Discovered Something", "10.0.0.24"],
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


@pytest.mark.anyio
async def test_sync_device_updates_existing_device_by_id(monkeypatch):
    client = NetBoxClient("http://netbox.local", "Bearer token", 5.0)
    monkeypatch.setattr(NetBoxClient, "find_manufacturer_by_slug", AsyncMock(return_value={"id": 11, "name": "Intelbras"}))
    monkeypatch.setattr(
        NetBoxClient,
        "find_device_types",
        AsyncMock(return_value=[{"id": 22, "model": "SF 2400 QR+", "manufacturer": {"id": 11, "name": "Intelbras"}}]),
    )
    monkeypatch.setattr(
        NetBoxClient,
        "get_device",
        AsyncMock(return_value={
            "id": 101,
            "name": "SW-OLD-NAME",
            "status": {"value": "planned"},
            "site": {"id": 1, "name": "ECVITORIA"},
            "role": {"id": 2, "name": "Switch"},
            "device_type": {"id": 22, "model": "SF 2400 QR+", "manufacturer": {"id": 11, "name": "Intelbras"}},
            "primary_ip4": {"id": 77, "address": "10.0.0.24/32"},
            "comments": "",
            "custom_fields": {},
        }),
    )
    update_device_mock = AsyncMock(return_value={
        "id": 101,
        "name": "SW-ACCESS-LAN",
        "status": {"value": "active"},
        "site": {"id": 1, "name": "ECVITORIA"},
        "role": {"id": 2, "name": "Switch"},
        "device_type": {"id": 22, "model": "SF 2400 QR+", "manufacturer": {"id": 11, "name": "Intelbras"}},
        "primary_ip4": {"id": 77, "address": "10.0.0.24/32"},
        "comments": "updated from scan",
        "custom_fields": {"zabbix_hostid": "10917"},
    })
    monkeypatch.setattr(NetBoxClient, "update_device", update_device_mock)
    monkeypatch.setattr(NetBoxClient, "find_interface", AsyncMock(return_value={"id": 501, "name": "mgmt0", "mac_address": "00:11:22:33:44:55"}))
    monkeypatch.setattr(NetBoxClient, "update_interface", AsyncMock(return_value={"id": 501, "name": "mgmt0", "mac_address": "AA:BB:CC:DD:EE:FF"}))
    monkeypatch.setattr(NetBoxClient, "find_mac_addresses", AsyncMock(return_value=[]))
    monkeypatch.setattr(NetBoxClient, "create_mac_address", AsyncMock(return_value={"id": 801, "mac_address": "AA:BB:CC:DD:EE:FF"}))
    monkeypatch.setattr(NetBoxClient, "update_mac_address", AsyncMock(return_value={"id": 801, "mac_address": "AA:BB:CC:DD:EE:FF"}))
    monkeypatch.setattr(NetBoxClient, "find_ip_address", AsyncMock(return_value={"id": 701, "address": "10.0.0.24/32", "assigned_object_type": "dcim.interface", "assigned_object_id": 501}))
    monkeypatch.setattr(NetBoxClient, "update_ip_address", AsyncMock(return_value={"id": 701, "address": "10.0.0.24/32", "assigned_object_type": "dcim.interface", "assigned_object_id": 501}))
    monkeypatch.setattr(NetBoxClient, "get_site", AsyncMock(return_value={"id": 1}))
    monkeypatch.setattr(NetBoxClient, "get_device_role", AsyncMock(return_value={"id": 2}))

    payload = SyncDeviceRequest(
        hostid="10.0.0.24",
        hostname="SW-ACCESS-LAN",
        display_name="SW-ACCESS-LAN",
        ip="10.0.0.24",
        fabricante="Intelbras",
        modelo="SF 2400 QR+",
        site_id=1,
        role_id=2,
        netbox_device_id=101,
        mac_address="AA:BB:CC:DD:EE:FF",
        comments_summary="updated from scan",
        netbox_status="active",
    )

    outcome = await sync_device(payload, client, default_site_id=1, dry_run=False)

    assert outcome.success is True
    assert outcome.action == "updated"
    assert outcome.device_id == 101
    assert update_device_mock.await_count >= 1
    assert client.get_device is not None


def test_mac_normalization_is_consistent():
    assert new_main._normalize_mac_text("0X808554007B92") == "80:85:54:00:7B:92"
    assert new_main._normalize_mac_text("000E1E9A73D0") == "00:0E:1E:9A:73:D0"
    assert new_main._normalize_mac_text("00:0e:1e:9a:73:d0") == "00:0E:1E:9A:73:D0"


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
    # Configuracao de integracoes verificada por outros marcadores abaixo
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
    assert "Configuracoes de integracao" in response.text
    assert "NetBox" in response.text
    assert "Salvar configuracoes" in response.text
    assert "E-mail de alertas" in response.text
    assert "Servidor SMTP" in response.text
    assert "Alerta sonoro" in response.text
    assert "sound_min_severity" in response.text
    assert "Dashboard CPD" in response.text
    assert "cpd_critical_devices" in response.text
    assert "Servidores, roteadores e switches criticos" in response.text


def test_discovery_classifier_switch():
    group, subgroup, notes = classify_discovered_device(
        sys_descr="Cisco IOS Software, Catalyst Switch",
        sys_name="SW-ACCESS-LAN",
        sys_object_id=".1.3.6.1.4.1.9",
    )

    assert group == "switches"
    assert subgroup in {"access", "core", "wireless"}
    assert "Matched" in notes


def test_discovery_status_badges_use_distinct_colors():
    novo_badge = new_main._render_status_badge("Novo")
    criado_badge = new_main._render_status_badge("Criado")
    atualizado_badge = new_main._render_status_badge("Atualizado")

    assert "#f59e0b" in novo_badge
    assert "#db2777" in criado_badge
    assert "#7c3aed" in atualizado_badge
    assert novo_badge != criado_badge


def test_nmap_grepable_output_parser_and_inventory_merge():
    live_hosts = discovery_module._parse_nmap_grepable_output(
        """
Host: 10.0.0.1 (core-switch)	Status: Up
Host: 10.0.0.2 ()	Status: Up
Host: 10.0.0.3 Status: Down
        """.strip()
    )
    snmp_devices = [
        DiscoveredDevice(
            ip="10.0.0.1",
            reachable=True,
            manufacturer="Intelbras",
            model="SF 2400 QR+",
            device_type="switch",
            sys_descr="Switch Gerenciavel Generico",
            sys_name="SW-ACCESS-LAN",
            sys_object_id="1.3.6.1.4.1.26138",
            if_number="24",
            hr_memory_size="1024",
            ucd_load_1="2.5",
            group="switches",
            subgroup="access",
            notes="SNMP ok",
        )
    ]
    merged = discovery_module._merge_inventory(live_hosts, snmp_devices)

    assert len(live_hosts) == 2
    assert merged[0].ip == "10.0.0.1"
    assert merged[0].group == "switches"
    assert merged[1].ip == "10.0.0.2"
    assert merged[1].group == "hosts"
    assert merged[1].notes == "Descoberto via ARP/Nmap"


@pytest.mark.parametrize(
    "sys_descr, sys_name, expected_group, expected_subgroup",
    [
        ("HP LaserJet Pro printer", "PRN-01", "printers", "office"),
        ("KYOCERA Document Solutions Printing System", "PRN-02", "printers", "office"),
        ("Grandstream GWN access point", "AP-01", "aps", "indoor"),
        ("Hikvision IP camera", "CAM-01", "cameras", "ip"),
        ("Intelbras DVR recorder", "REC-01", "recorders", "dvr"),
    ],
)
def test_discovery_classifier_additional_groups(sys_descr, sys_name, expected_group, expected_subgroup):
    group, subgroup, notes = classify_discovered_device(
        sys_descr=sys_descr,
        sys_name=sys_name,
        sys_object_id="1.3.6.1.4.1.1",
    )

    assert group == expected_group
    assert subgroup == expected_subgroup
    assert "Matched" in notes


@pytest.mark.anyio
async def test_discovery_scan_handles_partial_snmp_failure(monkeypatch):
    async def fake_scan_single_ip(ip: str, community: str, **kwargs):
        if ip.endswith(".2"):
            raise RuntimeError("timeout")
        return DiscoveredDevice(
            ip=ip,
            reachable=True,
            manufacturer="MikroTik",
            model="CCR",
            device_type="router",
            sys_descr="MikroTik CCR",
            sys_name="CCR-01",
            sys_object_id="1.3.6.1.4.1.14988",
            if_number="12",
            hr_memory_size="1024",
            ucd_load_1="2.5",
            group="routers",
            subgroup="core",
            notes="ok",
        )

    monkeypatch.setattr(discovery_module, "_scan_single_ip", fake_scan_single_ip, raising=True)
    payload = await scan_network("10.0.0.0/30", "public", timeout=0.1, retries=0, max_hosts=4096, concurrency=2)

    assert payload["network"] == "10.0.0.0/30"
    assert payload["count"] == 1
    assert payload["devices"][0]["ip"] == "10.0.0.1"


@pytest.mark.anyio
async def test_discovery_scan_allows_common_private_subnet(monkeypatch):
    async def fake_scan_single_ip(ip: str, community: str, **kwargs):
        return None

    monkeypatch.setattr(discovery_module, "_scan_single_ip", fake_scan_single_ip, raising=True)
    payload = await scan_network("10.0.0.0/24", "public", timeout=0.1, retries=0, max_hosts=4096, concurrency=4)

    assert payload["network"] == "10.0.0.0/24"
    assert payload["count"] == 0


@pytest.mark.anyio
async def test_discovery_scan_ignores_max_hosts_limit(monkeypatch):
    async def fake_scan_single_ip(ip: str, community: str, **kwargs):
        return None

    monkeypatch.setattr(discovery_module, "_scan_single_ip", fake_scan_single_ip, raising=True)
    monkeypatch.setattr(discovery_module, "save_last_scan", lambda payload: None, raising=True)
    monkeypatch.setattr(discovery_module, "save_scan_progress", lambda payload: None, raising=True)
    monkeypatch.setattr(discovery_module, "load_scan_progress", discovery_module._default_scan_progress_state, raising=True)
    payload = await scan_network("10.0.0.0/24", "public", timeout=0.1, retries=0, max_hosts=1, concurrency=4)

    assert payload["network"] == "10.0.0.0/24"
    assert payload["count"] == 0


def test_discovery_page_renders(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    monkeypatch.setattr(
        new_main,
        "load_scan_progress",
        lambda: {
            "scan_id": "scan-1",
            "network": "10.0.0.0/24",
            "status": "running",
            "phase": "snmp_scan",
            "message": "5 de 254 hosts processados",
            "total_hosts": 254,
            "processed_hosts": 5,
            "alive_hosts": 227,
            "found_devices": 2,
            "percentage": 2,
            "started_at": "2026-08-04T00:00:00Z",
            "updated_at": "2026-08-04T00:00:10Z",
            "finished_at": "",
            "last_ip": "10.0.0.5",
        },
    )
    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scanned_at": "2026-08-04T00:00:00Z",
            "devices": [
                {
                    "ip": "10.0.0.24",
                    "sys_name": "AP-01",
                    "manufacturer": "Grandstream",
                    "model": "GWN7630",
                    "device_type": "wireless_ap",
                    "sys_descr": "Grandstream GWN access point",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                    "group": "aps",
                    "subgroup": "indoor",
                    "include": True,
                    "sys_object_id": "1.3.6.1.4.1.42397",
                }
            ],
        },
    )

    with TestClient(app) as client:
        response = client.get("/discovery", follow_redirects=False)

    assert response.status_code == 200
    assert "Descoberta SNMP" in response.text
    assert "Varredura SNMP" in response.text
    assert "Progresso da varredura" in response.text
    assert "Status sistema" in response.text
    assert "Marcar / desmarcar todos" in response.text
    assert "MAC" in response.text
    assert "Grupo" in response.text
    assert "Subgrupo" in response.text
    assert "discovery-scan-overlay" in response.text
    assert "discovery-scan-modal" in response.text
    assert "Varredura SNMP em andamento" in response.text
    assert "discovery-save-form" in response.text
    assert "Salvando classificacao" in response.text
    assert "discovery-save-modal-title" in response.text
    assert "discovery-save-modal-spinner" in response.text
    assert "Classificacao salva com sucesso" in response.text
    assert "OK" in response.text
    assert "5 de 254 hosts processados" in response.text
    assert "227 hosts vivos" in response.text
    assert "Salvar classificacao" in response.text
    assert "Atualizar dados" in response.text
    assert "Incluir" in response.text


def test_discovery_progress_endpoint(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    monkeypatch.setattr(
        new_main,
        "load_scan_progress",
        lambda: {
            "scan_id": "scan-1",
            "network": "10.0.0.0/24",
            "status": "running",
            "phase": "snmp_scan",
            "message": "10 de 254 hosts processados",
            "total_hosts": 254,
            "processed_hosts": 10,
            "alive_hosts": 227,
            "found_devices": 4,
            "percentage": 4,
            "started_at": "2026-08-04T00:00:00Z",
            "updated_at": "2026-08-04T00:00:10Z",
            "finished_at": "",
            "last_ip": "10.0.0.10",
        },
    )

    with TestClient(app) as client:
        response = client.get("/discovery/progress", follow_redirects=False)

    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert response.json()["processed_hosts"] == 10


def test_discovery_scan_marks_updated_and_pending_inventory_status(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    saved_payloads = {}

    async def fake_scan_network(network, community, **kwargs):
        return {
            "network": network,
            "count": 2,
            "alive_hosts": 2,
            "snmp_devices": 2,
            "scanned_at": "2026-08-06T18:30:00Z",
            "devices": [
                {
                    "ip": "10.0.0.24",
                    "sys_name": "SW-ACCESS-LAN",
                    "manufacturer": "Intelbras",
                    "model": "S2328G-A",
                    "device_type": "switch",
                    "sys_descr": "INTELBRAS Platform Software",
                    "group": "switches",
                    "subgroup": "access",
                    "include": True,
                    "sys_object_id": "1.3.6.1.4.1.26138",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                },
                {
                    "ip": "10.0.0.25",
                    "sys_name": "AP-01",
                    "manufacturer": "Grandstream",
                    "model": "GWN7630",
                    "device_type": "wireless_ap",
                    "sys_descr": "Grandstream GWN access point",
                    "group": "aps",
                    "subgroup": "indoor",
                    "include": True,
                    "sys_object_id": "1.3.6.1.4.1.42397",
                    "mac_address": "11:22:33:44:55:66",
                },
            ],
        }

    async def fake_find_devices_by_ip(ip_value: str):
        if ip_value == "10.0.0.24":
            return [
                {
                    "id": 101,
                    "name": "SW-ACCESS-LAN",
                    "device_type": {
                        "manufacturer": {"name": "Intelbras"},
                        "model": "S2328G-A",
                    },
                    "interface_count": 24,
                }
            ]
        if ip_value == "10.0.0.25":
            return [
                {
                    "id": 202,
                    "name": "AP-01",
                    "device_type": {
                        "manufacturer": {"name": "Grandstream"},
                        "model": "GWN7630",
                    },
                    "interface_count": 8,
                }
            ]
        return []

    async def fake_find_devices_by_name(name: str):
        if name == "SW-ACCESS-LAN":
            return await fake_find_devices_by_ip("10.0.0.24")
        if name == "AP-01":
            return await fake_find_devices_by_ip("10.0.0.25")
        return []

    async def fake_list_interfaces(params=None):
        if params and str(params.get("device_id")) == "101":
            return [{"id": 501, "name": "mgmt0", "mac_address": "AA:BB:CC:DD:EE:FF"}]
        if params and str(params.get("device_id")) == "202":
            return [{"id": 601, "name": "mgmt0", "mac_address": "00:11:22:33:44:00"}]
        return []

    monkeypatch.setattr(new_main, "scan_network", fake_scan_network)
    monkeypatch.setattr(NetBoxClient, "find_devices_by_ip", AsyncMock(side_effect=fake_find_devices_by_ip))
    monkeypatch.setattr(NetBoxClient, "find_devices_by_name", AsyncMock(side_effect=fake_find_devices_by_name))
    monkeypatch.setattr(NetBoxClient, "list_interfaces", AsyncMock(side_effect=fake_list_interfaces))
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: saved_payloads.__setitem__("scan", payload))

    with TestClient(app) as client:
        response = client.post(
            "/discovery/scan",
            data={
                "network": "10.0.0.0/24",
                "community": "public",
                "timeout": "1.0",
                "retries": "0",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Atualizado" in response.text
    assert "Pendente atualização" in response.text
    assert saved_payloads["scan"]["devices"][0]["inventory_status"] == "Atualizado"
    assert saved_payloads["scan"]["devices"][1]["inventory_status"] == "Pendente atualização"


def test_discovery_scan_creates_ipam_prefix_from_network(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    created_prefixes = []

    async def fake_scan_network(network, community, **kwargs):
        return {
            "network": network,
            "count": 0,
            "alive_hosts": 0,
            "snmp_devices": 0,
            "scanned_at": "2026-08-06T18:30:00Z",
            "devices": [],
        }

    async def fake_list_prefixes(params=None):
        return []

    async def fake_create_prefix(payload):
        created_prefixes.append(payload)
        return {"id": 901, **payload}

    monkeypatch.setattr(new_main, "scan_network", fake_scan_network)
    monkeypatch.setattr(NetBoxClient, "list_prefixes", AsyncMock(side_effect=fake_list_prefixes))
    monkeypatch.setattr(NetBoxClient, "create_prefix", AsyncMock(side_effect=fake_create_prefix))
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: None)

    with TestClient(app) as client:
        response = client.post(
            "/discovery/scan",
            data={
                "network": "10.0.0.0/24",
                "community": "public",
                "timeout": "1.0",
                "retries": "0",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert created_prefixes[0]["prefix"] == "10.0.0.0/24"
    assert "criado no IPAM" in response.text


def test_discovery_save_renders_success_and_persists_selection(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    saved_payloads = {}
    async def fake_find_devices_by_ip(ip_value: str):
        if ip_value == "10.0.0.24":
            return [{"id": 101, "name": "SW-ACCESS-LAN"}]
        return []

    async def fake_find_devices_by_name(name: str):
        if name == "AP-01":
            return []
        return []

    async def fake_list_interfaces(params=None):
        if params and str(params.get("device_id")) == "101":
            return [{"id": 501, "name": "eth0", "mac_address": "AA:BB:CC:DD:EE:FF"}]
        return []

    async def fake_sync_device(payload, client, default_site_id, dry_run=False):
        if payload.ip == "10.0.0.24/32":
            return SyncOutcome(
                success=True,
                action="updated",
                device_id=101,
                device_name="SW-ACCESS-LAN",
                manufacturer_id=1,
                device_type_id=2,
                interface_id=3,
                ip_address_id=4,
                message="Synchronization completed successfully.",
            )
        return SyncOutcome(
            success=True,
            action="created",
            device_id=202,
            device_name="AP-01",
            manufacturer_id=1,
            device_type_id=2,
            interface_id=3,
            ip_address_id=4,
            created_device=True,
            message="Synchronization completed successfully.",
        )

    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scanned_at": "2026-08-04T00:00:00Z",
            "devices": [
                {
                    "ip": "10.0.0.24",
                    "sys_name": "SW-ACCESS-LAN",
                    "manufacturer": "Intelbras",
                    "model": "SF 2400 QR+",
                    "device_type": "switch",
                    "sys_descr": "Switch Gerenciavel Generico",
                    "group": "switches",
                    "subgroup": "access",
                    "include": True,
                    "sys_object_id": "1.3.6.1.4.1.26138",
                },
                {
                    "ip": "10.0.0.25",
                    "sys_name": "AP-01",
                    "manufacturer": "Grandstream",
                    "model": "GWN7630",
                    "device_type": "wireless_ap",
                    "sys_descr": "Grandstream GWN access point",
                    "group": "aps",
                    "subgroup": "indoor",
                    "include": True,
                    "sys_object_id": "1.3.6.1.4.1.42397",
                }
            ],
        },
    )
    monkeypatch.setattr(NetBoxClient, "find_devices_by_ip", AsyncMock(side_effect=fake_find_devices_by_ip))
    monkeypatch.setattr(NetBoxClient, "find_devices_by_name", AsyncMock(side_effect=fake_find_devices_by_name))
    monkeypatch.setattr(NetBoxClient, "list_interfaces", AsyncMock(side_effect=fake_list_interfaces))
    monkeypatch.setattr(new_main, "sync_device", AsyncMock(side_effect=fake_sync_device))
    monkeypatch.setattr(new_main, "save_group_selections", lambda payload: saved_payloads.__setitem__("groups", payload))
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: saved_payloads.__setitem__("scan", payload))

    with TestClient(app) as client:
        response = client.post(
            "/discovery/save",
            data={
                "include_10_0_0_24": "on",
                "include_10_0_0_25": "on",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Classificacao gravada com sucesso" in response.text
    assert saved_payloads["groups"]["count"] == 2
    assert saved_payloads["scan"]["devices"][0]["system_status"] == "Atualizado"
    assert saved_payloads["scan"]["devices"][1]["system_status"] == "Criado"
    assert saved_payloads["scan"]["devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:FF"


def test_discovery_save_prefers_scanned_mac_for_existing_devices(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    saved_payloads = {}
    synced_payloads = []

    async def fake_find_devices_by_ip(ip_value: str):
        if ip_value == "10.0.0.18":
            return [{"id": 321, "name": "Atendimento SMV"}]
        return []

    async def fake_find_devices_by_name(name: str):
        if name == "Atendimento SMV":
            return [{"id": 321, "name": "Atendimento SMV"}]
        return []

    async def fake_list_interfaces(params=None):
        if params and str(params.get("device_id")) == "321":
            return [{"id": 67, "name": "mgmt0", "mac_address": "00:11:22:33:44:55"}]
        return []

    async def fake_sync_device(payload, client, default_site_id, dry_run=False):
        synced_payloads.append(payload)
        return SyncOutcome(
            success=True,
            action="updated",
            device_id=321,
            device_name=payload.hostname,
            manufacturer_id=1,
            device_type_id=2,
            interface_id=67,
            ip_address_id=4,
            message="Synchronization completed successfully.",
        )

    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scanned_at": "2026-08-04T00:00:00Z",
            "devices": [
                {
                    "ip": "10.0.0.18",
                    "sys_name": "Atendimento SMV",
                    "manufacturer": "Intelbras",
                    "model": "S2328G-A",
                    "device_type": "switch",
                    "sys_descr": "INTELBRAS Platform Software",
                    "group": "switches",
                    "subgroup": "access",
                    "include": True,
                    "netbox_device_id": 321,
                    "system_status": "Cadastrado",
                    "sys_object_id": "1.3.6.1.4.1.26138",
                    "mac_address": "AA:BB:CC:DD:EE:FF",
                }
            ],
        },
    )
    monkeypatch.setattr(NetBoxClient, "find_devices_by_ip", AsyncMock(side_effect=fake_find_devices_by_ip))
    monkeypatch.setattr(NetBoxClient, "find_devices_by_name", AsyncMock(side_effect=fake_find_devices_by_name))
    monkeypatch.setattr(NetBoxClient, "list_interfaces", AsyncMock(side_effect=fake_list_interfaces))
    monkeypatch.setattr(new_main, "sync_device", AsyncMock(side_effect=fake_sync_device))
    monkeypatch.setattr(new_main, "save_group_selections", lambda payload: saved_payloads.__setitem__("groups", payload))
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: saved_payloads.__setitem__("scan", payload))
    monkeypatch.setattr(
        new_main,
        "load_last_probe",
        lambda: {
            "last_probe": {
                "ip": "10.0.0.18",
                "ports": [
                    {
                        "index": "1",
                        "name": "ge-0/0/1",
                        "description": "uplink core",
                        "alias": "uplink core",
                        "admin_status": "up",
                        "oper_status": "up",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "speed_bps": "1.00 Gbps",
                    }
                ],
            }
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/discovery/save",
            data={
                "include_10_0_0_18": "on",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert len(synced_payloads) == 1
    assert synced_payloads[0].netbox_device_id == 321
    assert synced_payloads[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert synced_payloads[0].ports and synced_payloads[0].ports[0]["name"] == "ge-0/0/1"
    assert saved_payloads["scan"]["devices"][0]["discovered_mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert saved_payloads["scan"]["devices"][0]["netbox_mac_address"] == "00:11:22:33:44:55"


def test_discovery_update_only_targets_saved_devices(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    synced_payloads = []

    async def fake_sync_device(payload, client, default_site_id, dry_run=False):
        synced_payloads.append(payload)
        return SyncOutcome(
            success=True,
            action="updated",
            device_id=payload.netbox_device_id or 101,
            device_name=payload.hostname,
            manufacturer_id=1,
            device_type_id=2,
            interface_id=3,
            ip_address_id=4,
            message="Synchronization completed successfully.",
        )

    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scanned_at": "2026-08-04T00:00:00Z",
            "devices": [
                {
                    "ip": "10.0.0.18",
                    "sys_name": "Atendimento SMV",
                    "manufacturer": "Intelbras",
                    "model": "S2328G-A",
                    "device_type": "switch",
                    "sys_descr": "INTELBRAS Platform Software",
                    "group": "switches",
                    "subgroup": "core",
                    "include": True,
                    "netbox_device_id": 321,
                    "system_status": "Cadastrado",
                    "sys_object_id": "1.3.6.1.4.1.26138",
                },
                {
                    "ip": "10.0.0.23",
                    "sys_name": "SW-24-FUTEBOL-PROF",
                    "manufacturer": "TP-Link",
                    "model": "SG 5204 MR",
                    "device_type": "switch",
                    "sys_descr": "SG 5204 MR L2+ Gigabit Ethernet Switch",
                    "group": "switches",
                    "subgroup": "access",
                    "include": True,
                    "system_status": "Novo",
                    "sys_object_id": "1.3.6.1.4.1.11863",
                },
            ],
        },
    )
    monkeypatch.setattr(new_main, "sync_device", AsyncMock(side_effect=fake_sync_device))
    monkeypatch.setattr(new_main, "save_group_selections", lambda payload: None)
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: None)

    with TestClient(app) as client:
        response = client.post(
            "/discovery/save",
            data={
                "operation": "update",
                "include_10_0_0_18": "on",
                "include_10_0_0_23": "on",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Classificacao gravada com sucesso" in response.text or "Atualizacao concluida com sucesso" in response.text
    assert len(synced_payloads) == 1
    assert synced_payloads[0].netbox_device_id == 321
    assert synced_payloads[0].hostname == "Atendimento SMV"


def test_discovery_update_refreshes_existing_device_from_snmp(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()

    saved_payloads = {}
    synced_payloads = []
    probe_payload = {
        "ip": "10.0.0.40",
        "sys_name": "SW-40-CORE",
        "sys_descr": "Managed switch core",
        "sys_object_id": "1.3.6.1.4.1.99999",
        "if_number": "24",
        "hr_memory_size": "2048",
        "notes": "interfaces=24 | mac=AA:BB:CC:DD:EE:FF",
        "ports": [
            {
                "index": "1",
                "name": "mgmt0",
                "description": "management",
                "alias": "",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "admin_status": "up",
                "oper_status": "up",
                "speed_bps": "1.00 Gbps",
            }
        ],
    }

    async def fake_probe_snmp_device(ip_value: str, community: str, *, timeout: float, retries: int, max_ports: int):
        if ip_value == "10.0.0.40":
            return probe_payload
        raise AssertionError(f"Unexpected probe for {ip_value}")

    async def fake_find_devices_by_ip(ip_value: str):
        if ip_value == "10.0.0.40":
            return [{"id": 401, "name": "SW-40-CORE"}]
        return []

    async def fake_find_devices_by_name(name: str):
        if name == "SW-40-CORE":
            return [{"id": 401, "name": "SW-40-CORE"}]
        return []

    async def fake_list_interfaces(params=None):
        if params and str(params.get("device_id")) == "401":
            return [{"id": 501, "name": "mgmt0", "mac_address": "00:11:22:33:44:55"}]
        return []

    async def fake_sync_device(payload, client, default_site_id, dry_run=False):
        synced_payloads.append(payload)
        return SyncOutcome(
            success=True,
            action="updated",
            device_id=401,
            device_name=payload.hostname,
            manufacturer_id=1,
            device_type_id=2,
            interface_id=3,
            ip_address_id=4,
            message="Synchronization completed successfully.",
        )

    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scan_community": "public",
            "scan_timeout": 1.0,
            "scan_retries": 0,
            "scan_max_ports": 48,
            "scanned_at": "2026-08-04T00:00:00Z",
            "devices": [
                {
                    "ip": "10.0.0.40",
                    "sys_name": "SW-40-CORE",
                    "manufacturer": "Intelbras",
                    "model": "S2328G-A",
                    "device_type": "switch",
                    "sys_descr": "Managed switch core",
                    "group": "switches",
                    "subgroup": "core",
                    "include": True,
                    "netbox_device_id": 401,
                    "system_status": "Cadastrado",
                    "sys_object_id": "1.3.6.1.4.1.26138",
                    "mac_address": "00:11:22:33:44:55",
                },
                {
                    "ip": "10.0.0.42",
                    "sys_name": "SW-42-ACCESS",
                    "manufacturer": "TP-Link",
                    "model": "SG 5204 MR",
                    "device_type": "switch",
                    "sys_descr": "Access switch",
                    "group": "switches",
                    "subgroup": "access",
                    "include": True,
                    "system_status": "Novo",
                    "sys_object_id": "1.3.6.1.4.1.11863",
                },
            ],
        },
    )
    monkeypatch.setattr(new_main, "probe_snmp_device", AsyncMock(side_effect=fake_probe_snmp_device))
    monkeypatch.setattr(NetBoxClient, "find_devices_by_ip", AsyncMock(side_effect=fake_find_devices_by_ip))
    monkeypatch.setattr(NetBoxClient, "find_devices_by_name", AsyncMock(side_effect=fake_find_devices_by_name))
    monkeypatch.setattr(NetBoxClient, "list_interfaces", AsyncMock(side_effect=fake_list_interfaces))
    monkeypatch.setattr(new_main, "sync_device", AsyncMock(side_effect=fake_sync_device))
    monkeypatch.setattr(new_main, "save_group_selections", lambda payload: saved_payloads.__setitem__("groups", payload))
    monkeypatch.setattr(new_main, "save_last_scan", lambda payload: saved_payloads.__setitem__("scan", payload))

    with TestClient(app) as client:
        response = client.post(
            "/discovery/save",
            data={
                "operation": "update",
                "include_10_0_0_40": "on",
                "include_10_0_0_42": "on",
                "scan_community": "public",
                "scan_timeout": "1.0",
                "scan_retries": "0",
                "scan_max_ports": "48",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert len(synced_payloads) == 1
    assert synced_payloads[0].netbox_device_id == 401
    assert synced_payloads[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert synced_payloads[0].ports and synced_payloads[0].ports[0]["name"] == "mgmt0"
    assert saved_payloads["scan"]["devices"][0]["system_status"] == "Atualizado"
    assert saved_payloads["scan"]["devices"][0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert saved_payloads["scan"]["devices"][1]["system_status"] == "Novo"


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
        device_detail = client.get("/devices/view/101", follow_redirects=False)
        vlans = client.get("/vlans", follow_redirects=False)
        networks = client.get("/networks", follow_redirects=False)
        topology = client.get("/topology", follow_redirects=False)
        alerts = client.get("/alerts", follow_redirects=False)
        reports = client.get("/reports", follow_redirects=False)
        cpd = client.get("/cpd", follow_redirects=False)

    assert devices.status_code == 200
    assert "Devices cadastrados" in devices.text
    assert "Leitura SNMP" in devices.text
    assert device_detail.status_code == 200
    assert "Detalhe do device" in device_detail.text
    assert "Interfaces" in device_detail.text
    assert "Campos personalizados" in device_detail.text
    assert "Visão geral" in device_detail.text
    assert vlans.status_code == 200
    assert "VLANs cadastradas" in vlans.text
    assert networks.status_code == 200
    assert "IPAM" in networks.text
    assert "Redes e prefixes" in networks.text
    assert "IPs em uso" in networks.text
    assert "/devices/view/101" in networks.text
    assert "Mapa da rede" in networks.text
    assert "Tipo da rede" in networks.text
    assert "Mapa da rota" in networks.text
    assert topology.status_code == 200
    assert "Mapa interativo" in topology.text
    assert "topology-svg" in topology.text
    assert "Filtrar device" in topology.text
    assert alerts.status_code == 200
    assert "Alertas ativos" in alerts.text
    assert "Enviar e-mail de alertas" in alerts.text
    assert "playAlertSound" in alerts.text
    assert "soundMinSeverity" in alerts.text
    assert cpd.status_code == 200
    assert "CPD / Painel de operacao" in cpd.text
    assert "cpd-updated" in cpd.text
    assert "Dispositivos criticos" in cpd.text
    assert reports.status_code == 200
    assert "Alertas recentes" in reports.text

def test_devices_page_filters_computers(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/devices?kind=computers", follow_redirects=False)

    assert response.status_code == 200
    assert "Computadores" in response.text
    assert "NB-13-01" in response.text
    assert "SW-ACCESS-LAN" not in response.text

def test_devices_page_filters_computers(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/devices?kind=computers", follow_redirects=False)

    assert response.status_code == 200
    assert "Computadores" in response.text
    assert "NB-13-01" in response.text
    assert "SW-ACCESS-LAN" not in response.text


def test_snmp_page_renders(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    monkeypatch.setattr(
        new_main,
        "load_last_probe",
        lambda: {
            "devices": [],
            "last_probe": {
                "ip": "10.0.0.24",
                "sys_name": "SW-ACCESS-LAN",
                "sys_descr": "Access switch",
                "if_number": "24",
                "hr_memory_size": "1024",
                "processor_load_average": "12.5",
                "ports": [
                    {
                        "index": "1",
                        "name": "Gi0/1",
                        "description": "uplink core",
                        "alias": "uplink",
                        "admin_status": "up",
                        "oper_status": "up",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "speed_bps": "1.00 Gbps",
                    }
                ],
            },
        },
    )

    with TestClient(app) as client:
        response = client.get("/snmp", follow_redirects=False)

    assert response.status_code == 200
    assert "Consulta SNMP" in response.text
    assert "Portas" in response.text
    assert "SW-ACCESS-LAN" in response.text
    assert "aa:bb:cc:dd:ee:ff" in response.text or "AA:BB:CC:DD:EE:FF" in response.text
    assert "MAC" in response.text


def test_snmp_probe_post_renders_success(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    monkeypatch.setattr(new_main, "probe_snmp_device", AsyncMock(return_value={}))
    monkeypatch.setattr(
        new_main,
        "load_last_probe",
        lambda: {
            "devices": [],
            "last_probe": {
                "ip": "10.0.0.24",
                "sys_name": "SW-ACCESS-LAN",
                "sys_descr": "Access switch",
                "if_number": "24",
                "hr_memory_size": "1024",
                "processor_load_average": "12.5",
                "ports": [],
            },
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/snmp/probe",
            data={
                "ip": "10.0.0.24",
                "community": "public",
                "timeout": "1.0",
                "retries": "0",
                "max_ports": "24",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Leitura SNMP atualizada com sucesso" in response.text


def test_clean_value_prefers_pretty_print_for_asn1_like_values():
    class FakeOctetString:
        def prettyPrint(self):
            return "SWC-03-CPD"

        def __getitem__(self, index):
            raise AssertionError("ASN.1 values must not be indexed as sequences")

    assert snmp_probe._clean_value(FakeOctetString()) == "SWC-03-CPD"


def test_snmp_sync_post_sends_ports_to_netbox(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    synced_payloads = []

    async def fake_probe_snmp_device(ip, community, **kwargs):
        return {
            "ip": "10.0.0.24",
            "sys_name": "SW-ACCESS-LAN",
            "sys_descr": "Access switch",
            "sys_object_id": "1.3.6.1.4.1.26138",
            "if_number": "24",
            "hr_memory_size": "1024",
            "processor_load_average": "12.5",
            "notes": "sysName=SW-ACCESS-LAN",
            "ports": [
                {
                    "index": "1",
                    "name": "ge-0/0/1",
                    "description": "uplink core",
                    "alias": "uplink core",
                    "admin_status": "up",
                    "oper_status": "up",
                    "mac_address": "aa:bb:cc:dd:ee:ff",
                    "speed_bps": "1.00 Gbps",
                }
            ],
        }

    async def fake_sync_device(payload, client, default_site_id, dry_run=False):
        synced_payloads.append(payload)
        return SyncOutcome(
            success=True,
            action="updated",
            device_id=101,
            device_name=payload.hostname,
            manufacturer_id=1,
            device_type_id=2,
            interface_id=3,
            ip_address_id=4,
            message="Synchronization completed successfully.",
        )

    monkeypatch.setattr(new_main, "probe_snmp_device", fake_probe_snmp_device)
    monkeypatch.setattr(new_main, "sync_device", fake_sync_device)

    with TestClient(app) as client:
        response = client.post(
            "/snmp/sync",
            data={
                "ip": "10.0.0.24",
                "community": "public",
                "timeout": "1.0",
                "retries": "0",
                "max_ports": "24",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "Leitura SNMP atualizada com sucesso" in response.text
    assert synced_payloads[0].ports and synced_payloads[0].ports[0]["name"] == "ge-0/0/1"
    assert synced_payloads[0].mac_address == "AA:BB:CC:DD:EE:FF"


def test_cpd_dashboard_config_normalization():
    config = new_main._normalize_cpd_dashboard_config({
        "enabled": "yes",
        "title": "CPD Sala NOC",
        "critical_devices": "CORE-01",
        "critical_services": "DNS, DHCP",
        "critical_links": "uplink-core",
        "highlight_severity": "9",
    })

    assert config["enabled"] is True
    assert config["title"] == "CPD Sala NOC"
    assert config["highlight_severity"] == 5


def test_topology_page_renders(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)
    monkeypatch.setattr(
        new_main,
        "load_last_scan",
        lambda: {
            "network": "10.0.0.0/24",
            "scanned_at": "2026-08-07T17:55:55Z",
            "devices": [
                {
                    "ip": "10.0.0.24",
                    "sys_name": "SW-ACCESS-LAN",
                    "group": "switches",
                    "subgroup": "access",
                    "netbox_device_id": "101",
                    "system_status": "Atualizado",
                    "manufacturer": "Intelbras",
                    "model": "SF 2400 QR+",
                },
                {
                    "ip": "10.0.0.25",
                    "sys_name": "SW-CORE-01",
                    "group": "switches",
                    "subgroup": "core",
                    "netbox_device_id": "102",
                    "system_status": "Novo",
                    "manufacturer": "Intelbras",
                    "model": "SF 3200",
                },
            ],
        },
    )
    monkeypatch.setattr(
        new_main,
        "load_last_probe",
        lambda: {
            "devices": [
                {
                    "ip": "10.0.0.24",
                    "sys_name": "SW-ACCESS-LAN",
                    "snmp_mac_address": "00:11:22:33:44:55",
                    "ports": [
                        {"index": "1", "name": "ge-0/0/1", "mac_address": "00:11:22:33:44:55"},
                    ],
                    "lldp_neighbors": [
                        {
                            "local_port_index": "1",
                            "remote_sys_name": "SW-CORE-01",
                            "remote_port_id": "ge-0/0/24",
                            "remote_port_desc": "ge-0/0/24",
                            "remote_chassis_id": "00:11:22:33:44:66",
                        }
                    ],
                },
                {
                    "ip": "10.0.0.25",
                    "sys_name": "SW-CORE-01",
                    "snmp_mac_address": "00:11:22:33:44:66",
                    "ports": [
                        {"index": "24", "name": "ge-0/0/24", "mac_address": "00:11:22:33:44:66"},
                    ],
                    "lldp_neighbors": [
                        {
                            "local_port_index": "24",
                            "remote_sys_name": "SW-ACCESS-LAN",
                            "remote_port_id": "ge-0/0/1",
                            "remote_port_desc": "ge-0/0/1",
                            "remote_chassis_id": "00:11:22:33:44:55",
                        }
                    ],
                },
            ],
            "last_probe": {
                "ip": "10.0.0.24",
                "sys_name": "SW-ACCESS-LAN",
                "lldp_neighbors": [
                    {
                        "local_port_index": "1",
                        "remote_sys_name": "SW-CORE-01",
                        "remote_port_id": "ge-0/0/24",
                        "remote_port_desc": "ge-0/0/24",
                        "remote_chassis_id": "00:11:22:33:44:66",
                    }
                ],
                "ports": [
                    {"index": "1", "name": "ge-0/0/1", "mac_address": "00:11:22:33:44:55"},
                ],
            },
        },
    )
    monkeypatch.setattr(
        NetBoxClient,
        "list_devices",
        AsyncMock(return_value=[
            {
                "id": 101,
                "name": "SW-ACCESS-LAN",
                "status": {"value": "active"},
                "site": {"id": 1, "name": "ECVITORIA"},
                "role": {"id": 2, "name": "Switch"},
                "device_type": {"id": 3, "model": "Intelbras SF 2400 QR+"},
                "primary_ip4": {"id": 77, "address": "10.0.0.24/32"},
                "comments": "access switch",
            },
            {
                "id": 102,
                "name": "SW-CORE-01",
                "status": {"value": "active"},
                "site": {"id": 1, "name": "ECVITORIA"},
                "role": {"id": 2, "name": "Switch"},
                "device_type": {"id": 4, "model": "Intelbras SF 3200"},
                "primary_ip4": {"id": 78, "address": "10.0.0.25/32"},
                "comments": "core switch",
            },
        ]),
    )
    monkeypatch.setattr(
        new_main,
        "load_network_topology",
        lambda: {
            "entries": [
                {
                    "prefix_id": "301",
                    "network_kind": "vlan",
                    "origin_device_id": "101",
                    "origin_interface": "port 1",
                    "origin_mode": "trunk",
                    "next_device_id": "101",
                    "next_interface": "port 7",
                    "next_mode": "tagged",
                    "route_notes": "CCR trunk vlan 50",
                }
            ]
        },
    )

    with TestClient(app) as client:
        response = client.get("/topology", follow_redirects=False)

    assert response.status_code == 200
    assert "Mapa interativo" in response.text
    assert "Dispositivos localizados" in response.text
    assert "Ligações físicas" in response.text
    assert "SW-ACCESS-LAN" in response.text
    assert "SW-CORE-01" in response.text
    assert "LLDP" in response.text
    assert "ge-0/0/1" in response.text
    assert "ge-0/0/24" in response.text


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


def test_private_client_ip_is_allowed(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/topology", headers={"X-Forwarded-For": "192.168.10.25"}, follow_redirects=False)

    assert response.status_code == 200


def test_public_client_ip_is_blocked(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    with TestClient(app) as client:
        response = client.get("/topology", headers={"X-Forwarded-For": "8.8.8.8"}, follow_redirects=False)

    assert response.status_code == 403
    assert response.json()["detail"] == "Client IP not allowed"


def test_alerts_email_send_redirects_with_info(monkeypatch):
    monkeypatch.setenv("NETBOX_URL", "http://10.254.0.15:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "Bearer test-token")
    monkeypatch.setenv("ZABBIX_URL", "http://10.254.0.15/api_jsonrpc.php")
    monkeypatch.setenv("ZABBIX_TOKEN", "Bearer zabbix-token")
    monkeypatch.setenv("SYNC_API_KEY", "test-api-key")
    get_settings.cache_clear()
    _mock_management_clients(monkeypatch)

    async def fake_to_thread(func, *args, **kwargs):
        assert func is new_main.send_alert_email
        return {"subject": "x", "from": "noreply@example.com", "recipients": ["ops@example.com"], "alerts": 1}

    monkeypatch.setattr(new_main.asyncio, "to_thread", fake_to_thread)

    with TestClient(app) as client:
        client.app.state.runtime["email"] = {
            "enabled": True,
            "host": "smtp.example.com",
            "port": 587,
            "username": "infra@example.com",
            "password": "secret",
            "from_address": "infra@example.com",
            "to_addresses": "ops@example.com",
            "use_tls": True,
            "use_ssl": False,
            "subject_prefix": "[infra-sync-api]",
        }
        response = client.post("/alerts/email/send", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"].startswith("/alerts?info=")


def test_alert_sound_config_normalization():
    config = new_main._normalize_alert_sound_config({"enabled": "yes", "min_severity": "9"})

    assert config["enabled"] is True
    assert config["min_severity"] == 5
