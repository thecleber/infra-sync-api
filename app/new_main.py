from __future__ import annotations

import copy
import asyncio
import hmac
import ipaddress
import json
import logging
import re
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import parse_qs, quote
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import __version__
from .config import Settings, get_settings
from .email_notifications import EmailNotificationError, normalize_email_config, send_alert_email
from .discovery import classify_discovered_device, infer_device_profile, load_last_scan, load_scan_progress, save_group_selections, save_last_scan, scan_network
from .models import SyncDeviceRequest, ZabbixHostSyncRequest
from .netbox_client import NetBoxClient, NetBoxClientError
from .snmp_probe import load_last_probe, probe_device as probe_snmp_device
from .services import SyncError, sync_device, sync_zabbix_host
from .zabbix_client import ZabbixClient, ZabbixClientError


RUNTIME_CONFIG_PATH = Path("data") / "integrations.json"
TOPOLOGY_CONFIG_PATH = Path("data") / "network_topology.json"


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def default_runtime(settings: Settings) -> dict[str, Any]:
    return {
        "sync_api_key": settings.sync_api_key,
        "refresh": {
            "enabled": True,
            "value": 30,
            "unit": "seconds",
        },
        "netbox": {
            "enabled": bool(settings.netbox_url and settings.netbox_token),
            "url": settings.netbox_url,
            "token": settings.netbox_token,
        },
        "zabbix": {
            "enabled": settings.zabbix_configured(),
            "url": settings.zabbix_url or "",
            "token": settings.zabbix_token or "",
        },
        "glpi": {
            "enabled": False,
            "url": "",
            "token": "",
        },
        "n8n": {
            "enabled": False,
            "url": "",
            "token": "",
        },
        "email": {
            "enabled": False,
            "host": "",
            "port": 587,
            "username": "",
            "password": "",
            "from_address": "",
            "to_addresses": "",
            "use_tls": True,
            "use_ssl": False,
            "subject_prefix": "[infra-sync-api]",
        },
        "alert_sound": {
            "enabled": False,
            "min_severity": 4,
        },
        "cpd_dashboard": {
            "enabled": True,
            "title": "CPD - Painel de saude",
            "critical_devices": "CORE-01, CORE-02, SW-ACCESS-01, SRV-DB-01",
            "critical_services": "DNS, DHCP, AD, VPN",
            "critical_links": "uplink-core, wan-link, backbone",
            "highlight_severity": 4,
        },
    }


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_mac_text(value: Any) -> str:
    cleaned = _normalize_text(value)
    if not cleaned:
        return ""
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        cleaned = cleaned[2:]
        lowered = cleaned.lower()
    if lowered in {"00:00:00:00:00:00", "000000000000", "ff:ff:ff:ff:ff:ff"}:
        return ""
    hex_only = "".join(ch for ch in cleaned if ch.isalnum())
    if len(hex_only) == 12:
        return ":".join(hex_only[i:i + 2] for i in range(0, 12, 2)).upper()
    return cleaned.upper()


def _normalize_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    if cleaned and not cleaned.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return cleaned


def _default_refresh_config() -> dict[str, Any]:
    return {
        "enabled": True,
        "value": 30,
        "unit": "seconds",
    }


def _normalize_refresh_config(raw: Any) -> dict[str, Any]:
    config = _default_refresh_config()
    if not isinstance(raw, dict):
        return config

    config["enabled"] = bool(raw.get("enabled", config["enabled"]))
    unit = _normalize_text(raw.get("unit", config["unit"])).lower()
    if unit not in {"seconds", "minutes", "hours", "days"}:
        unit = config["unit"]
    config["unit"] = unit

    value = raw.get("value", config["value"])
    try:
        normalized_value = int(float(str(value).strip()))
    except (TypeError, ValueError):
        normalized_value = config["value"]
    config["value"] = max(1, normalized_value)
    return config


def _default_alert_sound_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "min_severity": 4,
    }


def _normalize_alert_sound_config(raw: Any) -> dict[str, Any]:
    config = _default_alert_sound_config()
    if not isinstance(raw, dict):
        return config

    config["enabled"] = bool(raw.get("enabled", config["enabled"]))
    try:
        severity = int(str(raw.get("min_severity", config["min_severity"])).strip())
    except (TypeError, ValueError):
        severity = config["min_severity"]
    config["min_severity"] = min(5, max(0, severity))
    return config


def _render_alert_sound_block(config: dict[str, Any]) -> str:
    enabled = "checked" if config.get("enabled") else ""
    try:
        severity_value = int(config.get("min_severity", 4))
    except (TypeError, ValueError):
        severity_value = 4
    severity_value = min(5, max(0, severity_value))
    severity_options = "".join(
        f'<option value="{value}" {"selected" if severity_value == value else ""}>{label}</option>'
        for value, label in (
            (0, "0 - Sem classe"),
            (1, "1 - Informacao"),
            (2, "2 - Aviso"),
            (3, "3 - Media"),
            (4, "4 - Alta"),
            (5, "5 - Desastre"),
        )
    )
    return f"""
        <div class="panel" style="margin-bottom:14px;">
          <h2>Alerta sonoro</h2>
          <p>Reproduz um som no navegador quando surgir um alerta com severidade igual ou superior ao nivel definido.</p>
          <div class="check">
            <input type="checkbox" name="sound_enabled" {enabled} />
            <span>Ativar som para alertas graves</span>
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="sound_min_severity">Nivel minimo</label>
              <select id="sound_min_severity" name="sound_min_severity">
                {severity_options}
              </select>
            </div>
          </div>
        </div>
    """


def _render_cpd_block(config: dict[str, Any]) -> str:
    enabled = "checked" if config.get("enabled") else ""
    title = escape(_normalize_text(config.get("title")))
    devices = escape(_normalize_text(config.get("critical_devices")))
    services = escape(_normalize_text(config.get("critical_services")))
    links = escape(_normalize_text(config.get("critical_links")))
    threshold = min(5, max(0, int(config.get("highlight_severity", 4) or 4)))
    options = "".join(
        f'<option value="{value}" {"selected" if threshold == value else ""}>{label}</option>'
        for value, label in (
            (0, "0 - Sem classe"),
            (1, "1 - Informacao"),
            (2, "2 - Aviso"),
            (3, "3 - Media"),
            (4, "4 - Alta"),
            (5, "5 - Desastre"),
        )
    )
    return f"""
        <div class="panel" id="cpd-dashboard" style="margin-bottom:14px;">
          <h2>Dashboard CPD</h2>
          <p>Tela fixa para sala de operacao, com foco nos servidores, roteadores, switches, links e servicos mais criticos.</p>
          <div class="check">
            <input type="checkbox" name="cpd_enabled" {enabled} />
            <span>Ativar dashboard CPD</span>
          </div>
          <div class="form-grid">
            <div class="field"><label for="cpd_title">Titulo</label><input id="cpd_title" name="cpd_title" type="text" value="{title}" placeholder="CPD - Painel de saude" /></div>
            <div class="field">
              <label for="cpd_highlight_severity">Severidade para destaque</label>
              <select id="cpd_highlight_severity" name="cpd_highlight_severity">
                {options}
              </select>
            </div>
          </div>
          <div class="field"><label for="cpd_critical_devices">Servidores, roteadores e switches criticos</label><textarea id="cpd_critical_devices" name="cpd_critical_devices" placeholder="CORE-01, CORE-02, SRV-DB-01">{devices}</textarea></div>
          <div class="field"><label for="cpd_critical_links">Links criticos</label><textarea id="cpd_critical_links" name="cpd_critical_links" placeholder="uplink-core, wan-link, backbone">{links}</textarea></div>
          <div class="field"><label for="cpd_critical_services">Servicos criticos</label><textarea id="cpd_critical_services" name="cpd_critical_services" placeholder="DNS, DHCP, AD, VPN">{services}</textarea></div>
          <div class="sub" style="margin-top:10px;">A tela CPD atualiza a cada 2 segundos e nao faz logout.</div>
        </div>
    """


def _default_cpd_dashboard_config() -> dict[str, Any]:
    return {
        "enabled": True,
        "title": "CPD - Painel de saude",
        "critical_devices": "CORE-01, CORE-02, SW-ACCESS-01, SRV-DB-01",
        "critical_services": "DNS, DHCP, AD, VPN",
        "critical_links": "uplink-core, wan-link, backbone",
        "highlight_severity": 4,
    }


def _normalize_cpd_dashboard_config(raw: Any) -> dict[str, Any]:
    config = _default_cpd_dashboard_config()
    if not isinstance(raw, dict):
        return config

    config["enabled"] = bool(raw.get("enabled", config["enabled"]))
    config["title"] = _normalize_text(raw.get("title")) or config["title"]
    config["critical_devices"] = _normalize_text(raw.get("critical_devices")) or config["critical_devices"]
    config["critical_services"] = _normalize_text(raw.get("critical_services")) or config["critical_services"]
    config["critical_links"] = _normalize_text(raw.get("critical_links")) or config["critical_links"]
    try:
        severity = int(str(raw.get("highlight_severity", config["highlight_severity"])).strip())
    except (TypeError, ValueError):
        severity = config["highlight_severity"]
    config["highlight_severity"] = min(5, max(0, severity))
    return config


def _split_dashboard_entries(value: Any) -> list[str]:
    text = _normalize_text(value)
    if not text:
        return []
    normalized = text.replace("\r", "\n").replace("\n", ",")
    return [entry.strip() for entry in normalized.split(",") if entry.strip()]


def _severity_rank(value: Any) -> int:
    text = _normalize_text(value).lower()
    try:
        return int(text)
    except ValueError:
        pass
    mapping = {
        "not classified": 0,
        "sem classe": 0,
        "information": 1,
        "informacao": 1,
        "info": 1,
        "warning": 2,
        "aviso": 2,
        "average": 3,
        "media": 3,
        "high": 4,
        "alta": 4,
        "disaster": 5,
        "desastre": 5,
    }
    return mapping.get(text, -1)


def _alert_host_name(alert: dict[str, Any]) -> str:
    hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
    if not hosts:
        return ""
    first = hosts[0]
    if isinstance(first, dict):
        return _normalize_text(first.get("name") or first.get("host") or first.get("hostid"))
    return _normalize_text(first)


def _match_alerts_for_token(alerts: list[dict[str, Any]], token: str) -> list[dict[str, Any]]:
    token_l = _normalize_text(token).lower()
    if not token_l:
        return []
    matches = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        alert_name = _normalize_text(alert.get("name")).lower()
        host_name = _alert_host_name(alert).lower()
        if token_l in alert_name or token_l in host_name:
            matches.append(alert)
    return matches


def _critical_item_status(matches: list[dict[str, Any]], threshold: int, connected: bool) -> tuple[str, str, int]:
    if not connected:
        return "OFFLINE", "muted", -1
    if not matches:
        return "OK", "ok", 0
    severity = max((_severity_rank(alert.get("severity")) for alert in matches), default=-1)
    if severity >= threshold:
        return "ALERTA", "bad", severity
    return "ATENCAO", "warn", severity


def _build_cpd_groups(snapshot: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    alerts = snapshot.get("alerts") if isinstance(snapshot.get("alerts"), list) else []
    netbox_ok = snapshot.get("connectors", [{}])[0].get("status") == "ONLINE" if snapshot.get("connectors") else False
    zabbix_ok = snapshot.get("connectors", [{}, {"status": "OFFLINE"}])[1].get("status") == "ONLINE" if len(snapshot.get("connectors", [])) > 1 else False
    threshold = int(config.get("highlight_severity", 4))

    def build_group(entries: list[str]) -> list[dict[str, Any]]:
        rows = []
        for entry in entries:
            matches = _match_alerts_for_token(alerts, entry)
            status, pill, severity = _critical_item_status(matches, threshold, zabbix_ok)
            rows.append({
                "name": entry,
                "status": status,
                "pill": pill,
                "severity": severity,
                "host": _alert_host_name(matches[0]) if matches else "",
                "clock": _normalize_text(matches[0].get("clock")) if matches else "",
                "alert": _normalize_text(matches[0].get("name")) if matches else "",
            })
        return rows

    return {
        "devices": build_group(_split_dashboard_entries(config.get("critical_devices"))),
        "services": build_group(_split_dashboard_entries(config.get("critical_services"))),
        "links": build_group(_split_dashboard_entries(config.get("critical_links"))),
        "threshold": threshold,
        "netbox_ok": netbox_ok,
        "zabbix_ok": zabbix_ok,
    }


def _refresh_interval_seconds(runtime: dict[str, Any]) -> int:
    refresh = runtime.get("refresh") if isinstance(runtime, dict) else None
    config = _normalize_refresh_config(refresh)
    multiplier = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}[config["unit"]]
    return config["value"] * multiplier


def _load_runtime_payload(settings: Settings) -> dict[str, Any]:
    payload = default_runtime(settings)
    if not RUNTIME_CONFIG_PATH.exists():
        return payload
    try:
        stored = json.loads(RUNTIME_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return payload
    if not isinstance(stored, dict):
        return payload
    for key in ("sync_api_key", "refresh", "netbox", "zabbix", "glpi", "n8n", "email", "alert_sound", "cpd_dashboard"):
        if key not in stored:
            continue
        if key == "sync_api_key" and isinstance(stored[key], str):
            payload[key] = _normalize_text(stored[key])
            continue
        if key == "refresh":
            payload[key] = _normalize_refresh_config(stored[key])
            continue
        if key == "email":
            payload[key] = normalize_email_config(stored[key])
            continue
        if key == "alert_sound":
            payload[key] = _normalize_alert_sound_config(stored[key])
            continue
        if key == "cpd_dashboard":
            payload[key] = _normalize_cpd_dashboard_config(stored[key])
            continue
        if isinstance(stored[key], dict):
            payload[key].update({
                "enabled": bool(stored[key].get("enabled", payload[key]["enabled"])),
                "url": _normalize_text(stored[key].get("url", payload[key]["url"])),
                "token": _normalize_text(stored[key].get("token", payload[key]["token"])),
            })
    return payload


def _save_runtime_payload(payload: dict[str, Any]) -> None:
    RUNTIME_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    RUNTIME_CONFIG_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _mask_secret(value: str) -> str:
    cleaned = _normalize_text(value)
    if not cleaned:
        return "não configurado"
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def _connector_status(connector: dict[str, Any]) -> tuple[str, str]:
    enabled = bool(connector.get("enabled"))
    url = _normalize_text(connector.get("url"))
    token = _normalize_text(connector.get("token"))
    if not enabled:
        return "DESATIVADO", "muted"
    if url and token:
        return "CONFIGURADO", "ok"
    return "INCOMPLETO", "warn"


def _runtime_is_ready(connector: dict[str, Any]) -> bool:
    return bool(connector.get("enabled") and _normalize_text(connector.get("url")) and _normalize_text(connector.get("token")))


async def _create_clients(runtime: dict[str, Any]) -> tuple[NetBoxClient | None, ZabbixClient | None]:
    netbox_client = None
    zabbix_client = None

    if _runtime_is_ready(runtime["netbox"]):
        netbox_client = NetBoxClient(
            _normalize_text(runtime["netbox"]["url"]),
            _normalize_text(runtime["netbox"]["token"]),
            get_settings().request_timeout,
        )

    if _runtime_is_ready(runtime["zabbix"]):
        zabbix_client = ZabbixClient(
            _normalize_text(runtime["zabbix"]["url"]),
            _normalize_text(runtime["zabbix"]["token"]),
            get_settings().zabbix_timeout,
        )

    return netbox_client, zabbix_client


async def _swap_clients(app: FastAPI, runtime: dict[str, Any]) -> None:
    old_netbox = getattr(app.state, "netbox_client", None)
    old_zabbix = getattr(app.state, "zabbix_client", None)
    if old_netbox is not None:
        with suppress(Exception):
            await old_netbox.aclose()
    if old_zabbix is not None:
        with suppress(Exception):
            await old_zabbix.aclose()
    app.state.netbox_client, app.state.zabbix_client = await _create_clients(runtime)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    runtime = _load_runtime_payload(settings)
    app.state.settings = settings
    app.state.runtime = runtime
    app.state.netbox_client = None
    app.state.zabbix_client = None
    await _swap_clients(app, runtime)
    try:
        yield
    finally:
        if getattr(app.state, "netbox_client", None) is not None:
            await app.state.netbox_client.aclose()
        if getattr(app.state, "zabbix_client", None) is not None:
            await app.state.zabbix_client.aclose()


app = FastAPI(title="infra-sync-api", version=__version__, lifespan=lifespan)


def require_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    runtime_key = _normalize_text(getattr(request.app.state, "runtime", {}).get("sync_api_key"))
    expected = runtime_key or settings.sync_api_key
    if x_api_key is None or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def get_client(request: Request) -> NetBoxClient:
    return request.app.state.netbox_client


@app.middleware("http")
async def restrict_client_networks(request: Request, call_next):
    settings: Settings | None = getattr(request.app.state, "settings", None)
    forwarded_for = _normalize_text(request.headers.get("x-forwarded-for"))
    client_host = forwarded_for.split(",", 1)[0].strip() if forwarded_for else getattr(request.client, "host", None)

    if settings is not None and client_host:
        try:
            client_ip = ipaddress.ip_address(client_host)
        except ValueError:
            client_ip = None
        if client_ip is not None:
            allowed = client_ip.is_private or client_ip.is_loopback or any(client_ip in network for network in settings.allowed_client_networks())
            if not allowed:
                return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "Client IP not allowed"})

    return await call_next(request)


@app.exception_handler(NetBoxClientError)
async def netbox_error_handler(request: Request, exc: NetBoxClientError):
    return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": "NetBox request failed", "message": str(exc)})


@app.exception_handler(ZabbixClientError)
async def zabbix_error_handler(request: Request, exc: ZabbixClientError):
    status_code = exc.status_code if isinstance(exc.status_code, int) and 100 <= exc.status_code < 600 else status.HTTP_502_BAD_GATEWAY
    return JSONResponse(status_code=status_code, content={"detail": "Zabbix request failed", "message": str(exc)})


@app.exception_handler(SyncError)
async def sync_error_handler(request: Request, exc: SyncError):
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logging.getLogger("infra-sync-api").exception("Unhandled error")
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"detail": "Internal server error"})


async def _collect_snapshot(request: Request) -> dict[str, Any]:
    settings: Settings = request.app.state.settings
    runtime: dict[str, Any] = request.app.state.runtime
    netbox_client: NetBoxClient | None = request.app.state.netbox_client
    zabbix_client: ZabbixClient | None = request.app.state.zabbix_client

    netbox_connected = await netbox_client.health_status() if netbox_client is not None else False
    zabbix_connected = await zabbix_client.healthcheck() if zabbix_client is not None else False

    counts = {"devices": 0, "interfaces": 0, "ips": 0, "prefixes": 0, "vlans": 0, "sites": 0, "racks": 0, "zabbix_hosts": 0, "zabbix_problems": 0}
    if netbox_connected and netbox_client is not None:
        counts["devices"] = await netbox_client.count("/api/dcim/devices/")
        counts["interfaces"] = await netbox_client.count("/api/dcim/interfaces/")
        counts["ips"] = await netbox_client.count("/api/ipam/ip-addresses/")
        counts["prefixes"] = await netbox_client.count("/api/ipam/prefixes/")
        counts["vlans"] = await netbox_client.count("/api/ipam/vlans/")
        counts["sites"] = await netbox_client.count("/api/dcim/sites/")
        counts["racks"] = await netbox_client.count("/api/dcim/racks/")

    recent_alerts: list[dict[str, Any]] = []
    if zabbix_connected and zabbix_client is not None:
        counts["zabbix_hosts"] = await zabbix_client.count_hosts()
        with suppress(Exception):
            counts["zabbix_problems"] = await zabbix_client.count_problems()
        with suppress(Exception):
            recent_alerts = await zabbix_client.list_problems(limit=10)

    discovery_state = load_last_scan()
    discovered_devices = discovery_state.get("devices") if isinstance(discovery_state.get("devices"), list) else []
    discovery_count = len(discovered_devices)

    connectors = []
    for key, title, note in (
        ("netbox", "NetBox", "Inventário, IPAM e documentação"),
        ("zabbix", "Zabbix", "Telemetria, eventos e SNMP"),
        ("glpi", "GLPI", "Chamados e histórico operacional"),
        ("n8n", "n8n", "Automação segura e ajustes pequenos"),
    ):
        connector = runtime[key]
        status_label, status_style = _connector_status(connector)
        if key == "netbox":
            status_label = "ONLINE" if netbox_connected else status_label
            status_style = "ok" if netbox_connected else status_style
        if key == "zabbix":
            status_label = "ONLINE" if zabbix_connected else status_label
            status_style = "ok" if zabbix_connected else status_style
        connectors.append({
            "name": title,
            "status": status_label,
            "status_style": status_style,
            "url": _normalize_text(connector.get("url")) or "não informado",
            "token": _mask_secret(_normalize_text(connector.get("token"))),
            "note": note,
        })

    health_status = "ok" if netbox_connected and (zabbix_client is None or zabbix_connected) else "degraded"
    headline = "Sistema central pronto" if health_status == "ok" else "Sistema central parcialmente indisponível"
    detail = (
        f"NetBox {'online' if netbox_connected else 'offline'}"
        + (
            f", Zabbix {'online' if zabbix_connected else 'offline'}"
            if zabbix_client is not None
            else ", Zabbix não configurado"
        )
        + f". Redes permitidas: {len(settings.allowed_client_networks())}."
    )

    inventory_cards = [
        {"label": "Devices", "value": counts["devices"], "note": "Dispositivos no inventário"},
        {"label": "IPs", "value": counts["ips"], "note": "Endereços e consumo"},
        {"label": "VLANs", "value": counts["vlans"], "note": "Segmentação de rede"},
        {"label": "Interfaces", "value": counts["interfaces"], "note": "Portas, uplinks e trunks"},
        {"label": "Prefixes", "value": counts["prefixes"], "note": "Blocos e pools"},
        {"label": "Sites", "value": counts["sites"], "note": "Locais e unidades"},
        {"label": "Racks", "value": counts["racks"], "note": "Racks físicos"},
        {"label": "Zabbix hosts", "value": counts["zabbix_hosts"], "note": "Hosts monitorados"},
        {"label": "Alertas", "value": counts["zabbix_problems"], "note": "Problemas abertos no Zabbix"},
        {"label": "Descobertos", "value": discovery_count, "note": "Dispositivos vistos na última varredura"},
    ]

    telemetry_score = 0
    telemetry_score += 60 if netbox_connected else 0
    telemetry_score += 40 if zabbix_connected else 0
    telemetry_score += 10 if runtime["glpi"]["enabled"] else 0
    telemetry_score += 10 if runtime["n8n"]["enabled"] else 0
    telemetry_score = min(100, telemetry_score)

    section_summary = [
        {"id": "overview", "label": "Visao geral", "description": "Resumo executivo do ambiente."},
        {"id": "inventory", "label": "Inventario", "description": "Devices, racks e topologia."},
        {"id": "ipam", "label": "IPAM", "description": "IPs, prefixes e VLANs."},
        {"id": "telemetry", "label": "Telemetria", "description": "Zabbix, SNMP e alertas."},
        {"id": "discovery", "label": "Descoberta", "description": "Varredura SNMP e classificacao."},
        {"id": "automation", "label": "Automacao", "description": "n8n e ajustes controlados."},
        {"id": "integrations", "label": "Integracoes", "description": "NetBox, Zabbix, GLPI e n8n."},
        {"id": "devices", "label": "Devices", "description": "Cadastro e edicao de equipamentos."},
        {"id": "vlans", "label": "VLANs", "description": "Criacao e manutencao de VLANs."},
        {"id": "networks", "label": "Redes", "description": "Prefixes e blocos IP."},
        {"id": "alerts", "label": "Alertas", "description": "Eventos do Zabbix em tempo real."},
        {"id": "reports", "label": "Relatorios", "description": "Impressao e exportacao."},
        {"id": "settings", "label": "Configuracao", "description": "Tokens e URLs editaveis."},
    ]

    return {
        "health": health_status,
        "headline": headline,
        "detail": detail,
        "cards": inventory_cards,
        "connectors": connectors,
        "runtime": runtime,
        "summary": section_summary,
        "telemetry_score": telemetry_score,
        "refresh_enabled": bool(runtime.get("refresh", {}).get("enabled", True)),
        "refresh_interval_seconds": _refresh_interval_seconds(runtime),
        "metric_bars": [
            {"label": "Devices", "value": counts["devices"]},
            {"label": "IPs", "value": counts["ips"]},
            {"label": "VLANs", "value": counts["vlans"]},
            {"label": "Interfaces", "value": counts["interfaces"]},
            {"label": "Prefixes", "value": counts["prefixes"]},
            {"label": "Sites", "value": counts["sites"]},
            {"label": "Racks", "value": counts["racks"]},
            {"label": "Zabbix", "value": counts["zabbix_hosts"]},
            {"label": "Alertas", "value": counts["zabbix_problems"]},
        ],
        "discovery": {
            "network": discovery_state.get("network", ""),
            "count": discovery_count,
            "scanned_at": discovery_state.get("scanned_at", ""),
            "devices": discovered_devices,
        },
        "alerts": recent_alerts,
    }


async def _collect_cpd_snapshot(request: Request) -> dict[str, Any]:
    snapshot = await _collect_snapshot(request)
    runtime: dict[str, Any] = request.app.state.runtime
    config = _normalize_cpd_dashboard_config(runtime.get("cpd_dashboard"))
    snapshot["cpd_dashboard"] = config
    snapshot["cpd_groups"] = _build_cpd_groups(snapshot, config)
    snapshot["cpd_updated_at"] = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
    snapshot["cpd_refresh_seconds"] = 2
    return snapshot


def _render_shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="cache-control" content="no-store" />
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f7fb;
      --panel: #ffffff;
      --panel-2: #f3f6ff;
      --ink: #0f172a;
      --muted: #5b6475;
      --line: #d7ddea;
      --accent: #b91c1c;
      --good: #15803d;
      --warn: #b45309;
      --bad: #b91c1c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, #eef2ff 0%, var(--bg) 180px);
      color: var(--ink);
      font-family: Inter, Segoe UI, Arial, sans-serif;
    }}
    a {{ color: inherit; }}
    .shell {{ max-width: 1360px; margin: 0 auto; padding: 28px 20px 40px; }}
    .topbar {{ display: flex; justify-content: space-between; gap: 20px; align-items: start; margin-bottom: 18px; }}
    h1 {{ margin: 0; font-size: 30px; line-height: 1.15; }}
    .sub {{ margin-top: 8px; color: var(--muted); line-height: 1.45; max-width: 900px; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }}
    .btn {{
      display: inline-flex; align-items: center; gap: 8px;
      border: 1px solid var(--line); background: var(--panel);
      padding: 10px 14px; border-radius: 8px; text-decoration: none; font-weight: 700;
    }}
    .btn.primary {{ background: var(--ink); color: white; border-color: var(--ink); }}
    .hero {{
      background: rgba(255,255,255,.85); border: 1px solid var(--line); border-left: 4px solid var(--accent);
      border-radius: 12px; padding: 16px 18px; margin-bottom: 18px;
    }}
    .hero small {{ display: block; text-transform: uppercase; color: var(--muted); font-weight: 800; letter-spacing: .05em; margin-bottom: 4px; }}
    .hero strong {{ font-size: 18px; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }}
    .metric-card, .panel {{
      background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
      box-shadow: 0 8px 24px rgba(15,23,42,.04);
    }}
    .metric-card {{ padding: 16px; min-height: 120px; border-top: 4px solid #0f766e; }}
    .metric-label {{ color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; }}
    .metric-value {{ font-size: 30px; font-weight: 900; margin-top: 12px; }}
    .metric-note {{ color: var(--muted); font-size: 13px; margin-top: 8px; line-height: 1.35; }}
    .panels {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 14px; }}
    .panel {{ padding: 18px; }}
    .panel h2 {{ margin: 0 0 8px; font-size: 18px; }}
    .panel p {{ margin: 0 0 14px; color: var(--muted); line-height: 1.45; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--line); vertical-align: top; font-size: 14px; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    .pill {{ display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 800; }}
    .ok {{ background: #dcfce7; color: #166534; }}
    .warn {{ background: #fef3c7; color: #92400e; }}
    .muted {{ background: #e2e8f0; color: #334155; }}
    .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
    .connector-form {{ border: 1px solid var(--line); border-radius: 12px; padding: 14px; background: var(--panel-2); }}
    .connector-form h3 {{ margin: 0 0 4px; font-size: 16px; }}
    .connector-form small {{ color: var(--muted); display: block; margin-bottom: 12px; }}
    label {{ display: block; font-size: 13px; font-weight: 700; margin-bottom: 6px; }}
    input[type="text"], input[type="password"], select {{
      width: 100%; border: 1px solid var(--line); border-radius: 8px; background: white;
      padding: 10px 12px; font: inherit;
    }}
    .field {{ margin-bottom: 12px; }}
    .check {{ display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 14px; }}
    .foot {{ margin-top: 18px; color: var(--muted); font-size: 13px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
    @media (max-width: 1100px) {{ .grid, .panels, .form-grid {{ grid-template-columns: 1fr 1fr; }} }}
    @media (max-width: 760px) {{
      .topbar, .panels, .grid, .form-grid {{ display: grid; grid-template-columns: 1fr; }}
      .actions {{ justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    {body}
  </main>
</body>
</html>"""


def _render_dashboard(snapshot: dict[str, Any]) -> str:
    cards_markup = "".join(
        f"""
        <article class="metric-card">
          <div class="metric-label">{escape(card["label"])}</div>
          <div class="metric-value">{escape(str(card["value"]))}</div>
          <div class="metric-note">{escape(card["note"])}</div>
        </article>
        """
        for card in snapshot["cards"]
    )
    connector_rows = "".join(
        f"""
        <tr>
          <td><strong>{escape(connector["name"])}</strong><br><span style="color:var(--muted); font-size:12px">{escape(connector["note"])}</span></td>
          <td><span class="pill {escape(connector["status_style"])}">{escape(connector["status"])}</span></td>
          <td>{escape(connector["url"])}</td>
          <td>{escape(connector["token"])}</td>
        </tr>
        """
        for connector in snapshot["connectors"]
    )
    return _render_shell(
        "Rede | infra-sync-api",
        f"""
        <section class="topbar">
          <div>
            <h1>Rede</h1>
            <div class="sub">Painel central para NetBox, Zabbix, GLPI e n8n. A visão principal do ambiente fica aqui, com inventário, telemetria e automação reunidos em um só lugar.</div>
          </div>
          <div class="actions">
            <a class="btn primary" href="/settings">Configurar integrações</a>
            <a class="btn" href="/docs">API</a>
            <a class="btn" href="/health">Saúde</a>
            <a class="btn" href="/version">Versão</a>
          </div>
        </section>
        <section class="hero">
          <small>Última checagem</small>
          <strong>{escape(snapshot["headline"])}</strong>
          <div class="sub" style="margin: 6px 0 0;">{escape(snapshot["detail"])}</div>
        </section>
        <section class="grid">{cards_markup}</section>
        <section class="panels">
          <div class="panel">
            <h2>Conectores centrais</h2>
            <p>Os tokens e URLs ficam editáveis no próprio sistema. Assim você consegue ligar ou trocar a origem sem sair do painel.</p>
            <table>
              <thead>
                <tr>
                  <th>Sistema</th>
                  <th>Status</th>
                  <th>URL</th>
                  <th>Token</th>
                </tr>
              </thead>
              <tbody>{connector_rows}</tbody>
            </table>
          </div>
          <div class="panel">
            <h2>Atalhos operacionais</h2>
            <p>Rotas e ações principais para a operação do dia a dia.</p>
            <table>
              <thead>
                <tr>
                  <th>Ação</th>
                  <th>Destino</th>
                </tr>
              </thead>
              <tbody>
                <tr><td>Saúde da API</td><td><a href="/health">/health</a></td></tr>
                <tr><td>Documentação</td><td><a href="/docs">/docs</a></td></tr>
                <tr><td>Editar integrações</td><td><a href="/settings">/settings</a></td></tr>
                <tr><td>Versão</td><td><a href="/version">/version</a></td></tr>
              </tbody>
            </table>
          </div>
        </section>
        <div class="foot">
          <div>infra-sync-api v{escape(__version__)}</div>
          <div>Atualizado em {escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
        </div>
        """,
    )


def _render_settings(runtime: dict[str, Any], saved: bool = False) -> str:
    refresh = _normalize_refresh_config(runtime.get("refresh"))
    email = normalize_email_config(runtime.get("email"))
    sound = _normalize_alert_sound_config(runtime.get("alert_sound"))
    cpd = _normalize_cpd_dashboard_config(runtime.get("cpd_dashboard"))

    def connector_block(key: str, title: str, description: str, hint: str) -> str:
        connector = runtime[key]
        checked = "checked" if connector.get("enabled") else ""
        url = escape(_normalize_text(connector.get("url")))
        status_label, status_style = _connector_status(connector)
        return f"""
        <section class="connector-form">
          <h3>{escape(title)}</h3>
          <small>{escape(description)}</small>
          <div class="check">
            <input type="checkbox" name="{key}_enabled" {checked} />
            <span>Conector ativo</span>
            <span class="pill {status_style}" style="margin-left:auto">{status_label}</span>
          </div>
          <div class="field">
            <label for="{key}_url">URL</label>
            <input id="{key}_url" name="{key}_url" type="text" value="{url}" placeholder="{escape(hint)}" />
          </div>
          <div class="field">
            <label for="{key}_token">Token</label>
            <input id="{key}_token" name="{key}_token" type="password" value="" placeholder="Deixe em branco para manter o atual" />
            <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(connector.get("token"))))}</div>
          </div>
        </section>
        """

    def email_block(config: dict[str, Any]) -> str:
        checked = "checked" if config.get("enabled") else ""
        tls_checked = "checked" if config.get("use_tls") else ""
        ssl_checked = "checked" if config.get("use_ssl") else ""
        host = escape(_normalize_text(config.get("host")))
        username = escape(_normalize_text(config.get("username")))
        from_address = escape(_normalize_text(config.get("from_address")))
        to_addresses = escape(_normalize_text(config.get("to_addresses")))
        subject_prefix = escape(_normalize_text(config.get("subject_prefix")))
        status = "CONFIGURADO" if config.get("enabled") else "DESATIVADO"
        pill_class = "ok" if config.get("enabled") else "muted"
        return f"""
        <div class="panel" style="margin-bottom:14px;">
          <h2>E-mail de alertas</h2>
          <p>Configure o SMTP para enviar alertas do Zabbix por e-mail quando houver problemas ativos.</p>
          <div class="check">
            <input type="checkbox" name="email_enabled" {checked} />
            <span>Envio de e-mail ativo</span>
            <span class="pill {pill_class}" style="margin-left:auto">{status}</span>
          </div>
          <div class="form-grid">
            <div class="field"><label for="email_host">Servidor SMTP</label><input id="email_host" name="email_host" type="text" value="{host}" placeholder="smtp.exemplo.com" /></div>
            <div class="field"><label for="email_port">Porta SMTP</label><input id="email_port" name="email_port" type="text" value="{escape(str(config.get('port', 587)))}" placeholder="587" /></div>
            <div class="field"><label for="email_username">Usu?rio SMTP</label><input id="email_username" name="email_username" type="text" value="{username}" placeholder="usuario@exemplo.com" /></div>
            <div class="field"><label for="email_password">Senha SMTP</label><input id="email_password" name="email_password" type="password" value="" placeholder="Deixe em branco para manter a atual" /><div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(config.get('password'))))}</div></div>
            <div class="field"><label for="email_from_address">Remetente</label><input id="email_from_address" name="email_from_address" type="text" value="{from_address}" placeholder="alertas@ecvitoria.local" /></div>
            <div class="field"><label for="email_to_addresses">Destinat?rios</label><input id="email_to_addresses" name="email_to_addresses" type="text" value="{to_addresses}" placeholder="ti@exemplo.com, noc@exemplo.com" /></div>
            <div class="field"><label for="email_subject_prefix">Prefixo do assunto</label><input id="email_subject_prefix" name="email_subject_prefix" type="text" value="{subject_prefix}" placeholder="[infra-sync-api]" /></div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label>Seguran?a da conex?o</label>
              <div class="check"><input type="checkbox" name="email_use_tls" {tls_checked} /><span>Usar STARTTLS</span></div>
              <div class="check"><input type="checkbox" name="email_use_ssl" {ssl_checked} /><span>Usar SSL direto</span></div>
            </div>
          </div>
        </div>
        """

    return _render_shell(
        "Configurações | infra-sync-api",
        f"""
        <section class="topbar">
          <div>
            <h1>Configurações</h1>
            <div class="sub">Aqui você insere e altera os tokens e URLs que alimentam o sistema central. A atualização vale na hora para o painel e para os conectores.</div>
          </div>
          <div class="actions">
            <a class="btn" href="/">Dashboard</a>
            <a class="btn" href="/docs">API</a>
          </div>
        </section>
        {"<div class='hero'><small>Salvo</small><strong>Configurações atualizadas com sucesso.</strong><div class='sub' style='margin: 6px 0 0;'>As conexões foram recarregadas sem sair do sistema.</div></div>" if saved else ""}
        <form method="post" action="/settings">
          <div class="panel" style="margin-bottom:14px;">
            <h2>Chave de sincronização</h2>
            <p>Essa chave protege os endpoints de sync. Se você trocar aqui, os processos que usam API key precisam ser atualizados também.</p>
            <div class="form-grid">
              <div class="field">
                <label for="sync_api_key">SYNC API key</label>
                <input id="sync_api_key" name="sync_api_key" type="password" value="" placeholder="Deixe em branco para manter a atual" />
                <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(runtime["sync_api_key"])))}</div>
              </div>
            </div>
          </div>
          <div class="form-grid">
            {connector_block("netbox", "NetBox", "Inventário, IPAM, VLANs, racks e dispositivos.", "https://netbox.example.local")}
            {connector_block("zabbix", "Zabbix", "Telemetria, eventos e SNMP.", "https://zabbix.example.local/zabbix/api_jsonrpc.php")}
            {connector_block("glpi", "GLPI", "Chamados e histórico de atendimento.", "https://glpi.example.local/apirest.php")}
            {connector_block("n8n", "n8n", "Automação e pequenas correções controladas.", "https://n8n.example.local")}
          </div>
          <div style="display:flex; gap:10px; margin-top:16px; flex-wrap:wrap;">
            <button class="btn primary" type="submit">Salvar configurações</button>
            <a class="btn" href="/">Voltar ao dashboard</a>
          </div>
        </form>
        <div class="foot">
          <div>Os valores vazios mantêm o que já está salvo.</div>
          <div>Arquivo local: {escape(str(RUNTIME_CONFIG_PATH))}</div>
        </div>
        """,
    )


async def render_dashboard(request: Request) -> HTMLResponse:
    snapshot = await _collect_snapshot(request)
    return HTMLResponse(_render_dashboard(snapshot))


async def render_settings(request: Request, saved: bool = False) -> HTMLResponse:
    runtime = request.app.state.runtime
    return HTMLResponse(_render_settings(runtime, saved=saved))


@app.get("/", include_in_schema=False)
async def root(request: Request):
    return await render_dashboard(request)


@app.head("/", include_in_schema=False)
async def root_head():
    return Response(status_code=status.HTTP_200_OK)


@app.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request):
    return await render_dashboard(request)


@app.get("/settings", include_in_schema=False)
async def settings_page(request: Request, saved: int = 0):
    return await render_settings(request, saved=bool(saved))


def _form_value(form: dict[str, str], key: str, default: str = "") -> str:
    return _normalize_text(form.get(key, default))


def _form_bool(form: dict[str, str], key: str) -> bool:
    return form.get(key) in {"on", "true", "True", "1", "yes", "checked"}


async def _read_urlencoded_form(request: Request) -> dict[str, str]:
    body = await request.body()
    if not body:
        return {}
    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


@app.post("/settings", include_in_schema=False)
async def save_settings(request: Request):
    form = await _read_urlencoded_form(request)
    runtime = copy.deepcopy(request.app.state.runtime)

    sync_api_key = _form_value(form, "sync_api_key")
    if sync_api_key:
        runtime["sync_api_key"] = sync_api_key

    refresh_enabled = _form_bool(form, "refresh_enabled")
    refresh_value = _form_value(form, "refresh_value")
    refresh_unit = _form_value(form, "refresh_unit", "seconds").lower()
    runtime["refresh"] = _normalize_refresh_config({
        "enabled": refresh_enabled,
        "value": refresh_value or runtime.get("refresh", {}).get("value", 30),
        "unit": refresh_unit,
    })

    runtime["email"] = normalize_email_config({
        "enabled": _form_bool(form, "email_enabled"),
        "host": _form_value(form, "email_host"),
        "port": _form_value(form, "email_port") or runtime.get("email", {}).get("port", 587),
        "username": _form_value(form, "email_username"),
        "password": _form_value(form, "email_password") or runtime.get("email", {}).get("password", ""),
        "from_address": _form_value(form, "email_from_address"),
        "to_addresses": _form_value(form, "email_to_addresses"),
        "subject_prefix": _form_value(form, "email_subject_prefix") or runtime.get("email", {}).get("subject_prefix", "[infra-sync-api]"),
        "use_tls": _form_bool(form, "email_use_tls"),
        "use_ssl": _form_bool(form, "email_use_ssl"),
    })
    runtime["alert_sound"] = _normalize_alert_sound_config({
        "enabled": _form_bool(form, "sound_enabled"),
        "min_severity": _form_value(form, "sound_min_severity") or runtime.get("alert_sound", {}).get("min_severity", 4),
    })
    runtime["cpd_dashboard"] = _normalize_cpd_dashboard_config({
        "enabled": _form_bool(form, "cpd_enabled"),
        "title": _form_value(form, "cpd_title"),
        "critical_devices": _form_value(form, "cpd_critical_devices"),
        "critical_services": _form_value(form, "cpd_critical_services"),
        "critical_links": _form_value(form, "cpd_critical_links"),
        "highlight_severity": _form_value(form, "cpd_highlight_severity") or runtime.get("cpd_dashboard", {}).get("highlight_severity", 4),
    })

    updates = {
        "netbox": (_form_bool(form, "netbox_enabled"), _form_value(form, "netbox_url"), _form_value(form, "netbox_token")),
        "zabbix": (_form_bool(form, "zabbix_enabled"), _form_value(form, "zabbix_url"), _form_value(form, "zabbix_token")),
        "glpi": (_form_bool(form, "glpi_enabled"), _form_value(form, "glpi_url"), _form_value(form, "glpi_token")),
        "n8n": (_form_bool(form, "n8n_enabled"), _form_value(form, "n8n_url"), _form_value(form, "n8n_token")),
    }
    for key, (enabled, url, token) in updates.items():
        connector = runtime[key]
        connector["enabled"] = bool(enabled)
        if _normalize_text(url):
            connector["url"] = _normalize_url(url)
        if _normalize_text(token):
            connector["token"] = _normalize_text(token)

    _save_runtime_payload(runtime)
    request.app.state.runtime = runtime
    await _swap_clients(request.app, runtime)
    return RedirectResponse(url="/settings?saved=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/api/config")
async def api_config(request: Request):
    runtime = request.app.state.runtime
    masked = copy.deepcopy(runtime)
    for key in ("sync_api_key",):
        masked[key] = _mask_secret(_normalize_text(masked[key]))
    if "email" in masked and isinstance(masked["email"], dict):
        masked["email"]["password"] = _mask_secret(_normalize_text(masked["email"].get("password")))
    for key in ("netbox", "zabbix", "glpi", "n8n"):
        masked[key]["token"] = _mask_secret(_normalize_text(masked[key]["token"]))
    return masked


@app.get("/api/overview")
async def api_overview(request: Request):
    return await _collect_snapshot(request)


@app.get("/health")
async def health(request: Request):
    client: NetBoxClient | None = request.app.state.netbox_client
    connected = await client.health_status() if client is not None else False
    zabbix_client: ZabbixClient | None = request.app.state.zabbix_client
    zabbix_connected = await zabbix_client.healthcheck() if zabbix_client is not None else False
    status_value = "ok" if connected and (zabbix_client is None or zabbix_connected) else "degraded"
    runtime = request.app.state.runtime
    return {
        "service": "infra-sync-api",
        "status": status_value,
        "netbox_connected": connected,
        "zabbix_connected": zabbix_connected,
        "runtime": {
            "netbox": _connector_status(runtime["netbox"])[0],
            "zabbix": _connector_status(runtime["zabbix"])[0],
            "glpi": _connector_status(runtime["glpi"])[0],
            "n8n": _connector_status(runtime["n8n"])[0],
        },
    }


@app.get("/version")
async def version():
    return {"service": "infra-sync-api", "version": __version__}


@app.post("/sync/device")
async def sync_device_endpoint(payload: SyncDeviceRequest, request: Request, _: None = Depends(require_api_key)):
    client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_device(payload, client, settings.default_site_id, dry_run=False)
    return result.as_dict()


@app.post("/sync/device/dry-run")
async def sync_device_dry_run_endpoint(payload: SyncDeviceRequest, request: Request, _: None = Depends(require_api_key)):
    client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_device(payload, client, settings.default_site_id, dry_run=True)
    return result.as_dict()


@app.post("/sync/zabbix/device")
async def sync_zabbix_device_endpoint(payload: ZabbixHostSyncRequest, request: Request, _: None = Depends(require_api_key)):
    zabbix_client: ZabbixClient | None = request.app.state.zabbix_client
    if zabbix_client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Zabbix client is not configured")
    netbox_client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_zabbix_host(
        payload.hostid,
        zabbix_client,
        netbox_client,
        settings.default_site_id,
        settings.default_role_id,
        settings.default_access_point_role_id,
        dry_run=False,
        site_id=payload.site_id,
        role_id=payload.role_id,
    )
    return result.as_dict()


@app.post("/sync/zabbix/device/dry-run")
async def sync_zabbix_device_dry_run_endpoint(payload: ZabbixHostSyncRequest, request: Request, _: None = Depends(require_api_key)):
    zabbix_client: ZabbixClient | None = request.app.state.zabbix_client
    if zabbix_client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Zabbix client is not configured")
    netbox_client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_zabbix_host(
        payload.hostid,
        zabbix_client,
        netbox_client,
        settings.default_site_id,
        settings.default_role_id,
        settings.default_access_point_role_id,
        dry_run=True,
        site_id=payload.site_id,
        role_id=payload.role_id,
    )
    return result.as_dict()


def _render_shell(title: str, body: str, extra_script: str = "") -> str:
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="cache-control" content="no-store" />
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0a0a0c;
      --panel: #131317;
      --panel-2: #18181d;
      --panel-3: #1f1f25;
      --ink: #f6f6f8;
      --muted: #a6a6b0;
      --line: #2a2a31;
      --accent: #d4001a;
      --accent-2: #900015;
      --accent-soft: rgba(212, 0, 26, 0.16);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(212, 0, 26, 0.13), transparent 22%),
        linear-gradient(180deg, #101013 0%, var(--bg) 100%);
      color: var(--ink);
      font-family: Inter, Segoe UI, Arial, sans-serif;
    }}
    a {{ color: inherit; }}
    .layout {{
      display: grid;
      grid-template-columns: 292px minmax(0, 1fr);
      min-height: 100vh;
    }}
    .sidebar {{
      background: linear-gradient(180deg, #09090b 0%, #111115 100%);
      border-right: 1px solid var(--line);
      padding: 22px 18px;
      position: sticky;
      top: 0;
      height: 100vh;
      overflow: auto;
    }}
    .brand {{
      border: 1px solid var(--line);
      background: #09090b;
      border-radius: 14px;
      padding: 14px;
      margin-bottom: 18px;
    }}
    .brand .kicker {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: .12em;
      font-size: 11px;
      font-weight: 800;
      margin-bottom: 6px;
    }}
    .brand h1 {{
      margin: 0;
      font-size: 22px;
      line-height: 1.08;
    }}
    .brand p {{
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.45;
    }}
    .menu {{
      display: grid;
      gap: 8px;
      margin-top: 14px;
    }}
    .menu button, .menu a {{
      width: 100%;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      text-decoration: none;
      border-radius: 12px;
      padding: 12px 12px;
      text-align: left;
      cursor: pointer;
      display: block;
      font: inherit;
    }}
    .menu button:hover, .menu a:hover {{ border-color: var(--accent); }}
    .menu button.active {{ background: var(--accent); border-color: var(--accent); color: white; }}
    .menu a.active {{ background: var(--accent); border-color: var(--accent); color: white; }}
    .menu a.active .meta {{ color: rgba(255,255,255,.8); }}
    .menu .meta {{
      display: block;
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.3;
    }}
    .sidebar-footer {{
      margin-top: 18px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
    }}
    .content {{
      padding: 26px 24px 40px;
      min-width: 0;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: start;
      margin-bottom: 18px;
    }}
    .page-title {{
      margin: 0;
      font-size: 32px;
      line-height: 1.08;
      letter-spacing: -0.02em;
    }}
    .sub {{
      margin-top: 8px;
      color: var(--muted);
      line-height: 1.5;
      max-width: 980px;
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: flex-end;
    }}
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      padding: 10px 14px;
      border-radius: 10px;
      text-decoration: none;
      font-weight: 700;
      min-height: 42px;
    }}
    .btn.primary {{ background: var(--accent); border-color: var(--accent); color: white; }}
    .hero {{
      background: linear-gradient(180deg, rgba(212,0,26,0.13), rgba(0,0,0,0.06));
      border: 1px solid var(--line);
      border-left: 4px solid var(--accent);
      border-radius: 14px;
      padding: 16px 18px;
      margin-bottom: 18px;
    }}
    .hero small {{
      display: block;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 800;
      letter-spacing: .09em;
      margin-bottom: 4px;
    }}
    .hero strong {{ font-size: 18px; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    .metric-card, .panel, .chart-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, .18);
    }}
    .metric-card {{
      padding: 16px;
      min-height: 128px;
      border-top: 4px solid var(--accent);
    }}
    .metric-label {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .metric-value {{
      font-size: 30px;
      font-weight: 900;
      margin-top: 12px;
    }}
    .metric-note {{
      color: var(--muted);
      font-size: 13px;
      margin-top: 8px;
      line-height: 1.35;
    }}
    .panels {{
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 14px;
      margin-bottom: 14px;
    }}
    .panel {{
      padding: 18px;
    }}
    .panel h2 {{
      margin: 0 0 8px;
      font-size: 18px;
    }}
    .panel p {{
      margin: 0 0 14px;
      color: var(--muted);
      line-height: 1.45;
    }}
    .inventory-kind-menu {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .inventory-kind-item {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel-2);
      text-decoration: none;
      color: var(--ink);
    }}
    .inventory-kind-item span {{
      font-weight: 700;
      line-height: 1.3;
    }}
    .inventory-kind-item strong {{
      min-width: 28px;
      text-align: right;
      font-size: 14px;
    }}
    .inventory-kind-item.active {{
      border-color: rgba(212, 0, 26, .7);
      box-shadow: inset 3px 0 0 var(--accent);
      background: rgba(212, 0, 26, .08);
    }}
    .detail-nav {{
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .detail-nav a {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 11px 12px;
      text-decoration: none;
      background: var(--panel-2);
      color: var(--ink);
      font-weight: 700;
    }}
    .detail-nav small {{
      color: var(--muted);
      font-weight: 700;
    }}
    .detail-meta {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .detail-meta .metric-card {{
      min-height: 108px;
    }}
    .check input[type="checkbox"] {{
      accent-color: var(--accent);
    }}
    .glpi-frame {{
      display: grid;
      grid-template-columns: 260px minmax(0, 1fr) 360px;
      gap: 14px;
      align-items: start;
    }}
    .glpi-sidebar {{
      position: sticky;
      top: 14px;
    }}
    .glpi-section-title {{
      margin: 0 0 8px;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: .04em;
      color: var(--muted);
    }}
    .glpi-toolbar {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: flex-end;
      flex-wrap: wrap;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }}
    .glpi-breadcrumbs {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
    }}
    .glpi-breadcrumbs span {{
      color: var(--ink);
      font-weight: 700;
    }}
    .glpi-tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0 0 14px;
    }}
    .glpi-tabs a {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      text-decoration: none;
      color: var(--ink);
      background: var(--panel-2);
      font-weight: 700;
      font-size: 13px;
    }}
    .glpi-tabs a.active {{
      background: rgba(212, 0, 26, .08);
      border-color: rgba(212, 0, 26, .65);
    }}
    .glpi-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 14px;
    }}
    .glpi-card h3 {{
      margin: 0 0 8px;
      font-size: 16px;
    }}
    .glpi-detail-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      flex-wrap: wrap;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--line);
    }}
    .glpi-detail-title {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .glpi-detail-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .glpi-detail-pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--panel-2);
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 700;
    }}
    .glpi-detail-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }}
    .glpi-detail-section {{
      margin-bottom: 14px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
    }}
    .glpi-detail-section h3 {{
      margin: 0 0 10px;
      font-size: 16px;
    }}
    .glpi-info-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}
    .glpi-info-item {{
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-2);
    }}
    .glpi-info-item .label {{
      display: block;
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-bottom: 6px;
    }}
    .glpi-info-item strong {{
      display: block;
      word-break: break-word;
    }}
    .glpi-side-menu {{
      display: grid;
      gap: 8px;
    }}
    .glpi-side-menu a {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--line);
      text-decoration: none;
      color: var(--ink);
      background: var(--panel-2);
      font-weight: 700;
    }}
    .glpi-side-menu a span {{
      color: var(--muted);
      font-size: 12px;
      font-weight: 600;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 11px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .05em;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      border: 1px solid transparent;
    }}
    .ok {{ background: rgba(212,0,26,.16); color: #ff93a1; border-color: rgba(212,0,26,.35); }}
    .warn {{ background: rgba(255,255,255,.05); color: #f2f2f2; border-color: var(--line); }}
    .muted {{ background: rgba(255,255,255,.03); color: var(--muted); border-color: var(--line); }}
    .section {{
      display: none;
      margin-top: 6px;
    }}
    .section.active {{ display: block; }}
    .section-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .chart-card {{
      padding: 14px;
    }}
    .chart-card h3 {{
      margin: 0 0 10px;
      font-size: 15px;
    }}
    .chart-card canvas {{
      width: 100%;
      height: 240px;
      display: block;
    }}
    .foot {{
      margin-top: 18px;
      color: var(--muted);
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      padding-top: 12px;
      border-top: 1px solid var(--line);
    }}
    .connector-form {{
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      background: var(--panel-2);
    }}
    .connector-form h3 {{
      margin: 0 0 4px;
      font-size: 16px;
    }}
    .connector-form small {{
      color: var(--muted);
      display: block;
      margin-bottom: 12px;
    }}
    label {{
      display: block;
      font-size: 13px;
      font-weight: 700;
      margin-bottom: 6px;
    }}
    input[type="text"], input[type="password"], textarea, select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #0f0f12;
      color: var(--ink);
      padding: 10px 12px;
      font: inherit;
    }}
    textarea {{
      min-height: 100px;
      resize: vertical;
    }}
    .field {{ margin-bottom: 12px; }}
    .check {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      font-size: 14px;
    }}
    .form-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }}
    @media (max-width: 1120px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .sidebar {{ position: static; height: auto; }}
      .metrics, .panels, .section-grid, .form-grid {{ grid-template-columns: 1fr 1fr; }}
    }}
    @media (max-width: 760px) {{
      .metrics, .panels, .section-grid, .form-grid {{ grid-template-columns: 1fr; }}
      .topbar {{ display: grid; grid-template-columns: 1fr; }}
      .actions {{ justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <main class="layout">
    {body}
  </main>
  <script>{extra_script}</script>
</body>
</html>"""


def _render_dashboard(snapshot: dict[str, Any]) -> str:
    cards_markup = "".join(
        f"""
        <article class="metric-card">
          <div class="metric-label">{escape(card["label"])}</div>
          <div class="metric-value">{escape(str(card["value"]))}</div>
          <div class="metric-note">{escape(card["note"])}</div>
        </article>
        """
        for card in snapshot["cards"]
    )
    connector_rows = "".join(
        f"""
        <tr>
          <td><strong>{escape(connector["name"])}</strong><br><span style="color:var(--muted); font-size:12px">{escape(connector["note"])}</span></td>
          <td><span class="pill {escape(connector["status_style"])}">{escape(connector["status"])}</span></td>
          <td>{escape(connector["url"])}</td>
          <td>{escape(connector["token"])}</td>
        </tr>
        """
        for connector in snapshot["connectors"]
    )
    summary_buttons = "".join(
        f'<button class="menu-btn {"active" if item["id"] == "overview" else ""}" data-target="{escape(item["id"])}">{escape(item["label"])}<span class="meta">{escape(item["description"])}</span></button>'
        for item in snapshot["summary"]
    )
    menu_items = "".join(
        f'<button class="menu-btn {"active" if item["id"] == "overview" else ""}" data-target="{escape(item["id"])}">{escape(item["label"])}<span class="meta">{escape(item["description"])}</span></button>'
        for item in snapshot["summary"]
    )
    snapshot_json = json.dumps(snapshot, ensure_ascii=False).replace("</", "<\\/")
    extra_script = f"""
const snapshot = {snapshot_json};
const menuButtons = document.querySelectorAll('[data-target]');
const sections = document.querySelectorAll('.section');
function showSection(id) {{
  sections.forEach((section) => section.classList.toggle('active', section.dataset.section === id));
  menuButtons.forEach((btn) => btn.classList.toggle('active', btn.dataset.target === id));
}}
menuButtons.forEach((btn) => btn.addEventListener('click', () => showSection(btn.dataset.target)));
showSection('overview');

function getCtx(id) {{
  const canvas = document.getElementById(id);
  return canvas ? canvas.getContext('2d') : null;
}}
function resizeCanvas(ctx) {{
  const dpr = window.devicePixelRatio || 1;
  const w = ctx.canvas.clientWidth;
  const h = ctx.canvas.clientHeight;
  ctx.canvas.width = w * dpr;
  ctx.canvas.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return {{ w, h }};
}}
function panelBase(ctx, title) {{
  const {{ w, h }} = resizeCanvas(ctx);
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = '#18181d';
  ctx.fillRect(0, 0, w, h);
  ctx.fillStyle = '#a6a6b0';
  ctx.font = '12px Segoe UI, Arial';
  ctx.fillText(title, 16, 22);
  return {{ w, h }};
}}
function drawDonutChart(id, segments, title) {{
  const ctx = getCtx(id);
  if (!ctx) return;
  const {{ w, h }} = panelBase(ctx, title);
  const total = segments.reduce((acc, item) => acc + item.value, 0) || 1;
  let start = -Math.PI / 2;
  const cx = w / 2;
  const cy = h / 2 + 10;
  const radius = Math.min(w, h) * 0.28;
  segments.forEach((segment) => {{
    const angle = (Math.PI * 2) * (segment.value / total);
    ctx.beginPath();
    ctx.arc(cx, cy, radius, start, start + angle);
    ctx.strokeStyle = segment.color;
    ctx.lineWidth = 28;
    ctx.stroke();
    start += angle;
  }});
  ctx.fillStyle = '#f6f6f8';
  ctx.font = '700 22px Segoe UI, Arial';
  ctx.textAlign = 'center';
  ctx.fillText(String(total), cx, cy + 8);
  ctx.font = '12px Segoe UI, Arial';
  ctx.fillStyle = '#a6a6b0';
  ctx.fillText('Total', cx, cy + 28);
  ctx.textAlign = 'left';
}}
function drawBarChart(id, bars, title) {{
  const ctx = getCtx(id);
  if (!ctx) return;
  const {{ w, h }} = panelBase(ctx, title);
  const maxValue = Math.max(...bars.map((b) => b.value), 1);
  const baseY = h - 28;
  const leftPad = 20;
  const barWidth = Math.max(18, (w - 40) / bars.length - 10);
  bars.forEach((bar, index) => {{
    const x = leftPad + index * (barWidth + 10);
    const height = Math.max(8, ((h - 80) * bar.value) / maxValue);
    ctx.fillStyle = '#d4001a';
    ctx.fillRect(x, baseY - height, barWidth, height);
    ctx.fillStyle = '#f6f6f8';
    ctx.font = '700 12px Segoe UI, Arial';
    ctx.fillText(String(bar.value), x, baseY - height - 8);
    ctx.save();
    ctx.translate(x, baseY + 4);
    ctx.rotate(-Math.PI / 4);
    ctx.fillStyle = '#a6a6b0';
    ctx.fillText(bar.label, 0, 0);
    ctx.restore();
  }});
}}
function drawLineChart(id, points, title) {{
  const ctx = getCtx(id);
  if (!ctx) return;
  const {{ w, h }} = panelBase(ctx, title);
  const maxValue = Math.max(...points.map((p) => p.value), 1);
  const pad = 24;
  const plotW = w - (pad * 2);
  const plotH = h - 64;
  ctx.strokeStyle = '#2a2a31';
  ctx.strokeRect(pad, 34, plotW, plotH);
  ctx.beginPath();
  points.forEach((point, index) => {{
    const x = pad + (plotW * index) / Math.max(points.length - 1, 1);
    const y = 34 + plotH - ((plotH - 12) * point.value) / maxValue;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }});
  ctx.strokeStyle = '#d4001a';
  ctx.lineWidth = 3;
  ctx.stroke();
  points.forEach((point, index) => {{
    const x = pad + (plotW * index) / Math.max(points.length - 1, 1);
    const y = 34 + plotH - ((plotH - 12) * point.value) / maxValue;
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#f6f6f8';
    ctx.fill();
    ctx.strokeStyle = '#d4001a';
    ctx.stroke();
  }});
}}

drawDonutChart('overview-donut', [
  {{ label: 'NetBox', value: snapshot.connectors[0].status === 'ONLINE' ? 1 : 0, color: '#d4001a' }},
  {{ label: 'Zabbix', value: snapshot.connectors[1].status === 'ONLINE' ? 1 : 0, color: '#b10016' }},
  {{ label: 'GLPI', value: snapshot.connectors[2].status === 'CONFIGURADO' ? 1 : 0, color: '#8d0011' }},
  {{ label: 'n8n', value: snapshot.connectors[3].status === 'CONFIGURADO' ? 1 : 0, color: '#5d000b' }},
], 'Status operacional');
drawBarChart('inventory-bars', snapshot.metric_bars, 'Volume por categoria');
drawDonutChart('ipam-donut', [
  {{ label: 'IPs', value: snapshot.cards[1].value, color: '#d4001a' }},
  {{ label: 'Prefixes', value: snapshot.cards[4].value, color: '#b10016' }},
  {{ label: 'VLANs', value: snapshot.cards[2].value, color: '#8d0011' }},
  {{ label: 'Sites', value: snapshot.cards[5].value, color: '#5d000b' }},
], 'Consumo agregado');
drawLineChart('telemetry-line', [
  {{ label: 'Mon', value: 18 }},
  {{ label: 'Tue', value: 34 }},
  {{ label: 'Wed', value: 46 }},
  {{ label: 'Thu', value: 51 }},
  {{ label: 'Fri', value: 61 }},
  {{ label: 'Sat', value: 48 }},
  {{ label: 'Sun', value: snapshot.telemetry_score }},
], 'Tendencia semanal');
window.addEventListener('resize', () => {{
  drawDonutChart('overview-donut', [
    {{ label: 'NetBox', value: snapshot.connectors[0].status === 'ONLINE' ? 1 : 0, color: '#d4001a' }},
    {{ label: 'Zabbix', value: snapshot.connectors[1].status === 'ONLINE' ? 1 : 0, color: '#b10016' }},
    {{ label: 'GLPI', value: snapshot.connectors[2].status === 'CONFIGURADO' ? 1 : 0, color: '#8d0011' }},
    {{ label: 'n8n', value: snapshot.connectors[3].status === 'CONFIGURADO' ? 1 : 0, color: '#5d000b' }},
  ], 'Status operacional');
  drawBarChart('inventory-bars', snapshot.metric_bars, 'Volume por categoria');
  drawDonutChart('ipam-donut', [
    {{ label: 'IPs', value: snapshot.cards[1].value, color: '#d4001a' }},
    {{ label: 'Prefixes', value: snapshot.cards[4].value, color: '#b10016' }},
    {{ label: 'VLANs', value: snapshot.cards[2].value, color: '#8d0011' }},
    {{ label: 'Sites', value: snapshot.cards[5].value, color: '#5d000b' }},
  ], 'Consumo agregado');
  drawLineChart('telemetry-line', [
    {{ label: 'Mon', value: 18 }},
    {{ label: 'Tue', value: 34 }},
    {{ label: 'Wed', value: 46 }},
    {{ label: 'Thu', value: 51 }},
    {{ label: 'Fri', value: 61 }},
    {{ label: 'Sat', value: 48 }},
    {{ label: 'Sun', value: snapshot.telemetry_score }},
  ], 'Tendencia semanal');
drawDonutChart('automation-donut', [
  {{ label: 'NetBox', value: snapshot.connectors[0].status === 'ONLINE' ? 1 : 0, color: '#d4001a' }},
  {{ label: 'Zabbix', value: snapshot.connectors[1].status === 'ONLINE' ? 1 : 0, color: '#b10016' }},
  {{ label: 'GLPI', value: snapshot.connectors[2].status === 'CONFIGURADO' ? 1 : 0, color: '#8d0011' }},
  {{ label: 'n8n', value: snapshot.connectors[3].status === 'CONFIGURADO' ? 1 : 0, color: '#5d000b' }},
], 'Automacao assistida');
const refreshSeconds = Math.max(5, snapshot.refresh_interval_seconds || 30);
if (snapshot.refresh_enabled) {{
  window.setInterval(() => window.location.reload(), refreshSeconds * 1000);
}}
}});
"""
    return _render_shell(
        "Rede | infra-sync-api",
        f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="kicker">ECV Network Control</div>
        <h1>Rede</h1>
        <p>Central de operacao para inventario, telemetria, IPAM, automacao e ajustes controlados.</p>
      </div>
      <nav class="menu">
        {menu_items}
      </nav>
      <div class="sidebar-footer">
        <div>Dashboard v{escape(__version__)}</div>
        <div>{escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
        <div style="margin-top:10px;">Tema vermelho e preto</div>
      </div>
    </aside>
    <section class="content">
      <section class="topbar">
        <div>
          <h2 class="page-title">Central de rede</h2>
          <div class="sub">Uma visao unica do ambiente, com menus separados para operacao, inventario, IPAM, telemetria, automacao e integracoes.</div>
        </div>
          <div class="actions">
            <a class="btn primary" href="/settings">Configurar integrações</a>
            <a class="btn" href="/cpd">CPD</a>
            <a class="btn" href="/discovery">Varredura SNMP</a>
            <a class="btn" href="/api/overview">Snapshot</a>
            <a class="btn" href="/health">Saude</a>
            <a class="btn" href="/docs">API</a>
          </div>
      </section>

      <section class="hero">
        <small>Ultima checagem</small>
        <strong>{escape(snapshot["headline"])}</strong>
        <div class="sub" style="margin: 6px 0 0;">{escape(snapshot["detail"])}</div>
      </section>

      <section id="overview" class="section active" data-section="overview">
        <div class="metrics">{cards_markup}</div>
        <div class="panels">
          <div class="panel">
            <h2>Status resumido</h2>
            <p>Indicadores principais do ambiente e disponibilidade dos conectores centrais.</p>
            <table>
              <thead><tr><th>Sistema</th><th>Status</th><th>URL</th></tr></thead>
              <tbody>
                {''.join(
                    f'<tr><td><strong>{escape(connector["name"])}</strong></td><td><span class="pill {escape(connector["status_style"])}">{escape(connector["status"])}</span></td><td>{escape(connector["url"])}</td></tr>'
                    for connector in snapshot["connectors"]
                )}
              </tbody>
            </table>
          </div>
          <div class="chart-card">
            <h3>Operacional</h3>
            <canvas id="overview-donut"></canvas>
          </div>
        </div>
      </section>

      <section id="inventory" class="section" data-section="inventory">
        <div class="section-grid">
          <div class="panel">
            <h2>Inventario consolidado</h2>
            <p>Devices, racks e interfaces vistos pelo NetBox.</p>
            <table>
              <thead><tr><th>Categoria</th><th>Quantidade</th></tr></thead>
              <tbody>
                {''.join(f'<tr><td>{escape(card["label"])}</td><td>{escape(str(card["value"]))}</td></tr>' for card in snapshot["cards"][:7])}
              </tbody>
            </table>
          </div>
          <div class="chart-card">
            <h3>Volume por categoria</h3>
            <canvas id="inventory-bars"></canvas>
          </div>
        </div>
      </section>

      <section id="ipam" class="section" data-section="ipam">
        <div class="section-grid">
          <div class="panel">
            <h2>IPAM e segmentacao</h2>
            <p>Visao para consumo de IP, prefixes e VLANs.</p>
            <table>
              <thead><tr><th>Indicador</th><th>Valor</th></tr></thead>
              <tbody>
                <tr><td>IPs</td><td>{escape(str(snapshot["cards"][1]["value"]))}</td></tr>
                <tr><td>Prefixes</td><td>{escape(str(snapshot["cards"][4]["value"]))}</td></tr>
                <tr><td>VLANs</td><td>{escape(str(snapshot["cards"][2]["value"]))}</td></tr>
                <tr><td>Sites</td><td>{escape(str(snapshot["cards"][5]["value"]))}</td></tr>
              </tbody>
            </table>
          </div>
          <div class="chart-card">
            <h3>Consumo agregado</h3>
            <canvas id="ipam-donut"></canvas>
          </div>
        </div>
      </section>

      <section id="telemetry" class="section" data-section="telemetry">
        <div class="section-grid">
          <div class="panel">
            <h2>Telemetria e eventos</h2>
            <p>Zabbix concentrado para status, SNMP e uso ao longo do tempo.</p>
            <table>
              <thead><tr><th>Fonte</th><th>Estado</th></tr></thead>
              <tbody>
                <tr><td>Zabbix</td><td><span class="pill {escape(snapshot["connectors"][1]["status_style"])}">{escape(snapshot["connectors"][1]["status"])}</span></td></tr>
                <tr><td>Score operacional</td><td>{escape(str(snapshot["telemetry_score"]))}/100</td></tr>
              </tbody>
            </table>
          </div>
          <div class="chart-card">
            <h3>Tendencia semanal</h3>
            <canvas id="telemetry-line"></canvas>
          </div>
        </div>
      </section>

      <section id="discovery" class="section" data-section="discovery">
        <div class="section-grid">
          <div class="panel">
            <h2>Descoberta SNMP</h2>
            <p>Varredura controlada da rede local com classificacao por grupos. O resultado mais recente fica salvo para analise e ajuste.</p>
            <table>
              <thead><tr><th>Ultima rede</th><th>Resultado</th></tr></thead>
              <tbody>
                <tr><td>{escape(snapshot["discovery"]["network"] or "Nenhuma")}</td><td>{escape(str(snapshot["discovery"]["count"]))} dispositivos</td></tr>
                <tr><td>Ultima execucao</td><td>{escape(snapshot["discovery"]["scanned_at"] or "sem data")}</td></tr>
              </tbody>
            </table>
            <div style="display:flex; gap:10px; margin-top:16px; flex-wrap:wrap;">
              <a class="btn primary" href="/discovery">Abrir varredura</a>
              <a class="btn" href="/discovery#results">Ver resultados</a>
            </div>
          </div>
          <div class="panel">
            <h2>Classificacao padrao</h2>
            <p>Os dispositivos encontrados sao sugeridos em grupos como switch, servidor e hosts, com subgrupos para mobile, notebook, tablet, desktop e fixo.</p>
            <table>
              <thead><tr><th>Grupo</th><th>Subgrupo</th></tr></thead>
              <tbody>
                <tr><td>switches</td><td>core / access / wireless</td></tr>
                <tr><td>servers</td><td>hypervisor / physical</td></tr>
                <tr><td>hosts</td><td>mobile / notebook / tablet / desktop / fixed</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="automation" class="section" data-section="automation">
        <div class="section-grid">
          <div class="panel">
            <h2>Atalhos operacionais</h2>
            <p>n8n para ajustes pequenos, correcoes e replicacao assistida.</p>
            <table>
              <thead><tr><th>Acao</th><th>Destino</th></tr></thead>
              <tbody>
                <tr><td>Editar tokens</td><td><a href="/settings">/settings</a></td></tr>
                <tr><td>Sincronizar device</td><td><a href="/docs#/default/sync_device_endpoint_sync_device_post">POST /sync/device</a></td></tr>
                <tr><td>Sincronizar Zabbix</td><td><a href="/docs#/default/sync_zabbix_device_endpoint_sync_zabbix_device_post">POST /sync/zabbix/device</a></td></tr>
              </tbody>
            </table>
          </div>
          <div class="chart-card">
            <h3>Automacao assistida</h3>
            <canvas id="automation-donut"></canvas>
          </div>
        </div>
      </section>

      <section id="integrations" class="section" data-section="integrations">
        <div class="panel">
          <h2>Conectores centrais</h2>
          <p>URLs e tokens hoje configurados no sistema. Eles podem ser trocados sem parar a aplicacao.</p>
          <table>
            <thead>
              <tr><th>Sistema</th><th>Status</th><th>URL</th><th>Token</th></tr>
            </thead>
            <tbody>{connector_rows}</tbody>
          </table>
        </div>
      </section>

      <section id="settings" class="section" data-section="settings">
        <div class="panel">
          <h2>Configuracao</h2>
          <p>Os tokens sao editados em <a href="/settings">/settings</a>. A pagina abre em uma interface dedicada.</p>
          <a class="btn primary" href="/settings">Abrir configuracao</a>
        </div>
      </section>

      <section id="devices" class="section" data-section="devices">
        <div class="section-grid">
          <div class="panel">
            <h2>Devices</h2>
            <p>Cadastro e edição de equipamentos do inventário central.</p>
            <table>
              <thead><tr><th>Ação</th><th>Destino</th></tr></thead>
              <tbody>
                <tr><td>Listar devices</td><td><a href="/devices">/devices</a></td></tr>
                <tr><td>Imprimir relatório</td><td><a href="/reports">/reports</a></td></tr>
              </tbody>
            </table>
          </div>
          <div class="panel">
            <h2>Resumo</h2>
            <p>Dados atuais do inventário para apoiar a operação.</p>
            <table>
              <thead><tr><th>Métrica</th><th>Valor</th></tr></thead>
              <tbody>
                <tr><td>Devices</td><td>{escape(str(snapshot["cards"][0]["value"]))}</td></tr>
                <tr><td>Interfaces</td><td>{escape(str(snapshot["cards"][3]["value"]))}</td></tr>
                <tr><td>Zabbix hosts</td><td>{escape(str(snapshot["cards"][7]["value"]))}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="vlans" class="section" data-section="vlans">
        <div class="section-grid">
          <div class="panel">
            <h2>VLANs</h2>
            <p>Criação e edição de VLANs com acesso direto ao NetBox.</p>
            <a class="btn primary" href="/vlans">Abrir VLANs</a>
          </div>
          <div class="panel">
            <h2>Consumo</h2>
            <p>Visão rápida da segmentação de rede.</p>
            <table>
              <thead><tr><th>Indicador</th><th>Valor</th></tr></thead>
              <tbody>
                <tr><td>VLANs</td><td>{escape(str(snapshot["cards"][2]["value"]))}</td></tr>
                <tr><td>Sites</td><td>{escape(str(snapshot["cards"][5]["value"]))}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="networks" class="section" data-section="networks">
        <div class="section-grid">
          <div class="panel">
            <h2>Redes</h2>
            <p>Prefixes e blocos IP para IPAM centralizado.</p>
            <a class="btn primary" href="/networks">Abrir redes</a>
          </div>
          <div class="panel">
            <h2>Blocos IP</h2>
            <p>Consumo do espaço de endereçamento do ambiente.</p>
            <table>
              <thead><tr><th>Indicador</th><th>Valor</th></tr></thead>
              <tbody>
                <tr><td>IPs</td><td>{escape(str(snapshot["cards"][1]["value"]))}</td></tr>
                <tr><td>Prefixes</td><td>{escape(str(snapshot["cards"][4]["value"]))}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="alerts" class="section" data-section="alerts">
        <div class="section-grid">
          <div class="panel">
            <h2>Alertas do Zabbix</h2>
            <p>Problemas em aberto e acompanhamento em tempo real.</p>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
              <a class="btn primary" href="/alerts">Abrir alertas</a>
              <a class="btn" href="/api/alerts">Ver JSON</a>
            </div>
          </div>
          <div class="panel">
            <h2>Alertas recentes</h2>
            <table>
              <thead><tr><th>Problema</th><th>Host</th></tr></thead>
              <tbody>
                {''.join(
                    f'<tr><td>{escape(_normalize_text(alert.get("name")) or "—")}</td><td>{escape(_relation_label((alert.get("hosts") or [{}])[0]) if isinstance(alert.get("hosts"), list) and alert.get("hosts") else "—")}</td></tr>'
                    for alert in (snapshot["alerts"][:5] if isinstance(snapshot.get("alerts"), list) else [])
                ) or '<tr><td colspan="2">Nenhum alerta aberto.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="reports" class="section" data-section="reports">
        <div class="section-grid">
          <div class="panel">
            <h2>Relatórios</h2>
            <p>Resumo pronto para impressão ou exportação via navegador.</p>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
              <a class="btn primary" href="/reports">Abrir relatório</a>
              <button class="btn" type="button" onclick="window.print()">Imprimir página</button>
            </div>
          </div>
          <div class="panel">
            <h2>Resumo executivo</h2>
            <table>
              <thead><tr><th>Bloco</th><th>Valor</th></tr></thead>
              <tbody>
                <tr><td>Telemetria</td><td>{escape(str(snapshot["telemetry_score"]))}/100</td></tr>
                <tr><td>Alertas</td><td>{escape(str(snapshot["cards"][8]["value"]))}</td></tr>
                <tr><td>Descobertos</td><td>{escape(str(snapshot["cards"][9]["value"]))}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <div class="foot">
        <div>infra-sync-api v{escape(__version__)}</div>
        <div>Atualizado em {escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
      </div>
    </section>
        """,
        extra_script=extra_script,
    )


def _render_settings(runtime: dict[str, Any], saved: bool = False) -> str:
    refresh = _normalize_refresh_config(runtime.get("refresh"))
    email = normalize_email_config(runtime.get("email"))
    sound = _normalize_alert_sound_config(runtime.get("alert_sound"))
    cpd = _normalize_cpd_dashboard_config(runtime.get("cpd_dashboard"))

    def connector_block(key: str, title: str, description: str, hint: str) -> str:
        connector = runtime[key]
        checked = "checked" if connector.get("enabled") else ""
        url = escape(_normalize_text(connector.get("url")))
        status_label, status_style = _connector_status(connector)
        return f"""
        <section class="connector-form">
          <h3>{escape(title)}</h3>
          <small>{escape(description)}</small>
          <div class="check">
            <input type="checkbox" name="{key}_enabled" {checked} />
            <span>Conector ativo</span>
            <span class="pill {status_style}" style="margin-left:auto">{status_label}</span>
          </div>
          <div class="field">
            <label for="{key}_url">URL</label>
            <input id="{key}_url" name="{key}_url" type="text" value="{url}" placeholder="{escape(hint)}" />
          </div>
          <div class="field">
            <label for="{key}_token">Token</label>
            <input id="{key}_token" name="{key}_token" type="password" value="" placeholder="Deixe em branco para manter o atual" />
            <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(connector.get("token"))))}</div>
          </div>
        </section>
        """

    def email_block(config: dict[str, Any]) -> str:
        checked = "checked" if config.get("enabled") else ""
        tls_checked = "checked" if config.get("use_tls") else ""
        ssl_checked = "checked" if config.get("use_ssl") else ""
        host = escape(_normalize_text(config.get("host")))
        username = escape(_normalize_text(config.get("username")))
        from_address = escape(_normalize_text(config.get("from_address")))
        to_addresses = escape(_normalize_text(config.get("to_addresses")))
        subject_prefix = escape(_normalize_text(config.get("subject_prefix")))
        status = "CONFIGURADO" if config.get("enabled") else "DESATIVADO"
        pill_class = "ok" if config.get("enabled") else "muted"
        return f"""
        <div class="panel" style="margin-bottom:14px;">
          <h2>E-mail de alertas</h2>
          <p>Configure o SMTP para enviar alertas do Zabbix por e-mail quando houver problemas ativos.</p>
          <div class="check">
            <input type="checkbox" name="email_enabled" {checked} />
            <span>Envio de e-mail ativo</span>
            <span class="pill {pill_class}" style="margin-left:auto">{status}</span>
          </div>
          <div class="form-grid">
            <div class="field"><label for="email_host">Servidor SMTP</label><input id="email_host" name="email_host" type="text" value="{host}" placeholder="smtp.exemplo.com" /></div>
            <div class="field"><label for="email_port">Porta SMTP</label><input id="email_port" name="email_port" type="text" value="{escape(str(config.get('port', 587)))}" placeholder="587" /></div>
            <div class="field"><label for="email_username">Usu?rio SMTP</label><input id="email_username" name="email_username" type="text" value="{username}" placeholder="usuario@exemplo.com" /></div>
            <div class="field"><label for="email_password">Senha SMTP</label><input id="email_password" name="email_password" type="password" value="" placeholder="Deixe em branco para manter a atual" /><div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(config.get('password'))))}</div></div>
            <div class="field"><label for="email_from_address">Remetente</label><input id="email_from_address" name="email_from_address" type="text" value="{from_address}" placeholder="alertas@ecvitoria.local" /></div>
            <div class="field"><label for="email_to_addresses">Destinat?rios</label><input id="email_to_addresses" name="email_to_addresses" type="text" value="{to_addresses}" placeholder="ti@exemplo.com, noc@exemplo.com" /></div>
            <div class="field"><label for="email_subject_prefix">Prefixo do assunto</label><input id="email_subject_prefix" name="email_subject_prefix" type="text" value="{subject_prefix}" placeholder="[infra-sync-api]" /></div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label>Seguran?a da conex?o</label>
              <div class="check"><input type="checkbox" name="email_use_tls" {tls_checked} /><span>Usar STARTTLS</span></div>
              <div class="check"><input type="checkbox" name="email_use_ssl" {ssl_checked} /><span>Usar SSL direto</span></div>
            </div>
          </div>
        </div>
        """

    body = f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="kicker">ECV Network Control</div>
        <h1>Configuracao</h1>
        <p>Painel para manter tokens, URLs e chave de sync sem sair da central.</p>
      </div>
      <nav class="menu">
        <a href="/">Voltar ao dashboard</a>
        <a href="/api/config">Ver configuracao mascarada</a>
        <a href="/health">Saude da API</a>
      </nav>
      <div class="sidebar-footer">
        <div>Arquivo local</div>
        <div>{escape(str(RUNTIME_CONFIG_PATH))}</div>
      </div>
    </aside>
    <section class="content">
      <section class="topbar">
        <div>
          <h2 class="page-title">Configuracoes de integracao</h2>
          <div class="sub">Aqui voce informa ou troca tokens e URLs para NetBox, Zabbix, GLPI e n8n. As alteracoes passam a valer no sistema central logo apos salvar.</div>
        </div>
        <div class="actions">
          <a class="btn" href="/">Dashboard</a>
          <a class="btn" href="/docs">API</a>
        </div>
      </section>
      {"<div class='hero'><small>Salvo</small><strong>Configuracoes atualizadas com sucesso.</strong><div class='sub' style='margin: 6px 0 0;'>Os conectores foram recarregados.</div></div>" if saved else ""}
      <form method="post" action="/settings">
        <div class="panel" style="margin-bottom:14px;">
          <h2>Chave de sincronizacao</h2>
          <p>Essa chave protege os endpoints de sync. Se voce trocar aqui, os automations e integrações que usam API key precisam receber o novo valor.</p>
          <div class="form-grid">
            <div class="field">
              <label for="sync_api_key">SYNC API key</label>
              <input id="sync_api_key" name="sync_api_key" type="password" value="" placeholder="Deixe em branco para manter a atual" />
              <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(runtime["sync_api_key"])))}</div>
            </div>
          </div>
        </div>
        <div class="panel" style="margin-bottom:14px;">
          <h2>Atualização automática</h2>
          <p>Escolha de quanto em quanto tempo o painel deve recarregar os dados vindos dos devices e dos conectores integrados.</p>
          <div class="form-grid">
            <div class="field">
              <label for="refresh_enabled">Habilitar atualização automática</label>
              <input id="refresh_enabled" name="refresh_enabled" type="checkbox" {"checked" if refresh["enabled"] else ""} />
            </div>
            <div class="field">
              <label for="refresh_value">Intervalo</label>
              <input id="refresh_value" name="refresh_value" type="text" value="{escape(str(refresh["value"]))}" placeholder="30" />
            </div>
            <div class="field">
              <label for="refresh_unit">Unidade</label>
              <select id="refresh_unit" name="refresh_unit">
                <option value="seconds" {"selected" if refresh["unit"] == "seconds" else ""}>Segundos</option>
                <option value="minutes" {"selected" if refresh["unit"] == "minutes" else ""}>Minutos</option>
                <option value="hours" {"selected" if refresh["unit"] == "hours" else ""}>Horas</option>
                <option value="days" {"selected" if refresh["unit"] == "days" else ""}>Dias</option>
              </select>
            </div>
            <div class="field">
              <label>Equivalente em segundos</label>
              <input type="text" value="{escape(str(_refresh_interval_seconds(runtime)))}" readonly />
            </div>
          </div>
        </div>
        {email_block(email)}
        {_render_alert_sound_block(sound)}
        {_render_cpd_block(cpd)}
        <div class="form-grid">
          {connector_block("netbox", "NetBox", "Inventario, IPAM, VLANs, racks e dispositivos.", "https://netbox.example.local")}
          {connector_block("zabbix", "Zabbix", "Telemetria, eventos e SNMP.", "https://zabbix.example.local/zabbix/api_jsonrpc.php")}
          {connector_block("glpi", "GLPI", "Chamados e historico de atendimento.", "https://glpi.example.local/apirest.php")}
          {connector_block("n8n", "n8n", "Automacao e pequenas correcoes controladas.", "https://n8n.example.local")}
        </div>
        <div style="display:flex; gap:10px; margin-top:16px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Salvar configuracoes</button>
          <a class="btn" href="/">Voltar ao dashboard</a>
        </div>
      </form>
      <div class="foot">
        <div>Os valores vazios mantem o que ja esta salvo.</div>
        <div>Arquivo local: {escape(str(RUNTIME_CONFIG_PATH))}</div>
      </div>
    </section>
    """
    return _render_shell("Configuracao | infra-sync-api", body)


async def _read_form(request: Request) -> dict[str, str]:
    body = await request.body()
    if not body:
        return {}
    parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


@app.get("/discovery", include_in_schema=False)
async def discovery_page(request: Request, saved: int = 0, error: str | None = None):
    state = load_last_scan()
    state["progress"] = load_scan_progress()
    return HTMLResponse(_render_discovery_page(state, error=error, saved=bool(saved)))


@app.get("/discovery/progress", include_in_schema=False)
async def discovery_progress():
    return JSONResponse(load_scan_progress())


@app.post("/discovery/scan", include_in_schema=False)
async def discovery_scan(request: Request):
    form = await _read_form(request)
    network = form.get("network", "10.0.0.0/24").strip()
    community = form.get("community", "public").strip() or "public"
    timeout = float(form.get("timeout", "1.0") or "1.0")
    retries = int(form.get("retries", "0") or "0")
    max_hosts = int(form.get("max_hosts", "4096") or "4096")
    try:
        payload = await scan_network(network, community, timeout=timeout, retries=retries, max_hosts=max_hosts)
        payload["scan_community"] = community
        payload["scan_timeout"] = timeout
        payload["scan_retries"] = retries
        payload["scan_max_ports"] = 48
        payload["devices"] = await _annotate_discovered_devices(
            request,
            payload.get("devices") if isinstance(payload.get("devices"), list) else [],
            sync_with_netbox=False,
        )
        payload["ipam_prefix_status"] = await _ensure_discovery_prefix_in_netbox(request, payload.get("network", network))
        save_last_scan(payload)
        return HTMLResponse(_render_discovery_page(payload, saved=True))
    except Exception as exc:
        state = load_last_scan()
        state["network"] = network
        return HTMLResponse(_render_discovery_page(state, error=str(exc)), status_code=status.HTTP_400_BAD_REQUEST)


@app.post("/discovery/save", include_in_schema=False)
async def discovery_save(request: Request):
    form = await _read_form(request)
    state = load_last_scan()
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    settings: Settings = request.app.state.settings
    saved_devices: list[dict[str, Any]] = []
    operation = _normalize_text(form.get("operation")).lower() or "save"
    scan_community = _normalize_text(form.get("scan_community") or state.get("scan_community")) or "public"
    scan_timeout = float(form.get("scan_timeout") or state.get("scan_timeout") or 1.0)
    scan_retries = int(form.get("scan_retries") or state.get("scan_retries") or 0)
    scan_max_ports = int(form.get("scan_max_ports") or state.get("scan_max_ports") or 48)

    for device in devices:
        if not isinstance(device, dict):
            continue
        ip = str(device.get("ip", "")).strip()
        key = _device_key(ip)
        include = form.get(f"include_{key}") in {"on", "true", "True", "1", "checked", "yes"}
        existing_device_id = _related_id(device.get("netbox_device_id"))
        is_registered = bool(existing_device_id) or _normalize_text(device.get("system_status")) in {"Cadastrado", "Atualizado", "Criado"}
        if operation == "update" and not is_registered:
            include = False

        refresh_candidate = dict(device)
        if operation == "update" and include and is_registered and ip:
            refresh_candidate = await _refresh_discovered_device_from_snmp(
                refresh_candidate,
                community=scan_community,
                timeout=scan_timeout,
                retries=scan_retries,
                max_ports=scan_max_ports,
            )
        classified_group, classified_subgroup, notes = classify_discovered_device(
            sys_descr=str(refresh_candidate.get("sys_descr") or ""),
            sys_name=str(refresh_candidate.get("sys_name") or ""),
            sys_object_id=str(refresh_candidate.get("sys_object_id") or ""),
            manufacturer=str(refresh_candidate.get("manufacturer") or ""),
            model=str(refresh_candidate.get("model") or ""),
            device_type=str(refresh_candidate.get("device_type") or ""),
        )
        group = form.get(f"group_{key}") or str(refresh_candidate.get("suggested_group") or classified_group or refresh_candidate.get("group") or "hosts")
        subgroup = form.get(f"subgroup_{key}") or str(refresh_candidate.get("suggested_subgroup") or classified_subgroup or refresh_candidate.get("subgroup") or "fixed")
        enriched_device = {
            **refresh_candidate,
            "include": include,
            "group": group,
            "subgroup": subgroup,
            "suggested_group": classified_group,
            "suggested_subgroup": classified_subgroup,
            "notes": notes,
        }
        enriched_device = await _annotate_discovered_device(
            request,
            enriched_device,
            sync_with_netbox=include,
            settings=settings,
        )
        saved_devices.append(
            enriched_device
        )

    payload = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "network": state.get("network", ""),
        "count": len(saved_devices),
        "devices": saved_devices,
    }
    save_group_selections(payload)
    state["devices"] = saved_devices
    save_last_scan(state)
    return HTMLResponse(_render_discovery_page(state, saved=True))


def _device_key(ip: str) -> str:
    return ip.replace(".", "_")


def _discovery_group_options() -> list[tuple[str, str, list[str]]]:
    return [
        ("routers", "Roteadores", ["core", "distribution"]),
        ("switches", "Switches", ["core", "access", "wireless"]),
        ("printers", "Impressoras", ["office", "label"]),
        ("aps", "APs", ["indoor", "outdoor"]),
        ("cameras", "Cameras", ["ip", "ptz"]),
        ("recorders", "Gravadores", ["nvr", "dvr"]),
        ("servers", "Servidores", ["hypervisor", "physical"]),
        ("hosts", "Hosts", ["mobile", "notebook", "tablet", "desktop", "fixed"]),
    ]


def _discovery_group_select_options(selected_group: str) -> str:
    selected_value = _normalize_text(selected_group)
    return "".join(
        f'<option value="{escape(group_key)}" {"selected" if selected_value == group_key else ""}>{escape(label)}</option>'
        for group_key, label, _ in _discovery_group_options()
    )


def _discovery_subgroup_select_options(selected_group: str, selected_subgroup: str) -> str:
    selected_group_value = _normalize_text(selected_group)
    selected_subgroup_value = _normalize_text(selected_subgroup)
    options_by_group = {group_key: subgroups for group_key, _, subgroups in _discovery_group_options()}
    subgroups = options_by_group.get(selected_group_value, [])
    if not subgroups:
        subgroups = ["fixed"]
    return "".join(
        f'<option value="{escape(subgroup)}" {"selected" if selected_subgroup_value == subgroup else ""}>{escape(subgroup)}</option>'
        for subgroup in subgroups
    )


def _discovery_device_label(device: dict[str, Any]) -> str:
    name = _normalize_text(device.get("sys_name"))
    if name:
        return name
    ip = _normalize_text(device.get("ip"))
    if ip:
        return f"SCAN-{ip.replace('.', '-')}"
    return "SCAN-UNKNOWN"


def _discovery_role_id_for_group(group: str, settings: Settings) -> int:
    if group == "aps":
        return settings.default_access_point_role_id
    return settings.default_role_id


async def _discover_device_mac(client: NetBoxClient | None, device_id: Any) -> str:
    if client is None:
        return ""
    related_id = _related_id(device_id)
    if not related_id:
        return ""
    try:
        interfaces = await client.list_interfaces(params={"device_id": related_id, "limit": 100})
    except Exception:
        return ""
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        mac_address = _normalize_mac_text(interface.get("mac_address"))
        if mac_address:
            return mac_address
    return ""


async def _refresh_discovered_device_from_snmp(
    device: dict[str, Any],
    *,
    community: str,
    timeout: float,
    retries: int,
    max_ports: int,
) -> dict[str, Any]:
    ip = _normalize_text(device.get("ip"))
    if not ip:
        return device
    try:
        snapshot = await probe_snmp_device(ip, community, timeout=timeout, retries=retries, max_ports=max_ports)
    except Exception:
        return device

    refreshed = dict(device)
    refreshed["sys_descr"] = _normalize_text(snapshot.get("sys_descr")) or refreshed.get("sys_descr", "")
    refreshed["sys_name"] = _normalize_text(snapshot.get("sys_name")) or refreshed.get("sys_name", "")
    refreshed["sys_object_id"] = _normalize_text(snapshot.get("sys_object_id")) or refreshed.get("sys_object_id", "")
    refreshed["if_number"] = _normalize_text(snapshot.get("if_number")) or refreshed.get("if_number", "")
    refreshed["hr_memory_size"] = _normalize_text(snapshot.get("hr_memory_size")) or refreshed.get("hr_memory_size", "")
    refreshed["notes"] = _normalize_text(snapshot.get("notes")) or refreshed.get("notes", "")
    ports = snapshot.get("ports") if isinstance(snapshot.get("ports"), list) else []
    if ports:
        refreshed["ports"] = [port for port in ports if isinstance(port, dict)]
        refreshed["mac_address"] = next(
            (_normalize_mac_text(port.get("mac_address")) for port in refreshed["ports"] if _normalize_mac_text(port.get("mac_address"))),
            refreshed.get("mac_address", ""),
        )
    return refreshed


async def _discover_device_interface_count(client: NetBoxClient | None, device_id: Any) -> int:
    if client is None:
        return 0
    related_id = _related_id(device_id)
    if not related_id:
        return 0
    with suppress(Exception):
        details = await client.get_device(int(related_id))
        interface_count = details.get("interface_count")
        if isinstance(interface_count, int):
            return interface_count
    list_interfaces = getattr(client, "list_interfaces", None)
    if list_interfaces is None:
        return 0
    with suppress(Exception):
        interfaces = await list_interfaces({"device_id": related_id, "limit": 1000})
        return len([interface for interface in interfaces if isinstance(interface, dict)])
    return 0


def _discover_snmp_ports_for_ip(ip: str) -> list[dict[str, Any]]:
    last_probe = load_last_probe()
    probe = last_probe.get("last_probe") if isinstance(last_probe.get("last_probe"), dict) else None
    if not probe or _normalize_text(probe.get("ip")) != _normalize_text(ip):
        return []
    ports = probe.get("ports") if isinstance(probe.get("ports"), list) else []
    return [port for port in ports if isinstance(port, dict)]


async def _lookup_discovery_netbox_device(client: NetBoxClient | None, ip: str, name: str) -> dict[str, Any] | None:
    if client is None:
        return None
    if ip:
        try:
            matches = await client.find_devices_by_ip(ip)
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return matches[0]
        except Exception:
            pass
    if name:
        try:
            matches = await client.find_devices_by_name(name)
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return matches[0]
        except Exception:
            pass
    return None


def _discovery_device_status(device: dict[str, Any], existing: dict[str, Any] | None) -> tuple[str, str]:
    if existing is not None:
        name = _normalize_text(existing.get("name")) or _normalize_text(existing.get("display_name")) or _discovery_device_label(device)
        return "Cadastrado", f"Encontrado no inventário como {name}"
    if device.get("include") is False:
        return "Novo", "Ainda não cadastrado no inventário"
    return "Novo", "Pronto para criar no inventário"


def _existing_device_identity(existing: dict[str, Any] | None) -> tuple[str, str]:
    if not isinstance(existing, dict):
        return "", ""
    device_type = existing.get("device_type")
    manufacturer = ""
    model = ""
    if isinstance(device_type, dict):
        manufacturer = _relation_label(device_type.get("manufacturer"))
        model = _normalize_text(device_type.get("model"))
    elif device_type is not None:
        model = _relation_label(device_type)
    return manufacturer, model


def _normalized_comparison_text(value: Any) -> str:
    return _normalize_text(value).lower()


def _discovery_inventory_status(
    device: dict[str, Any],
    existing: dict[str, Any] | None,
    *,
    discovered_mac: str,
    existing_mac: str,
    discovered_interface_count: int,
    existing_interface_count: int,
) -> tuple[str, str]:
    if existing is None:
        return "Novo", "Ainda não cadastrado no inventário"

    expected_name = _normalize_text(device.get("sys_name")) or _discovery_device_label(device)
    current_name = _normalize_text(existing.get("name")) or _normalize_text(existing.get("display_name")) or expected_name
    expected_manufacturer = _normalized_comparison_text(device.get("manufacturer"))
    expected_model = _normalized_comparison_text(device.get("model") or device.get("device_type"))
    current_manufacturer, current_model = _existing_device_identity(existing)
    current_manufacturer = _normalized_comparison_text(current_manufacturer)
    current_model = _normalized_comparison_text(current_model)

    diffs: list[str] = []
    if expected_name and _normalized_comparison_text(current_name) != _normalized_comparison_text(expected_name):
        diffs.append("nome")
    if discovered_mac and existing_mac and _normalized_comparison_text(discovered_mac) != _normalized_comparison_text(existing_mac):
        diffs.append("MAC")
    if expected_manufacturer and current_manufacturer and expected_manufacturer != current_manufacturer:
        diffs.append("fabricante")
    if expected_model and current_model and expected_model != current_model:
        diffs.append("modelo")
    if discovered_interface_count and existing_interface_count and discovered_interface_count != existing_interface_count:
        diffs.append("interfaces")

    if diffs:
        return "Pendente atualização", f"Encontrado no inventário como {current_name}; diferenças: {', '.join(diffs)}"
    return "Atualizado", f"Encontrado no inventário como {current_name}; dados já estão atualizados no inventário"


async def _annotate_discovered_device(
    request: Request,
    device: dict[str, Any],
    *,
    sync_with_netbox: bool,
    settings: Settings | None = None,
) -> dict[str, Any]:
    annotated = dict(device)
    client = request.app.state.netbox_client
    settings = settings or request.app.state.settings
    ip = _normalize_text(annotated.get("ip"))
    name = _discovery_device_label(annotated)
    existing = await _lookup_discovery_netbox_device(client, ip, name)
    status, message = _discovery_device_status(annotated, existing)
    annotated["system_status"] = status
    annotated["system_message"] = message
    annotated["netbox_device_id"] = (
        _related_id(existing.get("id")) if isinstance(existing, dict) else None
    ) or _related_id(annotated.get("netbox_device_id"))
    annotated["netbox_device_name"] = _normalize_text(existing.get("name")) if isinstance(existing, dict) else ""
    discovered_mac = _normalize_mac_text(annotated.get("mac_address"))
    existing_mac = await _discover_device_mac(client, existing.get("id")) if isinstance(existing, dict) else ""
    discovered_ports = _discover_snmp_ports_for_ip(ip)
    existing_interface_count = await _discover_device_interface_count(client, existing.get("id")) if isinstance(existing, dict) else 0
    inventory_status, inventory_message = _discovery_inventory_status(
        annotated,
        existing,
        discovered_mac=discovered_mac,
        existing_mac=existing_mac,
        discovered_interface_count=len(discovered_ports),
        existing_interface_count=existing_interface_count,
    )
    annotated["inventory_status"] = inventory_status
    annotated["inventory_message"] = inventory_message
    annotated["discovered_mac_address"] = discovered_mac
    annotated["netbox_mac_address"] = existing_mac
    annotated["mac_address"] = discovered_mac or existing_mac
    if discovered_ports:
        annotated["ports"] = discovered_ports

    if not sync_with_netbox:
        return annotated
    if client is None:
        annotated["system_status"] = "NetBox indisponivel"
        annotated["system_message"] = "Conector NetBox não configurado"
        return annotated
    if not annotated.get("include", True):
        return annotated

    profile = infer_device_profile(
        sys_descr=_normalize_text(annotated.get("sys_descr")),
        sys_name=_normalize_text(annotated.get("sys_name")) or name,
        sys_object_id=_normalize_text(annotated.get("sys_object_id")),
    )
    device_name = _normalize_text(annotated.get("sys_name")) or (
        _normalize_text(existing.get("name")) if isinstance(existing, dict) and existing.get("name") else name
    )
    payload = SyncDeviceRequest(
        hostid=ip or device_name,
        hostname=device_name,
        display_name=device_name,
        ip=ip,
        fabricante=_normalize_text(annotated.get("manufacturer")) or profile["manufacturer"] or "GENERIC",
        modelo=_normalize_text(annotated.get("model")) or profile["model"] or profile["device_type"] or "Generico",
        site_id=settings.default_site_id,
        role_id=_discovery_role_id_for_group(_normalize_text(annotated.get("group")) or "hosts", settings),
        netbox_device_id=_related_id(annotated.get("netbox_device_id"))
        or (_related_id(existing.get("id")) if isinstance(existing, dict) else None),
        zabbix_status="active",
        mac_address=(
            _normalize_mac_text(annotated.get("discovered_mac_address"))
            or _normalize_mac_text(annotated.get("mac_address"))
            or None
        ),
        comments_summary=_normalize_text(annotated.get("notes")) or "Descoberto por ARP/Nmap + SNMP",
        netbox_status="active",
        ports=annotated.get("ports") if isinstance(annotated.get("ports"), list) else None,
    )
    try:
        outcome = await sync_device(payload, client, settings.default_site_id, dry_run=False)
    except Exception as exc:
        annotated["system_status"] = "Erro"
        annotated["system_message"] = str(exc)
        return annotated

    annotated["netbox_device_id"] = outcome.device_id
    annotated["system_action"] = outcome.action
    annotated["system_status"] = "Criado" if outcome.created_device else "Atualizado"
    annotated["system_message"] = outcome.message
    if outcome.warnings:
        annotated["system_warnings"] = outcome.warnings
    return annotated


async def _annotate_discovered_devices(
    request: Request,
    devices: list[dict[str, Any]],
    *,
    sync_with_netbox: bool,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    annotated_devices: list[dict[str, Any]] = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        annotated_devices.append(
            await _annotate_discovered_device(
                request,
                device,
                sync_with_netbox=sync_with_netbox,
                settings=settings,
            )
        )
    return annotated_devices


def _render_discovery_page(state: dict[str, Any], error: str | None = None, saved: bool = False) -> str:
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
    progress = state.get("progress") if isinstance(state.get("progress"), dict) else {}
    ipam_prefix_status = _normalize_text(state.get("ipam_prefix_status"))
    progress_status = str(progress.get("status") or "idle")
    progress_message = str(progress.get("message") or "Pronto para iniciar")
    progress_total = int(progress.get("total_hosts") or 0)
    progress_processed = int(progress.get("processed_hosts") or 0)
    progress_alive = int(progress.get("alive_hosts") or 0)
    progress_found = int(progress.get("found_devices") or 0)
    progress_percentage = int(progress.get("percentage") or 0)
    progress_width = max(0, min(100, progress_percentage))
    progress_label = {
        "running": "Varredura em andamento",
        "completed": "Varredura concluida",
        "failed": "Falha na varredura",
    }.get(progress_status, "Pronto para iniciar")
    progress_script = """
    <script>
      const discoveryForm = document.getElementById('discovery-scan-form');
      const discoveryButton = document.getElementById('discovery-scan-button');
      const discoveryScanOverlay = document.getElementById('discovery-scan-overlay');
      const discoveryScanModal = document.getElementById('discovery-scan-modal');
      const discoveryScanModalSpinner = document.getElementById('discovery-scan-modal-spinner');
      const discoveryScanModalText = document.getElementById('discovery-scan-modal-text');
      const discoveryScanModalOk = document.getElementById('discovery-scan-modal-ok');
      const discoveryScanModalCount = document.getElementById('discovery-scan-modal-count');
      const discoveryScanModalAlive = document.getElementById('discovery-scan-modal-alive');
      const discoveryScanModalFound = document.getElementById('discovery-scan-modal-found');
      const discoveryScanModalPercent = document.getElementById('discovery-scan-modal-percent');
      const discoveryScanModalBar = document.getElementById('discovery-scan-modal-bar');
      const discoverySaveOverlay = document.getElementById('discovery-save-overlay');
      const discoverySaveModal = document.getElementById('discovery-save-modal');
      const discoverySaveModalSpinner = document.getElementById('discovery-save-modal-spinner');
      const discoverySaveModalTitle = document.getElementById('discovery-save-modal-title');
      const discoverySaveModalText = document.getElementById('discovery-save-modal-text');
      const discoverySaveModalOk = document.getElementById('discovery-save-modal-ok');
      const discoverySaveOperation = document.getElementById('discovery-operation');
      const discoverySaveButton = document.getElementById('discovery-save-button');
      const discoveryUpdateButton = document.getElementById('discovery-update-button');
      const progressBar = document.getElementById('discovery-progress-bar');
      const progressMessage = document.getElementById('discovery-progress-message');
      const progressLabel = document.getElementById('discovery-progress-label');
      const progressPercent = document.getElementById('discovery-progress-percent');
      const progressCount = document.getElementById('discovery-progress-count');
      const progressAlive = document.getElementById('discovery-progress-alive');
      const progressFound = document.getElementById('discovery-progress-found');
      const toggleAllInclude = document.getElementById('discovery-toggle-all-include');
      let progressTimer = null;
      let activeScanId = '';
      let lastPercentage = 0;
      let lastProcessed = 0;
      let lastAlive = 0;
      let lastFound = 0;
      let saveBusy = false;
      let scanBusy = false;
      let scanCompletionShown = false;

      function resetProgressMemory(scanId) {
        activeScanId = scanId || '';
        lastPercentage = 0;
        lastProcessed = 0;
        lastAlive = 0;
        lastFound = 0;
      }

      function renderProgress(data) {
        const status = String(data?.status || 'idle');
        const scanId = String(data?.scan_id || '');
        if (scanId && scanId !== activeScanId) {
          resetProgressMemory(scanId);
        }
        const percentage = Math.max(0, Math.min(100, Number(data?.percentage || 0)));
        const processed = Math.max(0, Number(data?.processed_hosts || 0));
        const alive = Math.max(0, Number(data?.alive_hosts || 0));
        const found = Math.max(0, Number(data?.found_devices || 0));
        const safePercentage = scanId && scanId === activeScanId ? Math.max(lastPercentage, percentage) : percentage;
        const safeProcessed = scanId && scanId === activeScanId ? Math.max(lastProcessed, processed) : processed;
        const safeAlive = scanId && scanId === activeScanId ? Math.max(lastAlive, alive) : alive;
        const safeFound = scanId && scanId === activeScanId ? Math.max(lastFound, found) : found;
        progressBar.style.width = `${safePercentage}%`;
        progressPercent.textContent = `${safePercentage}%`;
        progressMessage.textContent = String(data?.message || 'Pronto para iniciar');
        progressCount.textContent = `${safeProcessed} / ${Number(data?.total_hosts || 0)} hosts`;
        progressAlive.textContent = `${safeAlive} hosts vivos`;
        progressFound.textContent = `${safeFound} devices encontrados`;
        if (discoveryScanModalCount) {
          discoveryScanModalCount.textContent = `${safeProcessed} / ${Number(data?.total_hosts || 0)}`;
        }
        if (discoveryScanModalAlive) {
          discoveryScanModalAlive.textContent = String(safeAlive);
        }
        if (discoveryScanModalFound) {
          discoveryScanModalFound.textContent = String(safeFound);
        }
        if (discoveryScanModalPercent) {
          discoveryScanModalPercent.textContent = `${safePercentage}%`;
        }
        if (discoveryScanModalBar) {
          discoveryScanModalBar.style.width = `${safePercentage}%`;
        }
        progressLabel.textContent = status === 'running'
          ? 'Varredura em andamento'
          : status === 'completed'
            ? 'Varredura concluida'
            : status === 'failed'
              ? 'Falha na varredura'
              : 'Pronto para iniciar';
        if (discoveryScanModalText && status === 'running') {
          discoveryScanModalText.textContent = `${progressLabel.textContent}: ${data?.message || 'Processando hosts na rede.'}`;
        } else if (discoveryScanModalText && status === 'completed') {
          discoveryScanModalText.textContent = String(data?.message || 'Varredura concluida com sucesso.');
        } else if (discoveryScanModalText && status === 'failed') {
          discoveryScanModalText.textContent = `Falha na varredura: ${data?.message || 'Erro inesperado.'}`;
        }
        progressBar.style.background = status === 'failed'
          ? 'linear-gradient(90deg, #991b1b, #ef4444)'
          : 'linear-gradient(90deg, #b91c1c, #ef4444)';
        const activeScanInProgress = progressTimer !== null || scanBusy;
        if (status === 'completed' && activeScanInProgress && !scanCompletionShown) {
          if (progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
          }
          discoveryButton.disabled = false;
          discoveryButton.textContent = 'Varredura SNMP';
          showScanSuccess('Varredura concluida com sucesso.');
        } else if (status === 'failed' && activeScanInProgress && !scanCompletionShown) {
          if (progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
          }
          discoveryButton.disabled = false;
          discoveryButton.textContent = 'Varredura SNMP';
          showScanFailure(String(data?.message || 'Falha na varredura.'));
        }
        if (scanId) {
          lastPercentage = safePercentage;
          lastProcessed = safeProcessed;
          lastAlive = safeAlive;
          lastFound = safeFound;
        }
      }

      function openSaveOverlay(message) {
        saveBusy = true;
        if (discoverySaveOverlay) {
          discoverySaveOverlay.style.display = 'flex';
        }
        if (discoverySaveModal) {
          discoverySaveModal.style.display = 'block';
        }
        if (discoverySaveModalSpinner) {
          discoverySaveModalSpinner.style.display = 'inline-block';
        }
        if (discoverySaveModalTitle) {
          discoverySaveModalTitle.textContent = 'Salvamento em andamento';
        }
        if (discoverySaveModalOk) {
          discoverySaveModalOk.style.display = 'none';
        }
        if (discoverySaveModalText) {
          discoverySaveModalText.textContent = message || 'Salvando classificacao...';
        }
      }

      function closeSaveOverlay() {
        saveBusy = false;
        if (discoverySaveOverlay) {
          discoverySaveOverlay.style.display = 'none';
        }
      }

      function showSaveSuccess(message) {
        saveBusy = false;
        if (discoverySaveModalSpinner) {
          discoverySaveModalSpinner.style.display = 'none';
        }
        if (discoverySaveModalTitle) {
          discoverySaveModalTitle.textContent = 'Salvamento concluído';
        }
        if (discoverySaveModalText) {
          discoverySaveModalText.textContent = message || 'Classificacao salva com sucesso.';
        }
        if (discoverySaveOverlay) {
          discoverySaveOverlay.style.display = 'flex';
        }
        if (discoverySaveModal) {
          discoverySaveModal.style.display = 'block';
        }
        if (discoverySaveModalOk) {
          discoverySaveModalOk.style.display = 'inline-flex';
        }
      }

      function openScanOverlay(message) {
        scanBusy = true;
        scanCompletionShown = false;
        if (discoveryScanOverlay) {
          discoveryScanOverlay.style.display = 'flex';
        }
        if (discoveryScanModal) {
          discoveryScanModal.style.display = 'block';
        }
        if (discoveryScanModalSpinner) {
          discoveryScanModalSpinner.style.display = 'inline-block';
        }
        if (discoveryScanModalOk) {
          discoveryScanModalOk.style.display = 'none';
        }
        if (discoveryScanModalText) {
          discoveryScanModalText.textContent = message || 'Iniciando varredura...';
        }
      }

      function closeScanOverlay() {
        scanBusy = false;
        scanCompletionShown = false;
        if (discoveryScanOverlay) {
          discoveryScanOverlay.style.display = 'none';
        }
      }

      function showScanSuccess(message) {
        scanBusy = false;
        scanCompletionShown = true;
        if (discoveryScanModalSpinner) {
          discoveryScanModalSpinner.style.display = 'none';
        }
        if (discoveryScanModalText) {
          discoveryScanModalText.textContent = message || 'Varredura concluida com sucesso.';
        }
        if (discoveryScanOverlay) {
          discoveryScanOverlay.style.display = 'flex';
        }
        if (discoveryScanModal) {
          discoveryScanModal.style.display = 'block';
        }
        if (discoveryScanModalOk) {
          discoveryScanModalOk.style.display = 'inline-flex';
        }
      }

      function showScanFailure(message) {
        scanBusy = false;
        scanCompletionShown = true;
        if (discoveryScanModalSpinner) {
          discoveryScanModalSpinner.style.display = 'none';
        }
        if (discoveryScanModalText) {
          discoveryScanModalText.textContent = message || 'Falha na varredura.';
        }
        if (discoveryScanOverlay) {
          discoveryScanOverlay.style.display = 'flex';
        }
        if (discoveryScanModal) {
          discoveryScanModal.style.display = 'block';
        }
        if (discoveryScanModalOk) {
          discoveryScanModalOk.style.display = 'inline-flex';
        }
      }

      function getIncludeCheckboxes() {
        return Array.from(document.querySelectorAll('input[type="checkbox"][name^="include_"]'));
      }

      function syncToggleAllState() {
        if (!toggleAllInclude) {
          return;
        }
        const checkboxes = getIncludeCheckboxes();
        const checkedCount = checkboxes.filter((checkbox) => checkbox.checked).length;
        toggleAllInclude.checked = checkboxes.length > 0 && checkedCount === checkboxes.length;
        toggleAllInclude.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
      }

      function setAllIncludeState(checked) {
        getIncludeCheckboxes().forEach((checkbox) => {
          checkbox.checked = checked;
        });
        syncToggleAllState();
      }

      async function refreshProgress() {
        try {
          const response = await fetch('/discovery/progress', { cache: 'no-store' });
          if (!response.ok) {
            return;
          }
          const data = await response.json();
          renderProgress(data);
          if (data.status !== 'running' && progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
            discoveryButton.disabled = false;
            discoveryButton.textContent = 'Varredura SNMP';
          }
          if (!progressTimer && !scanBusy && (data.status === 'completed' || data.status === 'failed')) {
            scanCompletionShown = true;
          }
        } catch (error) {
          console.error('Falha ao ler progresso da varredura', error);
        }
      }

      async function submitDiscoveryScan(event) {
        event.preventDefault();
        if (scanBusy) {
          return;
        }
        if (progressTimer) {
          clearInterval(progressTimer);
          progressTimer = null;
        }
        openScanOverlay('Iniciando varredura SNMP...');
        discoveryButton.disabled = true;
        discoveryButton.textContent = 'Executando...';
        resetProgressMemory('');
        renderProgress({ status: 'running', message: 'Iniciando varredura...', percentage: 0, processed_hosts: 0, total_hosts: 0, alive_hosts: 0, found_devices: 0 });
        progressTimer = setInterval(refreshProgress, 1000);
        await refreshProgress();

        try {
          const formData = new URLSearchParams(new FormData(discoveryForm));
          const response = await fetch(discoveryForm.action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
            body: formData.toString(),
          });
          const html = await response.text();
          if (!response.ok) {
            closeScanOverlay();
            document.open();
            document.write(html);
            document.close();
            return;
          }
          await refreshProgress();
          if (!scanCompletionShown) {
            showScanSuccess('Varredura concluida com sucesso.');
          }
        } catch (error) {
          console.error('Falha ao executar varredura', error);
          closeScanOverlay();
        } finally {
          if (progressTimer) {
            clearInterval(progressTimer);
            progressTimer = null;
          }
          discoveryButton.disabled = false;
          discoveryButton.textContent = 'Varredura SNMP';
        }
      }

      async function submitDiscoverySave(event) {
        event.preventDefault();
        if (saveBusy) {
          return;
        }
        const operation = String(discoverySaveOperation?.value || 'save');
        const isUpdate = operation === 'update';
        openSaveOverlay(isUpdate ? 'Atualizando dados dos devices salvos...' : 'Salvando classificacao...');
        try {
          const formData = new URLSearchParams(new FormData(discoverySaveForm));
          const response = await fetch(discoverySaveForm.action, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
            body: formData.toString(),
          });
          const html = await response.text();
          if (!response.ok) {
            closeSaveOverlay();
            document.open();
            document.write(html);
            document.close();
            return;
          }
          showSaveSuccess(isUpdate ? 'Atualizacao concluida com sucesso.' : 'Classificacao salva com sucesso.');
        } catch (error) {
          console.error('Falha ao salvar classificacao', error);
          closeSaveOverlay();
          return;
        }
      }

      if (discoveryForm) {
        discoveryForm.addEventListener('submit', submitDiscoveryScan);
      }
      const discoverySaveForm = document.getElementById('discovery-save-form');
      if (discoverySaveForm) {
        discoverySaveForm.addEventListener('submit', submitDiscoverySave);
      }
      if (discoverySaveButton) {
        discoverySaveButton.addEventListener('click', () => {
          if (discoverySaveOperation) {
            discoverySaveOperation.value = 'save';
          }
        });
      }
      if (discoveryUpdateButton) {
        discoveryUpdateButton.addEventListener('click', () => {
          if (discoverySaveOperation) {
            discoverySaveOperation.value = 'update';
          }
        });
      }
      if (discoverySaveModalOk) {
        discoverySaveModalOk.addEventListener('click', () => {
          closeSaveOverlay();
          window.location.reload();
        });
      }
      if (discoveryScanModalOk) {
        discoveryScanModalOk.addEventListener('click', () => {
          closeScanOverlay();
          window.location.reload();
        });
      }
      if (toggleAllInclude) {
        toggleAllInclude.addEventListener('change', () => {
          setAllIncludeState(toggleAllInclude.checked);
        });
      }
      getIncludeCheckboxes().forEach((checkbox) => {
        checkbox.addEventListener('change', syncToggleAllState);
      });
      syncToggleAllState();
      refreshProgress();
    </script>
    """
    rows = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        ip = str(device.get("ip", "")).strip()
        key = _device_key(ip)
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(ip or '?')}</strong></td>
              <td>{escape(str(device.get("mac_address") or '—'))}</td>
              <td>{escape(str(device.get("sys_name") or '?'))}</td>
              <td>{escape(str(device.get("device_type") or '?'))}</td>
              <td>{escape(str(device.get("model") or '?'))}</td>
              <td style="max-width:280px;">{escape(str(device.get("sys_descr") or '?'))}</td>
              <td>
                <select name="group_{key}" style="min-width:140px;">
                  {_discovery_group_select_options(str(device.get("group") or "hosts"))}
                </select>
              </td>
              <td>
                <select name="subgroup_{key}" style="min-width:140px;">
                  {_discovery_subgroup_select_options(str(device.get("group") or "hosts"), str(device.get("subgroup") or "fixed"))}
                </select>
              </td>
              <td>{_render_status_badge(str(device.get("inventory_status") or "Novo"), str(device.get("inventory_message") or ""))}</td>
              <td>{_render_status_badge(str(device.get("system_status") or "Novo"), str(device.get("system_message") or ""))}</td>
              <td>
                <label class="check" style="margin:0;">
                  <input type="checkbox" name="include_{key}" {"checked" if device.get("include", True) else ""} />
                  <span>Incluir</span>
                </label>
              </td>
            </tr>
            """
        )

    body = f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="kicker">ECV Network Control</div>
        <h1>Varredura SNMP</h1>
        <p>Informe a rede, execute a busca e classifique os dispositivos encontrados antes de inserir nos grupos.</p>
      </div>
      <nav class="menu">
        <a href="/">Voltar ao dashboard</a>
        <a href="/settings">Editar conectores</a>
        <a href="/health">Saude da API</a>
      </nav>
      <div class="sidebar-footer">
        <div>Resultado salvo</div>
        <div>{escape(state.get("scanned_at") or "sem varredura")}</div>
      </div>
    </aside>
    <section class="content">
      <section class="topbar">
        <div>
          <h2 class="page-title">Descoberta SNMP</h2>
          <div class="sub">A varredura fica restrita a redes privadas IPv4. Depois do scan, voce decide o grupo e o subgrupo de cada equipamento.</div>
        </div>
        <div class="actions">
          <a class="btn" href="/">Dashboard</a>
          <a class="btn" href="/settings">Conectores</a>
        </div>
      </section>
      {"<div class='hero'><small>Salvo</small><strong>Classificacao gravada com sucesso.</strong><div class='sub' style='margin: 6px 0 0;'>Os dispositivos selecionados foram registrados localmente.</div></div>" if saved else ""}
      {f"<div class='hero'><small>Erro</small><strong>{escape(error)}</strong></div>" if error else ""}
      {f"<div class='hero'><small>IPAM</small><strong>{escape(ipam_prefix_status)}</strong><div class='sub' style='margin: 6px 0 0;'>O prefixo da rede descoberta foi sincronizado no NetBox.</div></div>" if ipam_prefix_status else ""}
      <div class="panel" style="margin-bottom:14px;">
        <h2>Executar varredura</h2>
        <p>Use uma rede privada como 10.0.0.0/24. O sistema consulta SNMP e monta uma lista de dispositivos com sugestao de grupo.</p>
        <form id="discovery-scan-form" method="post" action="/discovery/scan">
          <div class="form-grid">
            <div class="field">
              <label for="network">Rede</label>
              <input id="network" name="network" type="text" value="{escape(state.get("network") or "10.0.0.0/24")}" placeholder="10.0.0.0/24" />
            </div>
            <div class="field">
              <label for="community">Community</label>
              <input id="community" name="community" type="password" value="" placeholder="public" />
            </div>
            <div class="field">
              <label for="timeout">Timeout</label>
              <input id="timeout" name="timeout" type="text" value="1.0" />
            </div>
            <div class="field">
              <label for="retries">Retries</label>
              <input id="retries" name="retries" type="text" value="0" />
            </div>
          </div>
          <div style="display:flex; gap:10px; margin-top:14px; flex-wrap:wrap;">
            <button class="btn primary" id="discovery-scan-button" type="submit">Varredura SNMP</button>
          </div>
        </form>
      </div>
      <div class="panel" style="margin-bottom:14px;">
        <h2>Progresso da varredura</h2>
        <p id="discovery-progress-message">{escape(progress_message)}</p>
        <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:8px;">
          <strong id="discovery-progress-label">{escape(progress_label)}</strong>
          <span id="discovery-progress-percent">{escape(str(progress_width))}%</span>
        </div>
        <div style="height:16px; border-radius:999px; background:#1f2937; overflow:hidden; border:1px solid rgba(255,255,255,0.08);">
          <div id="discovery-progress-bar" style="height:100%; width:{progress_width}%; background:linear-gradient(90deg, #b91c1c, #ef4444); transition:width .25s ease;"></div>
        </div>
        <div style="display:flex; gap:14px; flex-wrap:wrap; margin-top:10px; color:#cbd5e1;">
          <span id="discovery-progress-count">{progress_processed} / {progress_total} hosts</span>
          <span id="discovery-progress-alive">{progress_alive} hosts vivos</span>
          <span id="discovery-progress-found">{progress_found} devices encontrados</span>
        </div>
      </div>
      <div id="discovery-scan-overlay" style="display:none; position:fixed; inset:0; z-index:1000; align-items:center; justify-content:center; background:rgba(2,6,23,.82); backdrop-filter:blur(6px); padding:24px;">
        <div id="discovery-scan-modal" style="width:min(560px, 100%); border-radius:18px; border:1px solid rgba(255,255,255,.10); background:#111317; box-shadow:0 30px 80px rgba(0,0,0,.45); padding:22px;">
          <div style="display:flex; align-items:center; gap:14px;">
            <div id="discovery-scan-modal-spinner" style="width:18px; height:18px; border-radius:999px; border:3px solid rgba(239,68,68,.25); border-top-color:#ef4444; animation:spin 1s linear infinite;"></div>
            <strong style="font-size:18px; color:#fff;">Varredura SNMP em andamento</strong>
          </div>
          <p id="discovery-scan-modal-text" style="margin:14px 0 16px; color:#d1d5db; line-height:1.5;">Iniciando varredura SNMP...</p>
          <div style="display:grid; grid-template-columns:repeat(4, minmax(0, 1fr)); gap:10px; margin-bottom:16px;">
            <div style="border-radius:14px; border:1px solid rgba(255,255,255,.08); background:#0f1115; padding:12px;">
              <div style="font-size:11px; color:#9ca3af; text-transform:uppercase;">Hosts</div>
              <strong id="discovery-scan-modal-count" style="font-size:20px; color:#fff;">0 / 0</strong>
            </div>
            <div style="border-radius:14px; border:1px solid rgba(255,255,255,.08); background:#0f1115; padding:12px;">
              <div style="font-size:11px; color:#9ca3af; text-transform:uppercase;">Vivos</div>
              <strong id="discovery-scan-modal-alive" style="font-size:20px; color:#fff;">0</strong>
            </div>
            <div style="border-radius:14px; border:1px solid rgba(255,255,255,.08); background:#0f1115; padding:12px;">
              <div style="font-size:11px; color:#9ca3af; text-transform:uppercase;">Devices</div>
              <strong id="discovery-scan-modal-found" style="font-size:20px; color:#fff;">0</strong>
            </div>
            <div style="border-radius:14px; border:1px solid rgba(255,255,255,.08); background:#0f1115; padding:12px;">
              <div style="font-size:11px; color:#9ca3af; text-transform:uppercase;">Progresso</div>
              <strong id="discovery-scan-modal-percent" style="font-size:20px; color:#fff;">0%</strong>
            </div>
          </div>
          <div style="height:14px; border-radius:999px; background:#1f2937; overflow:hidden; border:1px solid rgba(255,255,255,0.08);">
            <div id="discovery-scan-modal-bar" style="height:100%; width:0%; background:linear-gradient(90deg, #b91c1c, #ef4444); transition:width .25s ease;"></div>
          </div>
          <div style="display:flex; justify-content:flex-end; margin-top:18px;">
            <button id="discovery-scan-modal-ok" type="button" class="btn primary" style="display:none;">OK</button>
          </div>
        </div>
      </div>
      <div id="results" class="panel">
        <h2>Resultados</h2>
        <p>{escape(str(len(devices)))} itens encontrados para enriquecer o inventario (ARP/Nmap + SNMP).</p>
        <form id="discovery-save-form" method="post" action="/discovery/save">
          <div id="discovery-save-overlay" style="display:none; position:fixed; inset:0; z-index:1000; align-items:center; justify-content:center; background:rgba(2,6,23,.82); backdrop-filter:blur(6px); padding:24px;">
            <style>@keyframes spin {{ to {{ transform: rotate(360deg); }} }}</style>
            <div id="discovery-save-modal" style="display:none; width:min(460px, 100%); border-radius:18px; border:1px solid rgba(255,255,255,.10); background:#111317; box-shadow:0 30px 80px rgba(0,0,0,.45); padding:22px;">
              <div style="display:flex; align-items:center; gap:14px;">
                <div id="discovery-save-modal-spinner" style="width:18px; height:18px; border-radius:999px; border:3px solid rgba(239,68,68,.25); border-top-color:#ef4444; animation:spin 1s linear infinite;"></div>
                <strong id="discovery-save-modal-title" style="font-size:18px; color:#fff;">Salvamento em andamento</strong>
              </div>
              <p id="discovery-save-modal-text" style="margin:14px 0 18px; color:#d1d5db; line-height:1.5;">Salvando classificacao...</p>
              <div style="display:flex; justify-content:flex-end;">
                <button id="discovery-save-modal-ok" type="button" class="btn primary" style="display:none;">OK</button>
              </div>
            </div>
          </div>
          <input type="hidden" id="discovery-operation" name="operation" value="save" />
          <input type="hidden" name="network" value="{escape(state.get("network") or "")}" />
          <input type="hidden" name="scan_community" value="{escape(str(state.get("scan_community") or "public"))}" />
          <input type="hidden" name="scan_timeout" value="{escape(str(state.get("scan_timeout") or "1.0"))}" />
          <input type="hidden" name="scan_retries" value="{escape(str(state.get("scan_retries") or "0"))}" />
          <input type="hidden" name="scan_max_ports" value="{escape(str(state.get("scan_max_ports") or "48"))}" />
          <div style="display:flex; justify-content:flex-end; margin-bottom:10px;">
            <label class="check" style="margin:0;">
              <input type="checkbox" id="discovery-toggle-all-include" />
              <span>Marcar / desmarcar todos</span>
            </label>
          </div>
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>MAC</th>
                <th>Nome</th>
                <th>Tipo</th>
                <th>Modelo</th>
                <th>Descrição</th>
                <th>Grupo</th>
                <th>Subgrupo</th>
                <th>Inventário</th>
                <th>Status sistema</th>
                <th>Incluir</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows) if rows else '<tr><td colspan="10">Nenhum dispositivo na ultima varredura.</td></tr>'}
            </tbody>
          </table>
          <div style="display:flex; gap:10px; margin-top:14px; flex-wrap:wrap;">
            <button id="discovery-save-button" class="btn primary" type="submit">Salvar classificacao</button>
            <button id="discovery-update-button" class="btn" type="submit">Atualizar dados</button>
            <a class="btn" href="/discovery">Recarregar</a>
          </div>
        </form>
      </div>
      <div class="foot">
        <div>Grupo padrao: switches, servidores e hosts.</div>
        <div>O resultado fica salvo em disco para revisao posterior.</div>
      </div>
    </section>
    {progress_script}
    """
    return _render_shell("Descoberta SNMP | infra-sync-api", body)


def _management_nav(active: str) -> str:
    items = [
        ("overview", "/", "Dashboard", "Resumo operacional"),
        ("devices", "/devices", "Devices", "Criar e editar equipamentos"),
        ("vlans", "/vlans", "VLANs", "Segmentacao e tags"),
        ("networks", "/networks", "IPAM", "Prefixes, IPs e blocos IP"),
        ("snmp", "/snmp", "SNMP", "Portas, CPU e tráfego"),
        ("alerts", "/alerts", "Alertas", "Problemas em tempo real"),
        ("reports", "/reports", "Relatorios", "Impressao e exportacao"),
        ("discovery", "/discovery", "Descoberta", "Varredura SNMP"),
        ("settings", "/settings", "Configuracao", "Tokens e URLs"),
    ]
    return "".join(
        f'<a class="{"active" if key == active else ""}" href="{escape(href)}">{escape(label)}<span class="meta">{escape(meta)}</span></a>'
        for key, href, label, meta in items
    )


def _relation_label(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("display", "name", "label", "slug"):
            text = _normalize_text(value.get(key))
            if text:
                return text
        related_id = value.get("id")
        if related_id is not None:
            return str(related_id)
        return "—"
    text = _normalize_text(value)
    return text or "—"


def _status_value(value: Any, default: str = "active") -> str:
    if isinstance(value, dict):
        for key in ("value", "slug", "name", "label"):
            text = _normalize_text(value.get(key))
            if text:
                return text
        return default
    text = _normalize_text(value)
    return text or default


def _render_status_badge(label: str, title: str = "") -> str:
    normalized = _normalize_text(label).lower()
    if normalized in {"cadastrado"}:
        color = "#16a34a"
    elif normalized in {"atualizado"}:
        color = "#7c3aed"
    elif normalized in {"pendente atualização", "pendente atualizacao", "pendente"}:
        color = "#f59e0b"
    elif normalized in {"novo"}:
        color = "#f59e0b"
    elif normalized in {"criado"}:
        color = "#db2777"
    elif normalized in {"erro", "falha"}:
        color = "#dc2626"
    elif normalized in {"netbox indisponivel", "netbox indisponível"}:
        color = "#ea580c"
    else:
        color = "#475569"
    title_attr = f' title="{escape(title)}"' if title else ""
    return f'<span style="display:inline-flex; align-items:center; padding:4px 10px; border-radius:999px; background:{color}; color:#fff; font-size:12px; font-weight:700;"{title_attr}>{escape(label)}</span>'


def _render_port_status_badge(label: str) -> str:
    normalized = _normalize_text(label).lower()
    if normalized == "up":
        color = "#16a34a"
    elif normalized in {"down", "lowerlayerdown"}:
        color = "#dc2626"
    elif normalized in {"testing", "dormant", "unknown", "notpresent"}:
        color = "#f59e0b"
    else:
        color = "#475569"
    return f'<span style="display:inline-flex; align-items:center; padding:3px 8px; border-radius:999px; background:{color}; color:#fff; font-size:12px; font-weight:700;">{escape(label or "—")}</span>'


def _related_id(value: Any) -> str:
    if isinstance(value, dict):
        text = value.get("id")
        return str(text) if text is not None else ""
    return _normalize_text(value)


async def _ensure_discovery_prefix_in_netbox(request: Request, network: str) -> str:
    client = request.app.state.netbox_client
    network_value = _normalize_text(network)
    if client is None or not network_value:
        return ""

    try:
        existing_prefixes = await client.list_prefixes(params={"prefix": network_value, "limit": 10})
    except Exception as exc:
        return f"Nao foi possivel consultar o IPAM para criar o prefixo {network_value}: {exc}"

    for prefix in existing_prefixes:
        if isinstance(prefix, dict) and _normalize_text(prefix.get("prefix")) == network_value:
            return f"Prefixo {network_value} ja estava cadastrado no IPAM."

    payload = {
        "prefix": network_value,
        "status": "active",
        "description": f"Rede criada automaticamente pela descoberta SNMP em {datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')}",
    }
    try:
        await client.create_prefix(payload)
        return f"Prefixo {network_value} criado no IPAM a partir da varredura."
    except Exception as exc:
        return f"Nao foi possivel criar o prefixo {network_value} no IPAM: {exc}"


async def _collect_ipam_address_rows(client: NetBoxClient | None, search: str = "") -> list[dict[str, Any]]:
    if client is None:
        return []

    params: dict[str, Any] = {"limit": 100}
    search_value = _normalize_text(search)
    if search_value:
        params["q"] = search_value

    try:
        ip_addresses = await client.list_ip_addresses(params=params)
    except Exception:
        return []

    interface_cache: dict[str, dict[str, Any] | None] = {}
    rows: list[dict[str, Any]] = []
    for ip_address in ip_addresses:
        if not isinstance(ip_address, dict):
            continue

        assigned_object = ip_address.get("assigned_object") if isinstance(ip_address.get("assigned_object"), dict) else None
        assigned_type = _normalize_text(ip_address.get("assigned_object_type"))
        assigned_id = _related_id(ip_address.get("assigned_object_id"))
        interface = assigned_object

        if interface is None and assigned_type == "dcim.interface" and assigned_id:
            cached_interface = interface_cache.get(assigned_id)
            if cached_interface is None:
                try:
                    cached_interface = await client.get_interface(int(assigned_id))
                except Exception:
                    cached_interface = None
                interface_cache[assigned_id] = cached_interface
            interface = cached_interface

        device = None
        if isinstance(interface, dict):
            device = interface.get("device") if interface.get("device") is not None else None

        device_id = _related_id(device)
        device_name = _relation_label(device)
        interface_name = _relation_label(interface) if isinstance(interface, dict) else ""
        if isinstance(interface, dict) and not interface_name:
            interface_name = _normalize_text(interface.get("name")) or _normalize_text(interface.get("display")) or "—"

        assigned_label = assigned_type or "—"
        rows.append(
            {
                "address": _normalize_text(ip_address.get("address")) or "—",
                "status": _relation_label(ip_address.get("status")),
                "assigned_label": assigned_label,
                "device_id": device_id,
                "device_name": device_name,
                "device_link": f'<a href="/devices/view/{escape(device_id)}"><strong>{escape(device_name)}</strong></a>' if device_id else "—",
                "interface_name": interface_name or "—",
                "tenant": _relation_label(ip_address.get("tenant")),
                "role": _relation_label(ip_address.get("role")),
                "description": _normalize_text(ip_address.get("description")) or "—",
            }
        )

    return rows


def _custom_field_pairs(custom_fields: dict[str, Any] | None, limit: int = 6) -> list[tuple[str, str]]:
    items = []
    source = custom_fields or {}
    if isinstance(source, dict):
        items.extend((str(key), "" if value is None else str(value)) for key, value in source.items() if str(key).strip())
    while len(items) < limit:
        items.append(("", ""))
    return items[:limit]


def _parse_custom_fields_form(form: dict[str, str], *, limit: int = 6) -> dict[str, Any]:
    custom_fields: dict[str, Any] = {}
    for index in range(1, limit + 1):
        key = _form_value(form, f"custom_field_key_{index}")
        value = _form_value(form, f"custom_field_value_{index}")
        if key:
            custom_fields[key] = value
    raw_json = _form_value(form, "custom_fields_json")
    if raw_json:
        parsed = json.loads(raw_json)
        if not isinstance(parsed, dict):
            raise ValueError("custom_fields_json must be a JSON object")
        for key, value in parsed.items():
            if str(key).strip():
                custom_fields[str(key)] = value
    return custom_fields


def _default_topology_state() -> dict[str, Any]:
    return {"entries": []}


def load_network_topology() -> dict[str, Any]:
    return _load_json(TOPOLOGY_CONFIG_PATH, default=_default_topology_state())


def save_network_topology(payload: dict[str, Any]) -> None:
    _save_json(TOPOLOGY_CONFIG_PATH, payload)


def _network_topology_entries(state: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(state, dict):
        return []
    entries = state.get("entries")
    return [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []


def _topology_entry_for_prefix(topology_state: dict[str, Any] | None, prefix_id: Any) -> dict[str, Any] | None:
    if prefix_id in (None, "") or not isinstance(topology_state, dict):
        return None
    target = str(prefix_id)
    for entry in _network_topology_entries(topology_state):
        if str(entry.get("prefix_id")) == target:
            return entry
    return None


def _render_device_choice_options(devices: list[dict[str, Any]], selected: Any = "") -> str:
    selected_value = str(selected or "")
    options = ['<option value="">-</option>']
    for device in devices:
        if not isinstance(device, dict):
            continue
        value = _related_id(device.get("id"))
        label = _normalize_text(device.get("name")) or value or "-"
        site = _relation_label(device.get("site"))
        if site and site != "—":
            label = f"{label} ({site})"
        current = " selected" if value and value == selected_value else ""
        options.append(f'<option value="{escape(value)}"{current}>{escape(label)}</option>')
    return "".join(options)


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    return data if isinstance(data, dict) else default


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _query_value(request: Request, name: str, default: str = "") -> str:
    return _normalize_text(request.query_params.get(name, default))


def _query_int(request: Request, name: str) -> int | None:
    text = _query_value(request, name)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _checkbox_value(form: dict[str, str], key: str, default: bool = False) -> bool:
    if key not in form:
        return default
    return form.get(key) in {"on", "true", "True", "1", "yes", "checked"}


def _render_management_page(
    *,
    title: str,
    active: str,
    heading: str,
    subtitle: str,
    body: str,
    actions: str = "",
    banner: str = "",
) -> str:
    return _render_shell(
        title,
        f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="kicker">ECV Network Control</div>
        <h1>Rede</h1>
        <p>Central de operação para inventário, IPAM, alertas e automação.</p>
      </div>
      <nav class="menu">
        {_management_nav(active)}
      </nav>
      <div class="sidebar-footer">
        <div>infra-sync-api v{escape(__version__)}</div>
        <div>{escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
      </div>
    </aside>
    <section class="content">
      <section class="topbar">
        <div>
          <h2 class="page-title">{escape(heading)}</h2>
          <div class="sub">{escape(subtitle)}</div>
        </div>
        <div class="actions">
          {actions}
        </div>
      </section>
      {banner}
      {body}
      <div class="foot">
        <div>Tema vermelho e preto</div>
        <div>Atualizado em {escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
      </div>
    </section>
        """,
    )


def _render_table_empty(message: str, colspan: int) -> str:
    return f'<tr><td colspan="{colspan}">{escape(message)}</td></tr>'


DEVICE_KIND_ORDER = ("all", "computers", "servers", "network", "wireless", "printers", "phones", "monitors", "pdus", "racks", "chassis", "passive", "other")
DEVICE_KIND_LABELS = {
    "all": "Todos",
    "computers": "Computadores",
    "servers": "Servidores",
    "network": "Dispositivos de rede",
    "wireless": "Wireless / APs",
    "printers": "Impressoras",
    "phones": "Telefonia",
    "monitors": "Monitores",
    "pdus": "PDUs",
    "racks": "Racks",
    "chassis": "Chassis",
    "passive": "Dispositivos passivos",
    "other": "Outros",
}


def _inventory_kind_for_device(device: dict[str, Any]) -> str:
    name = _normalize_text(device.get("name")).lower()
    comments = _normalize_text(device.get("comments")).lower()
    role = _relation_label(device.get("role")).lower()
    device_type = _relation_label(device.get("device_type")).lower()
    manufacturer = ""
    model = ""
    if isinstance(device.get("device_type"), dict):
        manufacturer = _relation_label(device.get("device_type", {}).get("manufacturer")).lower()
        model = _normalize_text(device.get("device_type", {}).get("model")).lower()
    text = " ".join(part for part in (name, comments, role, device_type, manufacturer, model) if part)
    if any(token in text for token in ("notebook", "laptop", "desktop", "workstation", "pc", "computer", "computador", "windows", "macbook", "chromebook")):
        return "computers"
    if any(token in text for token in ("server", "hypervisor", "proxmox", "esxi", "idrac", "ilo", "qemu", "rack server", "blade", "virtual")):
        return "servers"
    if any(token in text for token in ("printer", "print server", "brother", "epson", "hp ethernet multi-environment")):
        return "printers"
    if any(token in text for token in ("phone", "voip", "sip", "grandstream", "yealink", "polycom", "softphone")):
        return "phones"
    if any(token in text for token in ("access point", "wireless", "ap", "gwn", "omada", "wifi")):
        return "wireless"
    if any(token in text for token in ("monitor",)):
        return "monitors"
    if any(token in text for token in ("pdu", "power distribution", "power strip", "power unit")):
        return "pdus"
    if any(token in text for token in ("rack", "rack unit", "cabinet")):
        return "racks"
    if any(token in text for token in ("chassis", "blade chassis", "virtual chassis")):
        return "chassis"
    if any(token in text for token in ("patch panel", "passive", "cable", "fiber tray", "keystone")):
        return "passive"
    if any(token in text for token in ("switch", "router", "gateway", "firewall", "bridge", "uplink", "network", "mikrotik", "intelbras", "tp-link", "grandstream")):
        return "network"
    return "other"


def _inventory_kind_label(kind: str) -> str:
    return DEVICE_KIND_LABELS.get(kind, DEVICE_KIND_LABELS["other"])


def _inventory_kind_counts(devices: list[dict[str, Any]]) -> dict[str, int]:
    counts = {kind: 0 for kind in DEVICE_KIND_ORDER}
    for device in devices:
        if not isinstance(device, dict):
            continue
        kind = _inventory_kind_for_device(device)
        counts[kind] = counts.get(kind, 0) + 1
        counts["all"] += 1
    return counts


def _inventory_kind_menu(active_kind: str, counts: dict[str, int], search: str = "") -> str:
    items = []
    for kind in DEVICE_KIND_ORDER:
        label = DEVICE_KIND_LABELS[kind]
        count = counts.get(kind, 0)
        active = " active" if kind == active_kind else ""
        query = f"kind={quote(kind)}"
        if search:
            query += f"&q={quote(search)}"
        items.append(
            f'<a class="inventory-kind-item{active}" href="/devices?{query}"><span>{escape(label)}</span><strong>{count}</strong></a>'
        )
    return "".join(items)


def _device_form(device: dict[str, Any] | None = None) -> str:
    device = device or {}
    custom_fields = device.get("custom_fields") if isinstance(device.get("custom_fields"), dict) else {}
    custom_rows = _custom_field_pairs(custom_fields, limit=6)
    custom_rows_markup = "".join(
        f"""
        <div class="form-grid">
          <div class="field"><label>Campo {index}</label><input name="custom_field_key_{index}" type="text" value="{escape(key)}" placeholder="access_user" /></div>
          <div class="field"><label>Valor {index}</label><input name="custom_field_value_{index}" type="text" value="{escape(value)}" placeholder="admin" /></div>
        </div>
        """
        for index, (key, value) in enumerate(custom_rows, start=1)
    )
    return f"""
    <div class="panel">
      <h2>{'Editar device' if device.get('id') else 'Criar device'}</h2>
      <p>Use este formulário para cadastrar ou corrigir um equipamento no NetBox.</p>
      <form method="post" action="/devices/save">
        <input type="hidden" name="device_id" value="{escape(_related_id(device.get('id')))}" />
        <div class="form-grid">
          <div class="field"><label>Nome</label><input name="name" type="text" value="{escape(_normalize_text(device.get('name')))}" /></div>
          <div class="field"><label>Status</label><input name="status" type="text" value="{escape(_status_value(device.get('status')))}" placeholder="active" /></div>
          <div class="field"><label>Site ID</label><input name="site_id" type="text" value="{escape(_related_id(device.get('site')))}" /></div>
          <div class="field"><label>Role ID</label><input name="role_id" type="text" value="{escape(_related_id(device.get('role')))}" /></div>
          <div class="field"><label>Device Type ID</label><input name="device_type_id" type="text" value="{escape(_related_id(device.get('device_type')))}" /></div>
          <div class="field"><label>Rack ID</label><input name="rack_id" type="text" value="{escape(_related_id(device.get('rack')))}" /></div>
          <div class="field"><label>Primary IP4 ID</label><input name="primary_ip4_id" type="text" value="{escape(_related_id(device.get('primary_ip4')))}" /></div>
          <div class="field"><label>Serial</label><input name="serial" type="text" value="{escape(_normalize_text(device.get('serial')))}" /></div>
        </div>
        <div class="field">
          <label>Custom fields JSON</label>
          <textarea name="custom_fields_json" placeholder='{{"access_user": "admin", "access_password": "..."}}'>{escape(json.dumps(custom_fields, ensure_ascii=False))}</textarea>
        </div>
        <div class="field">
          <label>Campos personalizados</label>
          <p>Adicione qualquer informação extra do device. Ex.: acesso L2/L3, usuário, senha de apoio, VLAN de gerência ou observações.</p>
          {custom_rows_markup}
        </div>
        <div class="field"><label>Comments</label><input name="comments" type="text" value="{escape(_normalize_text(device.get('comments')))}" /></div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Salvar device</button>
          <a class="btn" href="/devices">Limpar</a>
        </div>
      </form>
    </div>
    """


def _render_device_detail_page(
    device: dict[str, Any],
    interfaces: list[dict[str, Any]],
    prefixes: list[dict[str, Any]],
    topology_state: dict[str, Any] | None,
    *,
    saved: bool = False,
    error: str | None = None,
) -> str:
    def _display(value: Any, default: str = "—") -> str:
        text = _normalize_text(value)
        return escape(text if text else default)

    def _display_relation(value: Any, default: str = "—") -> str:
        if isinstance(value, dict):
            text = _relation_label(value)
        elif isinstance(value, list):
            text = ", ".join(_relation_label(item) for item in value if item)
        else:
            text = _normalize_text(value)
        return escape(text if text else default)

    device_id = _related_id(device.get("id"))
    device_type = device.get("device_type") if isinstance(device.get("device_type"), dict) else {}
    manufacturer = _relation_label(device_type.get("manufacturer")) if isinstance(device_type, dict) else "—"
    model = _normalize_text(device_type.get("model")) if isinstance(device_type, dict) else _relation_label(device.get("device_type"))
    status = _relation_label(device.get("status"))
    site = _relation_label(device.get("site"))
    role = _relation_label(device.get("role"))
    rack = _relation_label(device.get("rack"))
    tenant = _relation_label(device.get("tenant"))
    platform = _relation_label(device.get("platform"))
    primary_ip = _relation_label(device.get("primary_ip4"))
    description = _normalize_text(device.get("description"))
    comments = _normalize_text(device.get("comments"))
    serial = _normalize_text(device.get("serial")) or "—"
    asset_tag = _normalize_text(device.get("asset_tag")) or "—"
    uuid = _normalize_text(device.get("uuid")) or "—"
    tags = ", ".join(_normalize_text(tag.get("name")) for tag in device.get("tags", []) if isinstance(tag, dict) and _normalize_text(tag.get("name")))
    custom_fields = device.get("custom_fields") if isinstance(device.get("custom_fields"), dict) else {}
    custom_pairs = _custom_field_pairs(custom_fields, limit=12)
    prefix_lookup = {str(prefix.get("id")): prefix for prefix in prefixes if isinstance(prefix, dict)}

    topology_rows = []
    for entry in _network_topology_entries(topology_state):
        if str(entry.get("origin_device_id")) != device_id and str(entry.get("next_device_id")) != device_id:
            continue
        prefix = prefix_lookup.get(str(entry.get("prefix_id")))
        topology_rows.append(
            f'''
            <tr>
              <td>{_display(prefix.get('prefix') if isinstance(prefix, dict) else None)}</td>
              <td>{_display(_normalize_text(entry.get('network_kind')) or ('VLAN' if prefix and _related_id(prefix.get('vlan')) else 'Prefixo'))}</td>
              <td>{_display(entry.get('origin_interface'))}</td>
              <td>{_display(_normalize_text(entry.get('origin_mode')) or '—')}</td>
              <td>{_display(entry.get('next_interface'))}</td>
              <td>{_display(_normalize_text(entry.get('next_mode')) or '—')}</td>
              <td>{_display(entry.get('route_notes'))}</td>
            </tr>
            '''
        )

    interface_rows = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        interface_rows.append(
            f'''
            <tr>
              <td><strong>{_display(interface.get('name'))}</strong></td>
              <td>{_display(interface.get('description'))}</td>
              <td>{_display_relation(interface.get('enabled'))}</td>
              <td>{_display_relation(interface.get('type'))}</td>
              <td>{_display(_normalize_text(interface.get('mode')) or '—')}</td>
              <td>{_display_relation(interface.get('untagged_vlan'))}</td>
              <td>{_display_relation(interface.get('tagged_vlans'))}</td>
              <td>{_display(_normalize_mac_text(interface.get('mac_address')) or '—')}</td>
            </tr>
            '''
        )

    interface_count = len(interface_rows)
    topology_count = len(topology_rows)
    custom_count = len(custom_pairs)
    tags_value = tags or "—"
    relation_links = '''
      <a class="btn" href="/topology">Mapa</a>
      <a class="btn" href="/networks">Redes</a>
      <a class="btn" href="/vlans">VLANs</a>
      <a class="btn" href="/snmp">SNMP</a>
    '''
    section_tabs = '''
      <a href="#visao-geral" class="active">Visão geral</a>
      <a href="#hardware">Hardware</a>
      <a href="#rede">Rede</a>
      <a href="#interfaces">Interfaces</a>
      <a href="#relacoes">Relações</a>
      <a href="#editar">Editar</a>
    '''
    summary_cards = f'''
      <div class="glpi-detail-grid" id="visao-geral">
        <div class="metric-card">
          <div class="metric-label">Status</div>
          <div class="metric-value">{escape(status)}</div>
          <div class="metric-note">{escape(site)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Tipo</div>
          <div class="metric-value">{escape(_inventory_kind_label(_inventory_kind_for_device(device)))}</div>
          <div class="metric-note">{escape(role)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Fabricante</div>
          <div class="metric-value" style="font-size:22px;">{escape(manufacturer)}</div>
          <div class="metric-note">{escape(model or 'Modelo não informado')}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Rede</div>
          <div class="metric-value" style="font-size:22px;">{escape(primary_ip)}</div>
          <div class="metric-note">{escape(rack)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Inventário</div>
          <div class="metric-value" style="font-size:22px;">{escape(serial)}</div>
          <div class="metric-note">Asset tag {escape(asset_tag)}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Relacionamentos</div>
          <div class="metric-value" style="font-size:22px;">{interface_count + topology_count}</div>
          <div class="metric-note">{interface_count} interfaces e {topology_count} vínculos de rota.</div>
        </div>
      </div>
    '''
    hardware_section = f'''
      <div class="glpi-detail-section" id="hardware">
        <h3>Informações de hardware</h3>
        <div class="glpi-info-grid">
          <div class="glpi-info-item"><span class="label">Nome</span><strong>{_display(device.get('name'))}</strong></div>
          <div class="glpi-info-item"><span class="label">UUID</span><strong>{escape(uuid)}</strong></div>
          <div class="glpi-info-item"><span class="label">Tenant</span><strong>{escape(tenant)}</strong></div>
          <div class="glpi-info-item"><span class="label">Rack</span><strong>{escape(rack)}</strong></div>
          <div class="glpi-info-item"><span class="label">Serial</span><strong>{escape(serial)}</strong></div>
          <div class="glpi-info-item"><span class="label">Asset tag</span><strong>{escape(asset_tag)}</strong></div>
          <div class="glpi-info-item"><span class="label">Plataforma</span><strong>{escape(platform)}</strong></div>
          <div class="glpi-info-item"><span class="label">Comentários</span><strong>{_display(comments)}</strong></div>
        </div>
        <div style="margin-top:12px;">
          <div class="metric-label">Descrição</div>
          <div style="margin-top:6px; line-height:1.6;">{_display(description)}</div>
        </div>
        <div style="margin-top:12px;">
          <div class="metric-label">Etiquetas</div>
          <div style="margin-top:6px; line-height:1.6;">{escape(tags_value)}</div>
        </div>
        <div style="margin-top:12px;">
          <div class="metric-label">Campos personalizados</div>
          {''.join(f'<div class="glpi-info-item" style="margin-top:8px;"><span class="label">{escape(key)}</span><strong>{escape(value or "—")}</strong></div>' for key, value in custom_pairs) if custom_pairs else '<div class="glpi-info-item" style="margin-top:8px;"><span class="label">Sem campos extras</span><strong>Use o formulário de edição para adicionar informações personalizadas.</strong></div>'}
        </div>
      </div>
    '''
    network_section = f'''
      <div class="glpi-detail-section" id="rede">
        <h3>Rede e endereçamento</h3>
        <div class="glpi-info-grid">
          <div class="glpi-info-item"><span class="label">IP principal</span><strong>{escape(primary_ip)}</strong></div>
          <div class="glpi-info-item"><span class="label">Site</span><strong>{escape(site)}</strong></div>
          <div class="glpi-info-item"><span class="label">Vínculo VLAN</span><strong>{escape(_relation_label(device.get('primary_ip4')) if device.get('primary_ip4') else '—')}</strong></div>
          <div class="glpi-info-item"><span class="label">Papel</span><strong>{escape(role)}</strong></div>
        </div>
        <div style="margin-top:12px;">
          <div class="metric-label">Atalhos operacionais</div>
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:8px;">{relation_links}</div>
        </div>
      </div>
    '''
    interfaces_section = f'''
      <div class="glpi-detail-section" id="interfaces">
        <h3>Interfaces</h3>
        <table>
          <thead>
            <tr><th>Nome</th><th>Descrição</th><th>Status</th><th>Tipo</th><th>Modo</th><th>VLAN sem tag</th><th>VLANs com tag</th><th>MAC</th></tr>
          </thead>
          <tbody>{''.join(interface_rows) if interface_rows else _render_table_empty('Nenhuma interface encontrada para este device.', 8)}</tbody>
        </table>
      </div>
    '''
    relations_section = f'''
      <div class="glpi-detail-section" id="relacoes">
        <h3>Relações e rota</h3>
        <table>
          <thead>
            <tr><th>Prefixo</th><th>Tipo</th><th>Saída origem</th><th>Modo origem</th><th>Entrada destino</th><th>Modo destino</th><th>Observações</th></tr>
          </thead>
          <tbody>{''.join(topology_rows) if topology_rows else _render_table_empty('Nenhuma relação de rede mapeada para este ativo.', 7)}</tbody>
        </table>
      </div>
    '''
    edit_section = f'''
      <div class="glpi-detail-section" id="editar">
        <h3>Editar device</h3>
        {_device_form(device)}
      </div>
    '''
    side_summary = f'''
      <div class="glpi-card">
        <h3>{escape(_normalize_text(device.get('name')) or 'Device')}</h3>
        <div class="metric-label">Resumo do ativo</div>
        <div style="display:grid; gap:8px; margin-top:10px;">
          <div><strong>Status:</strong> {escape(status)}</div>
          <div><strong>Tipo:</strong> {escape(_inventory_kind_label(_inventory_kind_for_device(device)))}</div>
          <div><strong>Fabricante:</strong> {escape(manufacturer)}</div>
          <div><strong>Modelo:</strong> {escape(model or '—')}</div>
          <div><strong>Site:</strong> {escape(site)}</div>
          <div><strong>Rack:</strong> {escape(rack)}</div>
          <div><strong>IP:</strong> {escape(primary_ip)}</div>
        </div>
      </div>
    '''
    side_links = f'''
      <div class="glpi-card">
        <h3>Ações</h3>
        <div class="glpi-side-menu">
          <a href="#visao-geral">Visão geral <span>{interface_count + topology_count}</span></a>
          <a href="#interfaces">Interfaces <span>{interface_count}</span></a>
          <a href="#relacoes">Relações <span>{topology_count}</span></a>
          <a href="#editar">Editar <span>{custom_count} campos extras</span></a>
        </div>
      </div>
    '''
    body = f'''
    <div class="glpi-frame">
      <aside class="panel glpi-sidebar">
        <div class="glpi-section-title">Ativos</div>
        <div class="glpi-breadcrumbs"><span>Home</span> / <span>Ativos</span> / <span>Computadores</span> / <span>Detalhe</span></div>
        <div class="glpi-card">
          <h3>Seções</h3>
          <div class="glpi-side-menu">
            <a href="#visao-geral">Visão geral <span>{interface_count + topology_count}</span></a>
            <a href="#hardware">Hardware <span>{custom_count}</span></a>
            <a href="#rede">Rede <span>{1 if primary_ip != '—' else 0}</span></a>
            <a href="#interfaces">Interfaces <span>{interface_count}</span></a>
            <a href="#relacoes">Relações <span>{topology_count}</span></a>
            <a href="#editar">Editar <span>Formulário</span></a>
          </div>
        </div>
        {side_links}
      </aside>
      <section class="panel">
        <div class="glpi-detail-header">
          <div class="glpi-detail-title">
            <div class="glpi-section-title">Ativo detalhado</div>
            <h2 style="margin:0;">{_display(device.get('name'))}</h2>
            <div class="sub" style="margin:0;">Tela no estilo GLPI com visão de inventário, rede, interfaces e vínculos entre equipamentos.</div>
            <div class="glpi-detail-meta">
              <span class="glpi-detail-pill">Status: {escape(status)}</span>
              <span class="glpi-detail-pill">Tipo: {escape(_inventory_kind_label(_inventory_kind_for_device(device)))}</span>
              <span class="glpi-detail-pill">Site: {escape(site)}</span>
              <span class="glpi-detail-pill">IP: {escape(primary_ip)}</span>
            </div>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <a class="btn" href="/devices">Voltar</a>
            <a class="btn" href="/snmp">Varredura SNMP</a>
            <a class="btn" href="/topology">Mapa</a>
            <a class="btn primary" href="#editar">Editar</a>
          </div>
        </div>
        <div class="glpi-tabs">{section_tabs}</div>
        {summary_cards}
        {hardware_section}
        {network_section}
        {interfaces_section}
        {relations_section}
        {edit_section}
      </section>
      <aside class="panel">
        <div class="glpi-section-title">Resumo rápido</div>
        {side_summary}
        <div class="glpi-card">
          <h3>Inventário ligado</h3>
          <div class="glpi-info-grid">
            <div class="glpi-info-item"><span class="label">Interfaces</span><strong>{interface_count}</strong></div>
            <div class="glpi-info-item"><span class="label">Relações</span><strong>{topology_count}</strong></div>
            <div class="glpi-info-item"><span class="label">Campos extras</span><strong>{custom_count}</strong></div>
            <div class="glpi-info-item"><span class="label">Prefixos</span><strong>{len(prefixes)}</strong></div>
          </div>
        </div>
        <div class="glpi-card">
          <h3>Campos personalizados</h3>
          {''.join(f'<div class="glpi-info-item" style="margin-top:8px;"><span class="label">{escape(key)}</span><strong>{escape(value or "—")}</strong></div>' for key, value in custom_pairs) if custom_pairs else '<p>Sem campos personalizados cadastrados.</p>'}
        </div>
      </aside>
    </div>
    '''
    device_title = _display(device.get('name')) if device else 'Device'
    page_banner = ""
    if saved:
        page_banner = "<div class='hero'><small>Atualizado</small><strong>Dados do device carregados.</strong></div>"
    elif error:
        page_banner = f"<div class='hero'><small>Erro</small><strong>{escape(error)}</strong></div>"
    return _render_management_page(
        title=f"{device_title} | infra-sync-api",
        active='devices',
        heading='Detalhe do device',
        subtitle='Inventário completo com foco em hardware, rede, interfaces e relacionamento entre ativos.',
        actions='<a class="btn" href="/devices">Lista</a><a class="btn" href="/reports">Relatórios</a><a class="btn" href="/topology">Mapa</a>',
        body=body,
        banner=page_banner,
    )


@app.get("/devices", include_in_schema=False)
async def devices_page(request: Request, saved: int = 0, error: str | None = None, edit: int | None = None):
    client = request.app.state.netbox_client
    devices: list[dict[str, Any]] = []
    edit_device: dict[str, Any] | None = None
    page_error = error
    active_kind = _query_value(request, "kind", "all") or "all"
    search = _query_value(request, "q")
    try:
        if client is not None:
            params: dict[str, Any] = {"limit": 100}
            if search:
                params["q"] = search
            devices = await client.list_devices(params=params)
            if edit is not None:
                edit_device = await client.get_device(edit)
    except Exception as exc:
        page_error = str(exc)

    inventory_counts = _inventory_kind_counts(devices)
    if active_kind not in inventory_counts:
        active_kind = "all"
    filtered_devices = [
        device for device in devices
        if active_kind == "all" or _inventory_kind_for_device(device) == active_kind
    ]
    selected_device = edit_device or (filtered_devices[0] if filtered_devices else None)

    rows = []
    for device in filtered_devices:
        device_type = device.get("device_type") if isinstance(device.get("device_type"), dict) else {}
        manufacturer = _relation_label(device_type.get("manufacturer")) if isinstance(device_type, dict) else "?"
        model = _normalize_text(device_type.get("model")) if isinstance(device_type, dict) else _relation_label(device.get("device_type"))
        serial = _normalize_text(device.get("serial")) or "—"
        ip_address = _relation_label(device.get("primary_ip4"))
        rows.append(
            f"""
            <tr>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}"><strong>{escape(_normalize_text(device.get('name')) or '?')}</strong></a></td>
              <td>{escape(_relation_label(device.get('site')))}</td>
              <td>{escape(_relation_label(device.get('status')))}</td>
              <td>{escape(manufacturer or '?')}</td>
              <td>{escape(serial)}</td>
              <td>{escape(_inventory_kind_label(_inventory_kind_for_device(device)))}</td>
              <td>{escape(model or '?')}</td>
              <td>{escape(ip_address)}</td>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}">Abrir</a></td>
            </tr>
            """
        )

    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Device atualizado com sucesso.</strong></div>"
    if page_error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(page_error)}</strong></div>"

    selected_kind = _inventory_kind_label(active_kind)
    quick_tabs_items = []
    for kind, label in (("all", "Todos"), ("computers", "Computadores"), ("servers", "Servidores"), ("network", "Rede"), ("wireless", "Wireless"), ("printers", "Impressoras")):
        href = f"/devices?kind={quote(kind)}"
        if search:
            href += f"&q={quote(search)}"
        active_class = " active" if kind == active_kind else ""
        quick_tabs_items.append(f'<a class="{active_class}" href="{href}">{escape(label)}</a>')
    quick_tabs = "".join(quick_tabs_items)
    selected_summary = ""
    if isinstance(selected_device, dict):
        selected_summary = f"""
        <div class="glpi-card">
          <h3>{escape(_normalize_text(selected_device.get('name')) or 'Device')}</h3>
          <div class="metric-label">Resumo do item</div>
          <div style="display:grid; gap:8px; margin-top:10px;">
            <div><strong>Status:</strong> {escape(_relation_label(selected_device.get('status')))}</div>
            <div><strong>Site:</strong> {escape(_relation_label(selected_device.get('site')))}</div>
            <div><strong>Rack:</strong> {escape(_relation_label(selected_device.get('rack')))}</div>
            <div><strong>Tipo:</strong> {escape(_inventory_kind_label(_inventory_kind_for_device(selected_device)))}</div>
            <div><strong>Fabricante:</strong> {escape(_relation_label(selected_device.get('device_type', {}).get('manufacturer')) if isinstance(selected_device.get('device_type'), dict) else '—')}</div>
            <div><strong>Modelo:</strong> {escape(_normalize_text(selected_device.get('device_type', {}).get('model')) if isinstance(selected_device.get('device_type'), dict) else _relation_label(selected_device.get('device_type')))}</div>
            <div><strong>Serial:</strong> {escape(_normalize_text(selected_device.get('serial')) or '—')}</div>
            <div><strong>IP:</strong> {escape(_relation_label(selected_device.get('primary_ip4')))}</div>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:12px;">
            <a class="btn primary" href="/devices/view/{escape(_related_id(selected_device.get('id')))}">Abrir detalhe</a>
            <a class="btn" href="/topology">Mapa</a>
            <a class="btn" href="/reports">Relatório</a>
          </div>
        </div>
        """
    else:
        selected_summary = """
        <div class="glpi-card">
          <h3>Inventário</h3>
          <p>Selecione uma categoria ou pesquise por nome, IP, fabricante ou modelo para inspecionar os ativos.</p>
        </div>
        """

    body = f"""
    <div class="glpi-frame">
      <aside class="panel glpi-sidebar">
        <div class="glpi-section-title">Ativos</div>
        <div class="glpi-breadcrumbs"><span>Home</span> / <span>Ativos</span> / {escape(selected_kind)}</div>
        <div class="glpi-card" style="margin-top:12px;">
          <h3>Menu</h3>
          <div class="inventory-kind-menu">
            {_inventory_kind_menu(active_kind, inventory_counts, search)}
          </div>
        </div>
        <div class="glpi-card">
          <div class="metric-label">Inventário carregado</div>
          <div class="metric-value" style="font-size:28px; margin-top:10px;">{len(devices)}</div>
          <div class="metric-note">Devices cadastrados e carregados do NetBox.</div>
        </div>
        <div class="glpi-card">
          <div class="metric-label">Categoria ativa</div>
          <div class="metric-value" style="font-size:24px; margin-top:10px;">{escape(selected_kind)}</div>
          <div class="metric-note">Clique em uma categoria para refinar a lista.</div>
        </div>
      </aside>
      <section class="panel">
        <div class="glpi-toolbar">
          <div>
            <h2 style="margin:0 0 4px;">Devices cadastrados</h2>
            <div class="sub" style="margin:0;">Lista central do inventário com navegação por categoria, como no GLPI.</div>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
            <a class="btn" href="/snmp">Varredura SNMP</a>
            <a class="btn" href="/discovery">Descoberta</a>
            <a class="btn" href="/networks">Redes</a>
            <a class="btn" href="/vlans">VLANs</a>
          </div>
        </div>
        <div class="glpi-tabs">{quick_tabs}</div>
        <div style="display:flex; gap:8px; justify-content:space-between; align-items:end; flex-wrap:wrap; margin-bottom:12px;">
          <div>
            <strong>{len(filtered_devices)} dispositivo(s)</strong>
            <div class="sub" style="margin:4px 0 0;">Use o filtro para focar em computadores, rede, wireless, impressoras e outros grupos.</div>
          </div>
          <form method="get" action="/devices" style="display:flex; gap:8px; align-items:end; flex-wrap:wrap; margin:0;">
            <input type="hidden" name="kind" value="{escape(active_kind)}" />
            <div class="field" style="margin:0; min-width:260px;"><label for="q">Pesquisar</label><input id="q" name="q" type="text" value="{escape(search)}" placeholder="Nome, IP, fabricante, modelo..." /></div>
            <button class="btn primary" type="submit">Pesquisar</button>
          </form>
        </div>
        <table>
          <thead><tr><th>Nome</th><th>Entidade</th><th>Status</th><th>Fabricante</th><th>Serial</th><th>Tipo</th><th>Modelo</th><th>IP</th><th>Ações</th></tr></thead>
          <tbody>{''.join(rows) if rows else _render_table_empty('Nenhum device encontrado nesta categoria.', 9)}</tbody>
        </table>
      </section>
      <aside class="panel">
        <div class="glpi-section-title">Detalhe rápido</div>
        {selected_summary}
        <div class="glpi-card">
          <h3>Resumo do grupo</h3>
          <div style="display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:10px;">
            <div><div class="metric-label">Computadores</div><div class="metric-value" style="font-size:22px;">{inventory_counts.get('computers', 0)}</div></div>
            <div><div class="metric-label">Rede</div><div class="metric-value" style="font-size:22px;">{inventory_counts.get('network', 0)}</div></div>
            <div><div class="metric-label">Wireless</div><div class="metric-value" style="font-size:22px;">{inventory_counts.get('wireless', 0)}</div></div>
            <div><div class="metric-label">Outros</div><div class="metric-value" style="font-size:22px;">{inventory_counts.get('other', 0)}</div></div>
          </div>
        </div>
      </aside>
    </div>
    """
    return _render_management_page(
        title="Assets | infra-sync-api",
        active="devices",
        heading="Ativos",
        subtitle="Inventário central com menu por categoria, resumo e abertura do detalhe do device.",
        actions=f'<a class="btn" href="/">Dashboard</a><a class="btn" href="/snmp">Leitura SNMP</a><a class="btn" href="/reports">Imprimir relatório</a>',
        body=body,
        banner=banner,
    )


@app.get("/devices/view/{device_id}", include_in_schema=False)
async def device_detail_page(request: Request, device_id: int, saved: int = 0, error: str | None = None):
    client = request.app.state.netbox_client
    device: dict[str, Any] = {}
    interfaces: list[dict[str, Any]] = []
    prefixes: list[dict[str, Any]] = []
    topology_state = load_network_topology()
    page_error = error
    try:
        if client is not None:
            device = await client.get_device(device_id)
            interfaces = await client.list_interfaces(params={"device_id": device_id, "limit": 100})
            prefixes = await client.list_prefixes(params={"limit": 100})
    except Exception as exc:
        page_error = str(exc)
    return HTMLResponse(_render_device_detail_page(device, interfaces, prefixes, topology_state, saved=bool(saved), error=page_error))

def _vlan_form(vlan: dict[str, Any] | None = None) -> str:
    vlan = vlan or {}
    return f"""
    <div class="panel">
      <h2>{'Editar VLAN' if vlan.get('id') else 'Criar VLAN'}</h2>
      <p>Cadastro de segmentação L2 para a rede central.</p>
      <form method="post" action="/vlans/save">
        <input type="hidden" name="vlan_id" value="{escape(_related_id(vlan.get('id')))}" />
        <div class="form-grid">
          <div class="field"><label>VID</label><input name="vid" type="text" value="{escape(_normalize_text(vlan.get('vid')))}" /></div>
          <div class="field"><label>Nome</label><input name="name" type="text" value="{escape(_normalize_text(vlan.get('name')))}" /></div>
          <div class="field"><label>Status</label><input name="status" type="text" value="{escape(_status_value(vlan.get('status')))}" /></div>
          <div class="field"><label>Site ID</label><input name="site_id" type="text" value="{escape(_related_id(vlan.get('site')))}" /></div>
        </div>
        <div class="field"><label>Descrição</label><input name="description" type="text" value="{escape(_normalize_text(vlan.get('description')))}" /></div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Salvar VLAN</button>
          <a class="btn" href="/vlans">Limpar</a>
        </div>
      </form>
    </div>
    """


def _prefix_form(
    prefix: dict[str, Any] | None = None,
    topology: dict[str, Any] | None = None,
    device_choices: list[dict[str, Any]] | None = None,
) -> str:
    prefix = prefix or {}
    topology = topology or {}
    device_choices = device_choices or []
    network_kind = _normalize_text(topology.get("network_kind")) or ("vlan" if _related_id(prefix.get("vlan")) else "prefix")
    origin_device_id = _normalize_text(topology.get("origin_device_id"))
    next_device_id = _normalize_text(topology.get("next_device_id"))
    return f"""
    <div class="panel">
      <h2>{'Editar rede' if prefix.get('id') else 'Criar rede'}</h2>
      <p>Cadastro de prefixos e blocos IP para IPAM e desenho da rota entre equipamentos.</p>
      <form method="post" action="/networks/save">
        <input type="hidden" name="prefix_id" value="{escape(_related_id(prefix.get('id')))}" />
        <div class="form-grid">
          <div class="field"><label>Prefixo</label><input name="prefix" type="text" value="{escape(_normalize_text(prefix.get('prefix')))}" placeholder="10.0.0.0/24" /></div>
          <div class="field"><label>Status</label><input name="status" type="text" value="{escape(_status_value(prefix.get('status')))}" /></div>
          <div class="field"><label>Site ID</label><input name="site_id" type="text" value="{escape(_related_id(prefix.get('site')))}" /></div>
          <div class="field">
            <label>Tipo da rede</label>
            <select name="network_kind">
              <option value="prefix" {"selected" if network_kind == "prefix" else ""}>Prefixo</option>
              <option value="vlan" {"selected" if network_kind == "vlan" else ""}>VLAN</option>
            </select>
          </div>
          <div class="field"><label>VLAN associada</label><input name="vlan_id" type="text" value="{escape(_related_id(prefix.get('vlan')))}" placeholder="50" /></div>
        </div>
        <div class="field"><label>Descrição</label><input name="description" type="text" value="{escape(_normalize_text(prefix.get('description')))}" /></div>
        <div class="panel" style="margin:14px 0 0; background:#0f0f12;">
          <h3 style="margin-top:0;">Mapa da rota</h3>
          <p>Preencha de onde essa VLAN ou prefixo nasce, por qual porta sai e para onde segue.</p>
          <div class="form-grid">
            <div class="field">
              <label>Equipamento de origem</label>
              <select name="origin_device_id">
                {_render_device_choice_options(device_choices, origin_device_id)}
              </select>
            </div>
            <div class="field"><label>Porta de origem</label><input name="origin_interface" type="text" value="{escape(_normalize_text(topology.get('origin_interface')))}" placeholder="Gi0/7" /></div>
            <div class="field">
              <label>Saida da origem</label>
              <select name="origin_mode">
                <option value="">-</option>
                <option value="tagged" {"selected" if _normalize_text(topology.get('origin_mode')) == 'tagged' else ""}>Tagged</option>
                <option value="untagged" {"selected" if _normalize_text(topology.get('origin_mode')) == 'untagged' else ""}>Untagged</option>
                <option value="trunk" {"selected" if _normalize_text(topology.get('origin_mode')) == 'trunk' else ""}>Trunk</option>
              </select>
            </div>
            <div class="field">
              <label>Equipamento seguinte</label>
              <select name="next_device_id">
                {_render_device_choice_options(device_choices, next_device_id)}
              </select>
            </div>
            <div class="field"><label>Porta seguinte</label><input name="next_interface" type="text" value="{escape(_normalize_text(topology.get('next_interface')))}" placeholder="Porta 12" /></div>
            <div class="field">
              <label>Entrada no proximo salto</label>
              <select name="next_mode">
                <option value="">-</option>
                <option value="tagged" {"selected" if _normalize_text(topology.get('next_mode')) == 'tagged' else ""}>Tagged</option>
                <option value="untagged" {"selected" if _normalize_text(topology.get('next_mode')) == 'untagged' else ""}>Untagged</option>
                <option value="trunk" {"selected" if _normalize_text(topology.get('next_mode')) == 'trunk' else ""}>Trunk</option>
              </select>
            </div>
          </div>
          <div class="field">
            <label>Observacoes da rota</label>
            <textarea name="route_notes" placeholder="CCR porta 7 trunk vlan 50">{escape(_normalize_text(topology.get('route_notes')))}</textarea>
          </div>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Salvar rede</button>
          <a class="btn" href="/networks">Limpar</a>
        </div>
      </form>
    </div>
    """


async def _get_netbox_client_or_error(request: Request) -> NetBoxClient:
    client: NetBoxClient | None = request.app.state.netbox_client
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="NetBox client is not configured")
    return client


async def _get_zabbix_client_or_error(request: Request) -> ZabbixClient:
    client: ZabbixClient | None = request.app.state.zabbix_client
    if client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Zabbix client is not configured")
    return client


def _render_topology_rows(
    prefixes: list[dict[str, Any]],
    topology_state: dict[str, Any] | None,
    device_lookup: dict[str, str],
) -> str:
    prefix_lookup = {str(prefix.get("id")): prefix for prefix in prefixes if isinstance(prefix, dict)}
    rows = []
    for entry in _network_topology_entries(topology_state):
        prefix = prefix_lookup.get(str(entry.get("prefix_id")))
        if not prefix:
            continue
        origin_device = device_lookup.get(_normalize_text(entry.get("origin_device_id")), "—")
        next_device = device_lookup.get(_normalize_text(entry.get("next_device_id")), "—")
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(_normalize_text(prefix.get('prefix')) or '—')}</strong></td>
              <td>{escape(_normalize_text(entry.get('network_kind')) or ('VLAN' if _related_id(prefix.get('vlan')) else 'Prefixo'))}</td>
              <td>{escape(_related_id(prefix.get('vlan')) or '—')}</td>
              <td>{escape(origin_device)}</td>
              <td>{escape(_normalize_text(entry.get('origin_interface')) or '—')}</td>
              <td>{escape(_normalize_text(entry.get('origin_mode')) or '—')}</td>
              <td>{escape(next_device)}</td>
              <td>{escape(_normalize_text(entry.get('next_interface')) or '—')}</td>
              <td>{escape(_normalize_text(entry.get('next_mode')) or '—')}</td>
              <td>{escape(_normalize_text(entry.get('route_notes')) or '—')}</td>
            </tr>
            """
        )
    return "".join(rows) if rows else _render_table_empty("Nenhuma rota cadastrada ainda.", 10)


def _topology_device_kind_label(device: dict[str, Any] | None, label: str = "") -> str:
    if isinstance(device, dict):
        discovery_group = _normalize_text(device.get("group")).lower()
        if discovery_group in {"switches", "routers", "network"}:
            return "Rede"
        if discovery_group in {"servers"}:
            return "Servidor"
        if discovery_group in {"aps", "wireless"}:
            return "Wireless"
        if discovery_group in {"hosts", "computers", "printers", "phones", "monitors"}:
            return "Usuario"
        kind = _inventory_kind_for_device(device)
        if kind in {"network"}:
            return "Rede"
        if kind in {"servers"}:
            return "Servidor"
        if kind in {"wireless"}:
            return "Wireless"
        if kind in {"computers", "phones", "printers", "monitors"}:
            return "Usuario"
        return "Outro"

    text = _normalize_text(label).lower()
    if any(token in text for token in ("router", "gateway", "firewall", "core", "distribution", "backbone", "uplink")):
        return "Rede"
    if any(token in text for token in ("server", "vm", "hyper", "host", "esxi", "proxmox")):
        return "Servidor"
    if any(token in text for token in ("wireless", "access point", "ap", "wifi")):
        return "Wireless"
    if any(token in text for token in ("printer", "mfp", "camera", "phone", "laptop", "desktop", "pc")):
        return "Usuario"
    return "Outro"


def _topology_device_key(device: dict[str, Any]) -> str:
    if not isinstance(device, dict):
        return ""
    for key in ("netbox_device_id", "id", "device_id"):
        value = _related_id(device.get(key))
        if value:
            return value
    for key in ("netbox_device_name", "name", "sys_name", "snmp_mac_address", "mac_address", "ip", "primary_ip4"):
        value = _normalize_text(device.get(key))
        if value:
            if key == "primary_ip4":
                value = value.split("/", 1)[0]
            return value.lower()
    return ""


def _topology_resolve_netbox_device(
    device: dict[str, Any],
    netbox_by_id: dict[str, dict[str, Any]],
    netbox_by_name: dict[str, dict[str, Any]],
    netbox_by_ip: dict[str, dict[str, Any]],
    netbox_by_mac: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(device, dict):
        return None
    candidates = [
        _related_id(device.get("netbox_device_id")),
        _related_id(device.get("id")),
        _normalize_text(device.get("netbox_device_name")).lower(),
        _normalize_text(device.get("name")).lower(),
        _normalize_text(device.get("sys_name")).lower(),
        _normalize_text(device.get("ip")).split("/", 1)[0].lower(),
    ]
    if isinstance(device.get("primary_ip4"), dict):
        candidates.append(_normalize_text(device.get("primary_ip4", {}).get("address")).split("/", 1)[0].lower())
    for key in ("snmp_mac_address", "mac_address"):
        mac_value = _normalize_mac_text(device.get(key))
        if mac_value:
            candidates.append(mac_value)
    if isinstance(device.get("ports"), list):
        for port in device.get("ports", []):
            if not isinstance(port, dict):
                continue
            mac_value = _normalize_mac_text(port.get("mac_address"))
            if mac_value:
                candidates.append(mac_value)
    for candidate in candidates:
        if not candidate:
            continue
        if candidate in netbox_by_id:
            return netbox_by_id[candidate]
        if candidate in netbox_by_name:
            return netbox_by_name[candidate]
        if candidate in netbox_by_ip:
            return netbox_by_ip[candidate]
        if netbox_by_mac is not None and candidate in netbox_by_mac:
            return netbox_by_mac[candidate]
    return None


def _topology_device_name(device: dict[str, Any] | None) -> str:
    if not isinstance(device, dict):
        return ""
    for key in ("name", "display_name", "device_name", "sys_name"):
        value = _normalize_text(device.get(key))
        if value:
            return value
    return ""


def _topology_is_generic_label(label: str) -> bool:
    text = _normalize_text(label)
    if not text:
        return True
    normalized = text.lower()
    return normalized.startswith("device ") or normalized.startswith("mac ") or normalized.startswith("unknown")


def _topology_build_node(
    device: dict[str, Any],
    *,
    fallback_device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source_device = fallback_device if isinstance(fallback_device, dict) else None
    discovered = device if isinstance(device, dict) else {}
    netbox_device = source_device or discovered
    is_placeholder_source = bool(_normalize_text(discovered.get("topology_placeholder")))
    node_id = (
        _related_id(discovered.get("netbox_device_id"))
        or _related_id(netbox_device.get("id"))
        or _topology_device_key(discovered)
        or _topology_device_key(netbox_device)
    )
    label = (
        _normalize_text(discovered.get("netbox_device_name"))
        or ("" if is_placeholder_source else _topology_device_name(netbox_device))
        or _normalize_text(discovered.get("sys_name"))
        or _normalize_text(discovered.get("ip"))
        or f"Device {node_id}"
    )
    primary_ip = _normalize_text(discovered.get("ip"))
    if not primary_ip and isinstance(netbox_device.get("primary_ip4"), dict):
        primary_ip = _normalize_text(netbox_device.get("primary_ip4", {}).get("address")).split("/", 1)[0]
    if not primary_ip:
        primary_ip = _normalize_text(netbox_device.get("primary_ip4"))
    if primary_ip and "/" in primary_ip:
        primary_ip = primary_ip.split("/", 1)[0]
    snmp_mac_address = _normalize_mac_text(discovered.get("snmp_mac_address")) or _normalize_mac_text(discovered.get("mac_address"))
    if not snmp_mac_address and isinstance(discovered.get("ports"), list):
        snmp_mac_address = next((_normalize_mac_text(port.get("mac_address")) for port in discovered.get("ports", []) if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))), "")

    group = _normalize_text(discovered.get("group")).lower()
    subgroup = _normalize_text(discovered.get("subgroup")).lower()
    system_status = _normalize_text(discovered.get("system_status"))
    inventory_kind = _inventory_kind_for_device(netbox_device) if isinstance(netbox_device, dict) else "other"
    if inventory_kind == "other":
        if group in {"switches", "routers", "network"}:
            inventory_kind = "network"
        elif group in {"servers"}:
            inventory_kind = "servers"
        elif group in {"aps", "wireless"}:
            inventory_kind = "wireless"
        elif group in {"printers"}:
            inventory_kind = "printers"
        elif group in {"phones"}:
            inventory_kind = "phones"
        elif group in {"hosts", "computers"}:
            inventory_kind = "computers"

    node = {
        "id": node_id or label,
        "label": label,
        "kind": _topology_device_kind_label(netbox_device if source_device else discovered, label),
        "inventory_kind": inventory_kind,
        "group": group,
        "subgroup": subgroup,
        "status": _relation_label(netbox_device.get("status")) if isinstance(netbox_device.get("status"), (dict, str)) else system_status or "—",
        "site": _relation_label(netbox_device.get("site")) if isinstance(netbox_device.get("site"), (dict, str)) else _normalize_text(discovered.get("site")) or "—",
        "role": _relation_label(netbox_device.get("role")) if isinstance(netbox_device.get("role"), (dict, str)) else _normalize_text(discovered.get("role")) or "—",
        "primary_ip": _relation_label(netbox_device.get("primary_ip4")) if isinstance(netbox_device.get("primary_ip4"), (dict, str)) else primary_ip or "—",
        "manufacturer": _relation_label(netbox_device.get("device_type", {}).get("manufacturer")) if isinstance(netbox_device.get("device_type"), dict) else _normalize_text(discovered.get("manufacturer")) or "—",
        "model": _normalize_text(netbox_device.get("device_type", {}).get("model")) if isinstance(netbox_device.get("device_type"), dict) else _normalize_text(discovered.get("model")) or "—",
        "system_status": system_status or "—",
        "system_message": _normalize_text(discovered.get("system_message")),
        "reachable": bool(discovered.get("reachable")),
        "ports_count": len(discovered.get("ports")) if isinstance(discovered.get("ports"), list) else 0,
        "ports": [port for port in discovered.get("ports", []) if isinstance(port, dict)] if isinstance(discovered.get("ports"), list) else [],
        "netbox_device_id": _related_id(discovered.get("netbox_device_id")) or _related_id(netbox_device.get("id")),
        "netbox_device_name": "" if is_placeholder_source else (_normalize_text(netbox_device.get("name")) or _normalize_text(discovered.get("netbox_device_name"))),
        "snmp_mac_address": snmp_mac_address,
        "mac_address": snmp_mac_address,
        "device_link": f"/devices/view/{_related_id(discovered.get('netbox_device_id')) or _related_id(netbox_device.get('id'))}" if (_related_id(discovered.get("netbox_device_id")) or _related_id(netbox_device.get("id"))) else "",
        "search_text": " ".join(
            text for text in (
                label,
                _normalize_text(discovered.get("ip")),
                _normalize_text(discovered.get("sys_name")),
                _normalize_text(discovered.get("manufacturer")),
                _normalize_text(discovered.get("model")),
                _normalize_text(discovered.get("device_type")),
                _normalize_text(discovered.get("group")),
                _normalize_text(discovered.get("subgroup")),
                _normalize_text(system_status),
                snmp_mac_address,
                _normalize_text(netbox_device.get("name")),
                _relation_label(netbox_device.get("site")) if isinstance(netbox_device.get("site"), dict) else "",
                _relation_label(netbox_device.get("role")) if isinstance(netbox_device.get("role"), dict) else "",
                _relation_label(netbox_device.get("primary_ip4")) if isinstance(netbox_device.get("primary_ip4"), dict) else "",
            )
            if _normalize_text(text)
        ).lower(),
        "degree": 0,
        "prefix_count": 0,
        "neighbors": [],
        "x": 0,
        "y": 0,
    }
    return node


async def _build_topology_netbox_mac_index(
    client: NetBoxClient | None,
    netbox_devices: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if client is None:
        return {}
    mac_index: dict[str, dict[str, Any]] = {}
    for device in netbox_devices:
        if not isinstance(device, dict):
            continue
        device_id = _related_id(device.get("id"))
        if not device_id or device_id in mac_index:
            continue
        try:
            interfaces = await client.list_all("/api/dcim/interfaces/", params={"device_id": int(device_id), "limit": 200})
        except Exception:
            continue
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            mac_address = _topology_extract_interface_mac(interface)
            if mac_address and mac_address not in mac_index:
                mac_index[mac_address] = device
    return mac_index


def _topology_extract_interface_peer(interface: dict[str, Any]) -> tuple[str, str, str] | None:
    if not isinstance(interface, dict):
        return None

    def _candidate_device(candidate: Any) -> tuple[str, str, str] | None:
        peer_device_id = ""
        peer_device_name = ""
        peer_interface_name = ""
        if isinstance(candidate, dict):
            peer_interface_name = _normalize_text(candidate.get("name")) or _normalize_text(candidate.get("display"))
            peer_device = candidate.get("device") or candidate.get("remote_device") or candidate.get("connected_device")
            if isinstance(peer_device, dict):
                peer_device_id = _related_id(peer_device.get("id"))
                peer_device_name = _normalize_text(peer_device.get("name"))
            elif peer_device is not None:
                peer_device_id = _related_id(peer_device) or _normalize_text(peer_device)
            if not peer_device_id:
                peer_device_id = _related_id(candidate.get("device_id")) or _related_id(candidate.get("device"))
            if not peer_device_name:
                peer_device_name = _normalize_text(candidate.get("device_name")) or _normalize_text(candidate.get("remote_device_name"))
            if not peer_interface_name:
                peer_interface_name = _normalize_text(candidate.get("interface_name")) or _normalize_text(candidate.get("label"))
        else:
            text = _normalize_text(candidate)
            if not text:
                return None
            match = re.search(r"/interfaces?/(\d+)/?", text)
            if match:
                peer_device_id = match.group(1)
            else:
                match = re.search(r"dcim\.interface[:/](\d+)", text)
                if match:
                    peer_device_id = match.group(1)
                else:
                    match = re.search(r"(\d+)$", text)
                    if match:
                        peer_device_id = match.group(1)
            peer_device_name = text
        if peer_device_id:
            return peer_device_id, peer_device_name, peer_interface_name
        return None

    for key in ("connected_endpoints", "connected_endpoint", "link_peers", "peer", "peers", "cable"):
        value = interface.get(key)
        if not value:
            continue
        if isinstance(value, list):
            for candidate in value:
                parsed = _candidate_device(candidate)
                if parsed is not None:
                    return parsed
        else:
            parsed = _candidate_device(value)
            if parsed is not None:
                return parsed
    return None


def _topology_extract_interface_mac(interface: dict[str, Any]) -> str:
    if not isinstance(interface, dict):
        return ""
    candidates = (
        interface.get("mac_address"),
        interface.get("primary_mac_address"),
        interface.get("l2address"),
        interface.get("l2_address"),
        interface.get("address"),
    )
    for candidate in candidates:
        if isinstance(candidate, dict):
            for key in ("mac_address", "address", "value", "label"):
                mac = _normalize_mac_text(candidate.get(key))
                if mac:
                    return mac
            continue
        mac = _normalize_mac_text(candidate)
        if mac:
            return mac
    return ""


def _topology_node_mac_candidates(node: dict[str, Any], interfaces: list[dict[str, Any]]) -> list[tuple[str, str]]:
    candidates: dict[str, str] = {}

    def add_candidate(value: Any, source_port: str = "") -> None:
        mac = _normalize_mac_text(value)
        if not mac:
            return
        port_name = _normalize_text(source_port)
        if mac not in candidates or (port_name and not candidates[mac]):
            candidates[mac] = port_name

    ports = node.get("ports")
    if isinstance(ports, list):
        for port in ports:
            if not isinstance(port, dict):
                continue
            add_candidate(port.get("mac_address"), port.get("name"))

    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        add_candidate(_topology_extract_interface_mac(interface), interface.get("name"))

    for key in ("mac_address", "discovered_mac_address", "netbox_mac_address", "snmp_mac_address"):
        add_candidate(node.get(key))

    return [(mac, source_port) for mac, source_port in candidates.items()]


def _topology_should_probe_interfaces(device: dict[str, Any]) -> bool:
    group = _normalize_text(device.get("group")).lower()
    kind = _normalize_text(device.get("kind")).lower()
    inventory_kind = _normalize_text(device.get("inventory_kind")).lower()
    label = " ".join(
        part for part in (
            _normalize_text(device.get("label")),
            _normalize_text(device.get("name")),
            _normalize_text(device.get("netbox_device_name")),
        )
        if part
    ).lower()
    if group in {"switches", "routers", "network"}:
        return True
    if inventory_kind in {"network"}:
        return True
    if kind == "rede":
        return True
    return any(token in label for token in ("switch", "router", "firewall", "gateway", "core", "backbone", "uplink"))


def _topology_inventory_devices(
    discovery_state: dict[str, Any] | None,
    netbox_devices: list[dict[str, Any]],
    netbox_by_mac: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    netbox_by_id = {str(device.get("id")): device for device in netbox_devices if isinstance(device, dict) and _related_id(device.get("id"))}
    netbox_by_name = {_normalize_text(device.get("name")).lower(): device for device in netbox_devices if isinstance(device, dict) and _normalize_text(device.get("name"))}
    netbox_by_ip: dict[str, dict[str, Any]] = {}
    for device in netbox_devices:
        if not isinstance(device, dict):
            continue
        primary_ip = device.get("primary_ip4")
        primary_ip_text = ""
        if isinstance(primary_ip, dict):
            primary_ip_text = _normalize_text(primary_ip.get("address"))
        else:
            primary_ip_text = _normalize_text(primary_ip)
        if primary_ip_text:
            netbox_by_ip[primary_ip_text.split("/", 1)[0].lower()] = device

    discovered_devices = []
    if isinstance(discovery_state, dict) and isinstance(discovery_state.get("devices"), list):
        discovered_devices = [device for device in discovery_state["devices"] if isinstance(device, dict)]

    inventory: dict[str, dict[str, Any]] = {}
    key_index: dict[str, str] = {}

    def _device_keys(device: dict[str, Any], node: dict[str, Any] | None = None) -> set[str]:
        keys = {
            _normalize_text(_topology_device_key(device)).lower(),
            _related_id(device.get("netbox_device_id")).lower(),
            _related_id(device.get("id")).lower(),
            _normalize_text(device.get("label")).lower(),
            _normalize_text(device.get("name")).lower(),
            _normalize_text(device.get("netbox_device_name")).lower(),
            _normalize_text(device.get("sys_name")).lower(),
            _normalize_mac_text(device.get("snmp_mac_address")),
            _normalize_mac_text(device.get("mac_address")),
            _normalize_text(device.get("ip")).split("/", 1)[0].lower(),
            _normalize_text(device.get("primary_ip")).split("/", 1)[0].lower(),
        }
        if isinstance(node, dict):
            keys.update(
                {
                    _normalize_text(_topology_device_key(node)).lower(),
                    _related_id(node.get("netbox_device_id")).lower(),
                    _related_id(node.get("id")).lower(),
                    _normalize_text(node.get("label")).lower(),
                    _normalize_text(node.get("netbox_device_name")).lower(),
                    _normalize_text(node.get("sys_name")).lower(),
                    _normalize_mac_text(node.get("snmp_mac_address")),
                    _normalize_mac_text(node.get("mac_address")),
                    _normalize_text(node.get("primary_ip")).split("/", 1)[0].lower(),
                }
            )
        return {key for key in keys if key}

    def _register_keys(node_id: str, device: dict[str, Any], node: dict[str, Any]) -> None:
        for key in _device_keys(device, node):
            key_index[key] = node_id

    def _merge_node(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        if _topology_is_generic_label(existing.get("label")) and not _topology_is_generic_label(incoming.get("label")):
            existing["label"] = incoming["label"]
        incoming_kind = _normalize_text(incoming.get("kind"))
        existing_kind = _normalize_text(existing.get("kind"))
        if incoming_kind and incoming_kind != existing_kind and incoming_kind in {"Rede", "Servidor", "Wireless", "Usuario"}:
            existing["kind"] = incoming_kind
        incoming_inventory_kind = _normalize_text(incoming.get("inventory_kind")).lower()
        existing_inventory_kind = _normalize_text(existing.get("inventory_kind")).lower()
        preferred_inventory_kinds = {"network", "servers", "wireless", "printers", "phones", "computers"}
        if incoming_inventory_kind in preferred_inventory_kinds and (
            existing_inventory_kind not in preferred_inventory_kinds
            or incoming_inventory_kind == "network"
            or (existing_inventory_kind in {"phones", "computers"} and incoming_inventory_kind in {"network", "servers", "wireless"})
        ):
            existing["inventory_kind"] = incoming_inventory_kind
        incoming_group = _normalize_text(incoming.get("group")).lower()
        if incoming_group and incoming_group != _normalize_text(existing.get("group")).lower():
            if incoming_inventory_kind in {"network", "servers", "wireless"} or incoming_group in {"switches", "routers", "network"}:
                existing["group"] = incoming_group
        for field in ("netbox_device_name", "primary_ip", "snmp_mac_address", "mac_address", "device_link"):
            if not _normalize_text(existing.get(field)) and _normalize_text(incoming.get(field)):
                existing[field] = incoming[field]
        if not _related_id(existing.get("netbox_device_id")) and _related_id(incoming.get("netbox_device_id")):
            existing["netbox_device_id"] = incoming["netbox_device_id"]
        if _normalize_text(incoming.get("site")) and _normalize_text(existing.get("site")) in {"", "—"}:
            existing["site"] = incoming["site"]
        if _normalize_text(incoming.get("role")) and _normalize_text(existing.get("role")) in {"", "—"}:
            existing["role"] = incoming["role"]
        if _normalize_text(incoming.get("status")) and _normalize_text(existing.get("status")) in {"", "—"}:
            existing["status"] = incoming["status"]
        if _normalize_text(incoming.get("manufacturer")) and _normalize_text(existing.get("manufacturer")) in {"", "—"}:
            existing["manufacturer"] = incoming["manufacturer"]
        if _normalize_text(incoming.get("model")) and _normalize_text(existing.get("model")) in {"", "—"}:
            existing["model"] = incoming["model"]
        return existing

    for device in [*discovered_devices, *netbox_devices]:
        fallback = _topology_resolve_netbox_device(device, netbox_by_id, netbox_by_name, netbox_by_ip, netbox_by_mac)
        node = _topology_build_node(device, fallback_device=fallback)
        node_id = _normalize_text(node.get("id"))
        if not node_id:
            continue
        match_id = None
        for key in _device_keys(device, node):
            match_id = key_index.get(key)
            if match_id:
                break
        if match_id and match_id in inventory:
            inventory[match_id] = _merge_node(inventory[match_id], node)
            _register_keys(match_id, device, inventory[match_id])
            continue
        inventory[node_id] = node
        _register_keys(node_id, device, node)

    return list(inventory.values())


async def _collect_topology_connection_edges(
    client: NetBoxClient | None,
    inventory_devices: list[dict[str, Any]],
    netbox_devices: list[dict[str, Any]],
    probe_state: dict[str, Any] | None = None,
    netbox_by_mac: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if client is None and not isinstance(probe_state, dict):
        return []

    netbox_by_id = {str(device.get("id")): device for device in netbox_devices if isinstance(device, dict) and _related_id(device.get("id"))}
    netbox_by_name = {_normalize_text(device.get("name")).lower(): device for device in netbox_devices if isinstance(device, dict) and _normalize_text(device.get("name"))}
    inventory_by_name: dict[str, dict[str, Any]] = {}
    inventory_by_mac: dict[str, dict[str, Any]] = {}
    inventory_by_ip: dict[str, dict[str, Any]] = {}
    inventory_by_node_id: dict[str, dict[str, Any]] = {}
    inventory_by_netbox_id: dict[str, dict[str, Any]] = {}
    for node in inventory_devices:
        if not isinstance(node, dict):
            continue
        node_id = _normalize_text(node.get("id")).lower()
        if node_id:
            inventory_by_node_id[node_id] = node
        netbox_id = _related_id(node.get("netbox_device_id"))
        if netbox_id:
            inventory_by_netbox_id[netbox_id.lower()] = node
        for name_key in (_normalize_text(node.get("label")).lower(), _normalize_text(node.get("netbox_device_name")).lower(), _normalize_text(node.get("sys_name")).lower()):
            if name_key:
                inventory_by_name[name_key] = node
        for mac_key in (_normalize_mac_text(node.get("snmp_mac_address")), _normalize_mac_text(node.get("mac_address"))):
            if mac_key:
                inventory_by_mac[mac_key] = node
        ip_key = _normalize_text(node.get("primary_ip")).split("/", 1)[0].lower()
        if ip_key and ip_key != "—":
            inventory_by_ip[ip_key] = node

    probe_devices = [device for device in (probe_state.get("devices") if isinstance(probe_state, dict) and isinstance(probe_state.get("devices"), list) else []) if isinstance(device, dict)]
    probe_by_ip: dict[str, dict[str, Any]] = {}
    probe_by_name: dict[str, dict[str, Any]] = {}
    probe_by_mac: dict[str, dict[str, Any]] = {}
    for device in probe_devices:
        ip_key = _normalize_text(device.get("ip")).split("/", 1)[0].lower()
        if ip_key:
            probe_by_ip[ip_key] = device
        name_key = _normalize_text(device.get("sys_name")).lower()
        if name_key:
            probe_by_name[name_key] = device
        mac_key = _normalize_mac_text(device.get("snmp_mac_address"))
        if not mac_key and isinstance(device.get("ports"), list):
            mac_key = next((_normalize_mac_text(port.get("mac_address")) for port in device.get("ports", []) if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))), "")
        if mac_key:
            probe_by_mac[mac_key] = device

    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    interfaces_by_device: dict[str, list[dict[str, Any]]] = {}
    interface_cache: dict[str, dict[str, Any]] = {}
    device_cache: dict[str, dict[str, Any]] = {}
    mac_records_cache: dict[str, list[dict[str, Any]]] = {}

    async def _load_interfaces(device_id: str) -> list[dict[str, Any]]:
        if device_id in interfaces_by_device:
            return interfaces_by_device[device_id]
        try:
            interfaces = await client.list_all("/api/dcim/interfaces/", params={"device_id": int(device_id), "limit": 200})
        except Exception:
            interfaces = []
        interfaces_by_device[device_id] = [interface for interface in interfaces if isinstance(interface, dict)]
        return interfaces_by_device[device_id]

    async def _load_interface(interface_id: str) -> dict[str, Any] | None:
        if interface_id in interface_cache:
            return interface_cache[interface_id] or None
        try:
            interface = await client.get_interface(int(interface_id))
        except Exception:
            interface = {}
        interface_cache[interface_id] = interface if isinstance(interface, dict) else {}
        return interface_cache[interface_id] or None

    async def _load_device(device_id: str) -> dict[str, Any] | None:
        if device_id in device_cache:
            return device_cache[device_id] or None
        try:
            device = await client.get_device(int(device_id))
        except Exception:
            device = {}
        device_cache[device_id] = device if isinstance(device, dict) else {}
        return device_cache[device_id] or None

    def _extract_peer_device(candidate: Any) -> tuple[str, str] | None:
        if isinstance(candidate, dict):
            device_id = (
                _related_id(candidate.get("id"))
                or _related_id(candidate.get("device_id"))
                or _related_id(candidate.get("pk"))
            )
            device_name = (
                _topology_device_name(candidate)
                or _normalize_text(candidate.get("device_name"))
                or _normalize_text(candidate.get("remote_device_name"))
                or _normalize_text(candidate.get("label"))
            )
            if not device_id:
                for key in ("url", "device_url", "href"):
                    device_id = _related_id(candidate.get(key))
                    if device_id:
                        break
            if device_id or device_name:
                return device_id, device_name
            return None
        text = _normalize_text(candidate)
        if not text:
            return None
        device_id = _related_id(text)
        if device_id:
            return device_id, ""
        return "", text

    async def _resolve_mac_peer(record: dict[str, Any]) -> tuple[str, str, str] | None:
        if not isinstance(record, dict):
            return None
        interface_data: dict[str, Any] | None = None
        assigned_object = record.get("assigned_object")
        if isinstance(assigned_object, dict):
            if isinstance(assigned_object.get("device"), dict):
                interface_data = assigned_object
            else:
                assigned_object_id = _related_id(assigned_object.get("id"))
                if assigned_object_id:
                    interface_data = await _load_interface(assigned_object_id)
                if interface_data is None and _normalize_text(assigned_object.get("device_name")):
                    interface_data = assigned_object
                if interface_data is None and _normalize_text(assigned_object.get("display_name")):
                    interface_data = assigned_object
        if interface_data is None and _normalize_text(record.get("assigned_object_type")).lower() == "dcim.interface":
            assigned_object_id = _related_id(record.get("assigned_object_id"))
            if assigned_object_id:
                interface_data = await _load_interface(assigned_object_id)
        if not isinstance(interface_data, dict):
            return None
        target_device_id = ""
        target_device_name = ""
        for candidate in (
            interface_data.get("device"),
            interface_data.get("device_id"),
            interface_data.get("device_name"),
            interface_data.get("device_display"),
            interface_data.get("display_name"),
            interface_data.get("remote_device"),
            interface_data.get("connected_device"),
        ):
            parsed = _extract_peer_device(candidate)
            if parsed is None:
                continue
            candidate_id, candidate_name = parsed
            if candidate_id and not target_device_id:
                target_device_id = candidate_id
            if candidate_name and not target_device_name:
                target_device_name = candidate_name
            if target_device_id and target_device_name:
                break
        if target_device_id and target_device_id.isdigit() and (not target_device_name or target_device_name.startswith("Device ")):
            loaded_device = await _load_device(target_device_id)
            if isinstance(loaded_device, dict):
                target_device_name = _topology_device_name(loaded_device) or target_device_name
        target_interface_name = (
            _normalize_text(interface_data.get("name"))
            or _normalize_text(interface_data.get("display"))
            or _normalize_text(interface_data.get("interface_name"))
            or _normalize_text(interface_data.get("label"))
        )
        if not target_device_id and target_device_name:
            target_device_id = _normalize_text(target_device_name).lower()
        if (not target_device_id or not target_device_name) and netbox_by_mac:
            record_mac = _normalize_mac_text(record.get("mac_address")) or _normalize_mac_text(record.get("address")) or _normalize_mac_text(record.get("value"))
            if record_mac and record_mac in netbox_by_mac:
                resolved_device = netbox_by_mac[record_mac]
                target_device_id = target_device_id or _related_id(resolved_device.get("id"))
                target_device_name = target_device_name or _topology_device_name(resolved_device)
        if not target_device_id:
            return None
        return target_device_id, target_device_name, target_interface_name

    async def _query_mac_records(mac_address: str) -> list[dict[str, Any]]:
        if mac_address in mac_records_cache:
            return mac_records_cache[mac_address]
        try:
            records = await client.find_mac_addresses(mac_address)
        except Exception:
            records = []
        mac_records_cache[mac_address] = [record for record in records if isinstance(record, dict)]
        return mac_records_cache[mac_address]

    def _probe_port_name(probe_device: dict[str, Any], port_index: str) -> str:
        ports = probe_device.get("ports") if isinstance(probe_device.get("ports"), list) else []
        for port in ports:
            if not isinstance(port, dict):
                continue
            if _normalize_text(port.get("index")) == _normalize_text(port_index):
                return _normalize_text(port.get("name")) or _normalize_text(port.get("description"))
        return ""

    def _resolve_inventory_target_by_lldp(remote_sys_name: str, remote_chassis_id: str) -> dict[str, Any] | None:
        if remote_sys_name:
            candidate_id = _normalize_text(remote_sys_name).lower()
            if candidate_id in inventory_by_node_id:
                return inventory_by_node_id[candidate_id]
            if candidate_id in inventory_by_netbox_id:
                return inventory_by_netbox_id[candidate_id]
            candidate = inventory_by_name.get(remote_sys_name.lower())
            if candidate is not None:
                return candidate
            candidate_probe = probe_by_name.get(remote_sys_name.lower())
            if candidate_probe is not None:
                ip_key = _normalize_text(candidate_probe.get("ip")).split("/", 1)[0].lower()
                if ip_key and ip_key in inventory_by_ip:
                    return inventory_by_ip[ip_key]
        if remote_chassis_id:
            candidate = inventory_by_mac.get(remote_chassis_id)
            if candidate is not None:
                return candidate
            candidate_probe = probe_by_mac.get(remote_chassis_id)
            if candidate_probe is not None:
                ip_key = _normalize_text(candidate_probe.get("ip")).split("/", 1)[0].lower()
                if ip_key and ip_key in inventory_by_ip:
                    return inventory_by_ip[ip_key]
        return None

    def _resolve_inventory_target_by_mac(mac_address: str) -> dict[str, Any] | None:
        mac_address = _normalize_mac_text(mac_address)
        if not mac_address:
            return None
        candidate = inventory_by_mac.get(mac_address)
        if candidate is not None:
            return candidate
        candidate_probe = probe_by_mac.get(mac_address)
        if candidate_probe is not None:
            ip_key = _normalize_text(candidate_probe.get("ip")).split("/", 1)[0].lower()
            if ip_key and ip_key in inventory_by_ip:
                return inventory_by_ip[ip_key]
            name_key = _normalize_text(candidate_probe.get("sys_name")).lower()
            if name_key and name_key in inventory_by_name:
                return inventory_by_name[name_key]
        return None

    def _resolve_source_probe(node: dict[str, Any]) -> dict[str, Any] | None:
        for candidate in (
            _normalize_text(node.get("primary_ip")).split("/", 1)[0].lower(),
            _normalize_text(node.get("netbox_device_name")).lower(),
            _normalize_text(node.get("label")).lower(),
            _normalize_mac_text(node.get("snmp_mac_address")),
            _normalize_mac_text(node.get("mac_address")),
        ):
            if not candidate:
                continue
            if candidate in probe_by_ip:
                return probe_by_ip[candidate]
            if candidate in probe_by_name:
                return probe_by_name[candidate]
            if candidate in probe_by_mac:
                return probe_by_mac[candidate]
        return None

    def _probe_port_name_by_bridge_port(probe_device: dict[str, Any], bridge_port: str) -> str:
        bridge_port = _normalize_text(bridge_port)
        if not bridge_port:
            return ""
        if_index = ""
        bridge_port_map = probe_device.get("bridge_port_map") if isinstance(probe_device.get("bridge_port_map"), list) else []
        for mapping in bridge_port_map:
            if not isinstance(mapping, dict):
                continue
            if _normalize_text(mapping.get("bridge_port")) == bridge_port:
                if_index = _normalize_text(mapping.get("if_index"))
                break
        return _probe_port_name(probe_device, if_index or bridge_port)

    def _edge_seen_key(source_key: str, target_key: str, edge_type: str, source_port: str = "", target_port: str = "", edge_token: str = "") -> str:
        left, right = sorted([_normalize_text(source_key), _normalize_text(target_key)])
        port_a, port_b = sorted([_normalize_text(source_port), _normalize_text(target_port)])
        return "::".join([left, right, _normalize_text(edge_type), port_a, port_b, _normalize_text(edge_token)])

    def _resolve_peer_netbox_device(peer_device_id: str, peer_device_name: str, peer_mac_address: str = "") -> dict[str, Any] | None:
        candidate = netbox_by_id.get(_related_id(peer_device_id))
        if isinstance(candidate, dict):
            return candidate
        normalized_name = _normalize_text(peer_device_name).lower()
        if normalized_name and normalized_name in netbox_by_name:
            return netbox_by_name[normalized_name]
        normalized_id_text = _normalize_text(peer_device_id).lower()
        if normalized_id_text and normalized_id_text in netbox_by_name:
            return netbox_by_name[normalized_id_text]
        normalized_mac = _normalize_mac_text(peer_mac_address)
        if normalized_mac and netbox_by_mac and normalized_mac in netbox_by_mac:
            return netbox_by_mac[normalized_mac]
        synthetic = {
            "id": peer_device_id,
            "device_id": peer_device_id,
            "netbox_device_id": peer_device_id,
            "name": peer_device_name,
            "netbox_device_name": peer_device_name,
        }
        candidate = _topology_resolve_netbox_device(synthetic, netbox_by_id, netbox_by_name, {}, netbox_by_mac)
        return candidate if isinstance(candidate, dict) else None

    for node in inventory_devices:
        if not isinstance(node, dict) or not _topology_should_probe_interfaces(node):
            continue
        device_id = _related_id(node.get("netbox_device_id")) or _related_id(node.get("id"))
        if not device_id or not device_id.isdigit():
            continue
        probe_device = _resolve_source_probe(node)
        if isinstance(probe_device, dict):
            for neighbor in probe_device.get("lldp_neighbors", []) if isinstance(probe_device.get("lldp_neighbors"), list) else []:
                if not isinstance(neighbor, dict):
                    continue
                remote_sys_name = _normalize_text(neighbor.get("remote_sys_name"))
                remote_chassis_id = _normalize_mac_text(neighbor.get("remote_chassis_id"))
                target_node = _resolve_inventory_target_by_lldp(remote_sys_name, remote_chassis_id)
                if not isinstance(target_node, dict):
                    continue
                source_key = str(node["id"])
                target_key = str(target_node["id"])
                if not source_key or not target_key or source_key == target_key:
                    continue
                source_port_name = _probe_port_name(probe_device, _normalize_text(neighbor.get("local_port_index")))
                target_port_name = _normalize_text(neighbor.get("remote_port_desc")) or _normalize_text(neighbor.get("remote_port_id"))
                seen_key = _edge_seen_key(source_key, target_key, "lldp-link", source_port_name, target_port_name, remote_sys_name or remote_chassis_id)
                if seen_key in seen:
                    continue
                label_bits = ["LLDP"]
                if source_port_name or target_port_name:
                    label_bits.append(f"{source_port_name or 'porta'} ↔ {target_port_name or 'porta remota'}")
                if remote_sys_name:
                    label_bits.append(remote_sys_name)
                seen.add(seen_key)
                edges.append(
                    {
                        "source": source_key,
                        "target": target_key,
                        "edge_type": "lldp-link",
                        "label": " • ".join(label_bits),
                        "source_port": source_port_name,
                        "target_port": target_port_name,
                        "peer_name": _normalize_text(target_node.get("label")) or _normalize_text(target_node.get("netbox_device_name")) or target_key,
                        "peer_device_id": _related_id(target_node.get("netbox_device_id")) or _related_id(target_node.get("id")),
                        "remote_sys_name": remote_sys_name,
                        "remote_chassis_id": remote_chassis_id,
                    }
                )
            for neighbor in probe_device.get("cdp_neighbors", []) if isinstance(probe_device.get("cdp_neighbors"), list) else []:
                if not isinstance(neighbor, dict):
                    continue
                remote_name = _normalize_text(neighbor.get("remote_sys_name")) or _normalize_text(neighbor.get("remote_device_id"))
                target_node = _resolve_inventory_target_by_lldp(remote_name, "")
                if not isinstance(target_node, dict):
                    continue
                source_key = str(node["id"])
                target_key = str(target_node["id"])
                if not source_key or not target_key or source_key == target_key:
                    continue
                source_port_name = _probe_port_name(probe_device, _normalize_text(neighbor.get("local_ifindex")))
                target_port_name = _normalize_text(neighbor.get("remote_port_id"))
                seen_key = _edge_seen_key(source_key, target_key, "cdp-link", source_port_name, target_port_name, remote_name)
                if seen_key in seen:
                    continue
                label_bits = ["CDP"]
                if source_port_name or target_port_name:
                    label_bits.append(f"{source_port_name or 'porta'} ↔ {target_port_name or 'porta remota'}")
                if remote_name:
                    label_bits.append(remote_name)
                seen.add(seen_key)
                edges.append(
                    {
                        "source": source_key,
                        "target": target_key,
                        "edge_type": "cdp-link",
                        "label": " • ".join(label_bits),
                        "source_port": source_port_name,
                        "target_port": target_port_name,
                        "peer_name": _normalize_text(target_node.get("label")) or _normalize_text(target_node.get("netbox_device_name")) or target_key,
                        "peer_device_id": _related_id(target_node.get("netbox_device_id")) or _related_id(target_node.get("id")),
                        "remote_sys_name": remote_name,
                        "remote_port_id": target_port_name,
                    }
                )
            for fdb_entry in probe_device.get("bridge_fdb", []) if isinstance(probe_device.get("bridge_fdb"), list) else []:
                if not isinstance(fdb_entry, dict):
                    continue
                learned_mac = _normalize_mac_text(fdb_entry.get("mac_address"))
                if not learned_mac:
                    continue
                source_key = str(node["id"])
                source_port_name = _probe_port_name_by_bridge_port(probe_device, _normalize_text(fdb_entry.get("bridge_port")))
                target_node = _resolve_inventory_target_by_mac(learned_mac)
                if isinstance(target_node, dict):
                    target_key = str(target_node["id"])
                    if source_key and target_key and source_key != target_key:
                        target_port_name = ""
                        if isinstance(target_node.get("ports"), list):
                            target_port_name = next(
                                (
                                    _normalize_text(port.get("name"))
                                    for port in target_node.get("ports", [])
                                    if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address")) == learned_mac
                                ),
                                "",
                            )
                        if not target_port_name:
                            target_port_name = _normalize_text(target_node.get("snmp_mac_address")) or _normalize_text(target_node.get("mac_address"))
                        seen_key = _edge_seen_key(source_key, target_key, "bridge-link", source_port_name, target_port_name, learned_mac)
                        if seen_key not in seen:
                            label_bits = [f"FDB {learned_mac}"]
                            if source_port_name or target_port_name:
                                label_bits.append(f"{source_port_name or 'porta'} ↔ {target_port_name or 'MAC remota'}")
                            seen.add(seen_key)
                            edges.append(
                                {
                                    "source": source_key,
                                    "target": target_key,
                                    "edge_type": "bridge-link",
                                    "label": " • ".join(label_bits),
                                    "source_port": source_port_name,
                                    "target_port": target_port_name,
                                    "peer_name": _normalize_text(target_node.get("label")) or _normalize_text(target_node.get("netbox_device_name")) or target_key,
                                    "peer_device_id": _related_id(target_node.get("netbox_device_id")) or _related_id(target_node.get("id")),
                                    "mac_address": learned_mac,
                                }
                            )
                records = await _query_mac_records(learned_mac)
                for record in records:
                    peer = await _resolve_mac_peer(record)
                    if peer is None:
                        continue
                    peer_device_id, peer_device_name, peer_interface_name = peer
                    inferred_target = _resolve_peer_netbox_device(peer_device_id, peer_device_name, learned_mac)
                    if not isinstance(inferred_target, dict):
                        continue
                    target_node = _resolve_inventory_target_by_mac(learned_mac) or _topology_build_node({}, fallback_device=inferred_target)
                    target_key = str(_related_id(inferred_target.get("id")) or peer_device_id or target_node.get("id"))
                    if not target_key or source_key == target_key:
                        continue
                    seen_key = _edge_seen_key(source_key, target_key, "bridge-link", source_port_name, peer_interface_name or target_port_name, learned_mac)
                    if seen_key in seen:
                        continue
                    seen.add(seen_key)
                    edges.append(
                        {
                            "source": source_key,
                            "target": target_key,
                            "edge_type": "bridge-link",
                            "label": " • ".join(filter(None, [f"FDB {learned_mac}", f"{source_port_name or 'porta'} ↔ {peer_interface_name or target_port_name or 'porta remota'}", _topology_device_name(inferred_target) or peer_device_name])),
                            "source_port": source_port_name,
                            "target_port": peer_interface_name or target_port_name,
                            "peer_name": _topology_device_name(inferred_target) or peer_device_name or target_key,
                            "peer_device_id": _related_id(inferred_target.get("id")) or peer_device_id,
                            "mac_address": learned_mac,
                        }
                    )
        if client is not None:
            interfaces = await _load_interfaces(device_id)
            mac_candidates = _topology_node_mac_candidates(node, interfaces)
            for mac_address, source_port in mac_candidates:
                records = await _query_mac_records(mac_address)
                for record in records:
                    peer = await _resolve_mac_peer(record)
                    if peer is None:
                        continue
                    peer_device_id, peer_device_name, peer_interface_name = peer
                    source_key = str(node["id"])
                    target_key = str(peer_device_id)
                    if not target_key or source_key == target_key:
                        continue
                    target_device = netbox_by_id.get(target_key) or netbox_by_name.get(_normalize_text(peer_device_name).lower())
                    target_label = _topology_device_name(target_device) or _normalize_text(peer_device_name) or f"Device {target_key}"
                    target_interface_name = peer_interface_name or _normalize_text(record.get("interface_name")) or _normalize_text(record.get("name"))
                    seen_key = _edge_seen_key(source_key, target_key, "mac-link", source_port, target_interface_name, mac_address)
                    if seen_key in seen:
                        continue
                    label_bits = [f"MAC {mac_address}"]
                    if source_port or target_interface_name:
                        label_bits.append(f"{source_port or 'porta'} ↔ {target_interface_name or 'porta remota'}")
                    label = " • ".join(label_bits)
                    seen.add(seen_key)
                    edges.append(
                        {
                            "source": source_key,
                            "target": target_key,
                            "edge_type": "mac-link",
                            "label": label,
                            "source_port": source_port or mac_address,
                            "target_port": target_interface_name,
                            "peer_name": target_label,
                            "peer_device_id": peer_device_id,
                            "mac_address": mac_address,
                        }
                    )
                    if peer_device_id and peer_device_id in netbox_by_id:
                        target_device = netbox_by_id[peer_device_id]
                        peer_node_id = _related_id(target_device.get("id"))
                        if peer_node_id and peer_node_id not in {str(item.get("id")) for item in inventory_devices if isinstance(item, dict)}:
                            inventory_devices.append(_topology_build_node({}, fallback_device=target_device))

            for interface in interfaces:
                peer = _topology_extract_interface_peer(interface)
                if peer is None:
                    continue
                peer_device_id, peer_device_name, peer_interface_name = peer
                source_label = _normalize_text(interface.get("name")) or _normalize_text(interface.get("display")) or f"port {device_id}"
                target_key = peer_device_id or _normalize_text(peer_device_name).lower()
                if not target_key:
                    continue
                seen_key = _edge_seen_key(str(node["id"]), str(target_key), "device-link", source_label, peer_interface_name, target_key)
                if seen_key in seen:
                    continue
                seen.add(seen_key)
                target_label = _normalize_text(peer_device_name) or f"Device {target_key}"
                edges.append(
                    {
                        "source": str(node["id"]),
                        "target": str(target_key),
                        "edge_type": "device-link",
                        "label": f"{source_label} ↔ {peer_interface_name}" if peer_interface_name else source_label,
                        "source_port": source_label,
                        "target_port": peer_interface_name,
                        "peer_name": target_label,
                        "peer_device_id": peer_device_id,
                    }
                )
                if peer_device_id and peer_device_id in netbox_by_id:
                    target_device = netbox_by_id[peer_device_id]
                    peer_node_id = _related_id(target_device.get("id"))
                    if peer_node_id and peer_node_id not in {str(item.get("id")) for item in inventory_devices if isinstance(item, dict)}:
                        inventory_devices.append(_topology_build_node({}, fallback_device=target_device))

    return edges


def _topology_graph_payload(
    prefixes: list[dict[str, Any]],
    topology_state: dict[str, Any] | None,
    inventory_devices: list[dict[str, Any]],
    netbox_devices: list[dict[str, Any]],
    connection_edges: list[dict[str, Any]],
    netbox_by_mac: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    degree_map: dict[str, int] = {}
    adjacency: dict[str, set[str]] = {}
    node_sources: dict[str, dict[str, Any]] = {}
    seen_edges: set[str] = set()
    netbox_by_id = {str(device.get("id")): device for device in netbox_devices if isinstance(device, dict) and _related_id(device.get("id"))}
    netbox_by_name = {_normalize_text(device.get("name")).lower(): device for device in netbox_devices if isinstance(device, dict) and _normalize_text(device.get("name"))}
    netbox_by_ip: dict[str, dict[str, Any]] = {}
    for device in netbox_devices:
        if not isinstance(device, dict):
            continue
        primary_ip = device.get("primary_ip4")
        if isinstance(primary_ip, dict):
            primary_ip_text = _normalize_text(primary_ip.get("address"))
        else:
            primary_ip_text = _normalize_text(primary_ip)
        if primary_ip_text:
            netbox_by_ip[primary_ip_text.split("/", 1)[0].lower()] = device

    def ensure_node(node_id: str, *, source_device: dict[str, Any] | None = None, fallback_device: dict[str, Any] | None = None) -> dict[str, Any]:
        node_id = _normalize_text(node_id)
        if not node_id:
            node_id = _topology_device_key(source_device or fallback_device or {})
        if not node_id:
            node_id = f"node-{len(nodes) + 1}"
        node = nodes.get(node_id)
        if node is not None:
            source = source_device or fallback_device or {}
            if source:
                preferred_label = _topology_build_node(source, fallback_device=fallback_device or source).get("label", "")
                if _topology_is_generic_label(node.get("label")) and not _topology_is_generic_label(preferred_label):
                    node["label"] = preferred_label
                if not _normalize_text(node.get("netbox_device_name")):
                    node["netbox_device_name"] = _topology_device_name(fallback_device or source) or _normalize_text(source.get("netbox_device_name"))
                if not _normalize_text(node.get("primary_ip")):
                    candidate_ip = _normalize_text(source.get("primary_ip")) or _normalize_text(source.get("ip"))
                    if not candidate_ip and isinstance((fallback_device or source).get("primary_ip4"), dict):
                        candidate_ip = _normalize_text((fallback_device or source).get("primary_ip4", {}).get("address"))
                    if candidate_ip:
                        node["primary_ip"] = candidate_ip.split("/", 1)[0]
                if not _related_id(node.get("netbox_device_id")):
                    node["netbox_device_id"] = _related_id((fallback_device or source).get("id")) or _related_id(source.get("netbox_device_id"))
                if not _normalize_text(node.get("snmp_mac_address")):
                    mac_value = _normalize_mac_text(source.get("snmp_mac_address")) or _normalize_mac_text(source.get("mac_address"))
                    if not mac_value and isinstance(source.get("ports"), list):
                        mac_value = next((_normalize_mac_text(port.get("mac_address")) for port in source.get("ports", []) if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))), "")
                    if mac_value:
                        node["snmp_mac_address"] = mac_value
                        node["mac_address"] = mac_value
            if source_device is not None:
                node_sources[node_id] = source_device
            return node
        source = source_device or fallback_device or {}
        fallback = fallback_device or source_device or {}
        node = _topology_build_node(source if source else {}, fallback_device=fallback if isinstance(fallback, dict) else None)
        node["id"] = node_id
        if fallback_device is not None and not _normalize_text(node.get("label")):
            node["label"] = _normalize_text(fallback_device.get("name")) or f"Device {node_id}"
        if source_device is not None:
            node_sources[node_id] = source_device
        nodes[node_id] = node
        degree_map[node_id] = 0
        adjacency[node_id] = set()
        return node

    for device in inventory_devices:
        if not isinstance(device, dict):
            continue
        fallback = _topology_resolve_netbox_device(device, netbox_by_id, netbox_by_name, netbox_by_ip, netbox_by_mac)
        ensure_node(_topology_device_key(device) or _related_id(device.get("netbox_device_id")) or _normalize_text(device.get("label")), source_device=device, fallback_device=fallback)

    for edge in connection_edges:
        if not isinstance(edge, dict):
            continue
        source_id = _normalize_text(edge.get("source"))
        target_id = _normalize_text(edge.get("target"))
        if not source_id or not target_id:
            continue
        source_device = node_sources.get(source_id)
        if source_device is None and source_id in netbox_by_id:
            source_device = netbox_by_id[source_id]
        target_device = node_sources.get(target_id)
        if target_device is None and target_id in netbox_by_id:
            target_device = netbox_by_id[target_id]
        if source_device is not None:
            ensure_node(source_id, source_device=source_device, fallback_device=source_device)
        else:
            ensure_node(source_id, fallback_device=netbox_by_id.get(source_id))
        if target_device is not None:
            ensure_node(target_id, source_device=target_device, fallback_device=target_device)
        else:
            placeholder = {"id": target_id, "name": _normalize_text(edge.get("peer_name")) or f"Device {target_id}", "topology_placeholder": True}
            ensure_node(target_id, source_device=placeholder, fallback_device=placeholder)
        edge_key = "::".join(
            sorted((source_id, target_id))
            + [
                _normalize_text(edge.get("source_port")),
                _normalize_text(edge.get("target_port")),
                _normalize_text(edge.get("edge_type")),
                _normalize_text(edge.get("mac_address")),
                _normalize_text(edge.get("peer_name")),
                _normalize_text(edge.get("label")),
            ]
        )
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        edges.append({
            "source": source_id,
            "target": target_id,
            "edge_type": _normalize_text(edge.get("edge_type")) or "device-link",
            "prefix": _normalize_text(edge.get("label")) or _normalize_text(edge.get("source_port")) or _normalize_text(edge.get("target_port")) or _normalize_text(edge.get("peer_name")) or f"{source_id} -> {target_id}",
            "label": _normalize_text(edge.get("label")),
            "source_port": _normalize_text(edge.get("source_port")),
            "target_port": _normalize_text(edge.get("target_port")),
            "peer_name": _normalize_text(edge.get("peer_name")),
            "mac_address": _normalize_text(edge.get("mac_address")),
        })
        degree_map[source_id] = degree_map.get(source_id, 0) + 1
        degree_map[target_id] = degree_map.get(target_id, 0) + 1
        adjacency[source_id].add(target_id)
        adjacency[target_id].add(source_id)

    for node_id, node in nodes.items():
        node["degree"] = degree_map.get(node_id, 0)
        node["neighbors"] = sorted(adjacency.get(node_id, set()))
        node["prefix_count"] = len([edge for edge in edges if edge["source"] == node_id or edge["target"] == node_id])
        group = _normalize_text(node.get("group")).lower()
        if group in {"switches", "routers", "network"}:
            if node["degree"] >= 8:
                tier = "core"
            elif node["degree"] >= 3:
                tier = "distribution"
            else:
                tier = "leaf"
        elif node["degree"] >= 6:
            tier = "distribution"
        else:
            tier = "leaf"
        node["topology_tier"] = tier
        node["topology_score"] = int(node["degree"] or 0) + (20 if tier == "core" else 10 if tier == "distribution" else 0) + min(int(node["prefix_count"] or 0), 6)

    def _is_placeholder_node(node: dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False
        if _normalize_text(node.get("topology_tier")).lower() in {"core", "distribution"}:
            return False
        if int(node.get("degree") or 0) > 1:
            return False
        if _normalize_text(node.get("netbox_device_name")):
            return False
        if _normalize_text(node.get("primary_ip")) not in {"", "—"}:
            return False
        label = _normalize_text(node.get("label"))
        if not label:
            return False
        if not label.lower().startswith("device "):
            return False
        return True

    visible_nodes = {node_id: node for node_id, node in nodes.items() if not _is_placeholder_node(node)}
    grouped_edges: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for edge in edges:
        source_id = _normalize_text(edge.get("source"))
        target_id = _normalize_text(edge.get("target"))
        if source_id not in visible_nodes or target_id not in visible_nodes:
            continue
        edge_type = _normalize_text(edge.get("edge_type")) or "device-link"
        group_key = tuple(sorted((source_id, target_id)) + [edge_type])
        grouped_edges.setdefault(group_key, []).append(edge)

    aggregated_edges: list[dict[str, Any]] = []
    for (left_id, right_id, edge_type), group_edges in grouped_edges.items():
        first = group_edges[0]
        source_port_values = [value for value in (_normalize_text(edge.get("source_port")) for edge in group_edges) if value]
        target_port_values = [value for value in (_normalize_text(edge.get("target_port")) for edge in group_edges) if value]
        label_values = [value for value in (_normalize_text(edge.get("label")) for edge in group_edges) if value]
        mac_values = [value for value in (_normalize_text(edge.get("mac_address")) for edge in group_edges) if value]
        peer_values = [value for value in (_normalize_text(edge.get("peer_name")) for edge in group_edges) if value]
        unique_source_ports = list(dict.fromkeys(source_port_values))
        unique_target_ports = list(dict.fromkeys(target_port_values))
        unique_macs = list(dict.fromkeys(mac_values))
        unique_labels = list(dict.fromkeys(label_values))
        label = unique_labels[0] if unique_labels else edge_type.upper()
        if len(group_edges) > 1:
            label = f"{label} • +{len(group_edges) - 1} vínculos"
        aggregated_edges.append({
            "source": left_id,
            "target": right_id,
            "edge_type": edge_type,
            "prefix": label,
            "label": label,
            "source_port": ", ".join(unique_source_ports[:3]),
            "target_port": ", ".join(unique_target_ports[:3]),
            "peer_name": peer_values[0] if peer_values else _normalize_text(visible_nodes.get(right_id, {}).get("label")) or right_id,
            "mac_address": ", ".join(unique_macs[:3]),
        })

    degree_map = {node_id: 0 for node_id in visible_nodes}
    adjacency = {node_id: set() for node_id in visible_nodes}
    for edge in aggregated_edges:
        source_id = _normalize_text(edge.get("source"))
        target_id = _normalize_text(edge.get("target"))
        if source_id not in visible_nodes or target_id not in visible_nodes:
            continue
        degree_map[source_id] = degree_map.get(source_id, 0) + 1
        degree_map[target_id] = degree_map.get(target_id, 0) + 1
        adjacency[source_id].add(target_id)
        adjacency[target_id].add(source_id)

    for node_id, node in visible_nodes.items():
        node["degree"] = degree_map.get(node_id, 0)
        node["neighbors"] = sorted(adjacency.get(node_id, set()))
        node["prefix_count"] = len([edge for edge in aggregated_edges if edge["source"] == node_id or edge["target"] == node_id])

    ordered_nodes = sorted(
        visible_nodes.values(),
        key=lambda item: (
            0 if _normalize_text(item.get("topology_tier")).lower() == "core" else 1 if _normalize_text(item.get("topology_tier")).lower() == "distribution" else 2,
            -int(item.get("topology_score") or item.get("degree") or 0),
            0 if _normalize_text(item.get("group")).lower() in {"switches", "routers", "network"} else 1,
            item.get("label", ""),
        ),
    )
    ordered_edges = sorted(aggregated_edges, key=lambda item: (item["source"], item["target"], item.get("edge_type", ""), item.get("label", "")))
    core_nodes = [node["id"] for node in ordered_nodes if _normalize_text(node.get("group")).lower() in {"switches", "routers", "network"} and _normalize_text(node.get("topology_tier")).lower() in {"core", "distribution"}][:8]
    if not core_nodes:
        core_nodes = [node["id"] for node in ordered_nodes[:5]]

    return {
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "core_nodes": core_nodes,
        "node_count": len(ordered_nodes),
        "edge_count": len(ordered_edges),
        "discovered_count": len([device for device in inventory_devices if isinstance(device, dict)]),
        "network_count": len([node for node in ordered_nodes if _normalize_text(node.get("group")).lower() in {"switches", "routers", "network"}]),
        "netbox_devices": netbox_devices,
    }


def _render_topology_graph_page(
    graph: dict[str, Any],
    prefixes: list[dict[str, Any]],
    topology_state: dict[str, Any] | None,
    page_error: str | None = None,
) -> str:
    # The interactive canvas is the primary view, while the table below remains as a safe
    # textual fallback for operations and troubleshooting.
    graph_json = json.dumps(graph, ensure_ascii=False).replace("</", "<\\/")
    route_rows = _render_topology_rows(
        prefixes,
        topology_state,
        {str(device.get("id")): _normalize_text(device.get("name")) for device in graph.get("netbox_devices", []) if isinstance(device, dict)},
    )

    body = f"""
    <style>
      .topology-shell {{
        display: grid;
        gap: 14px;
      }}
      .topology-hero {{
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: flex-start;
        flex-wrap: wrap;
      }}
      .topology-kicker {{
        text-transform: uppercase;
        letter-spacing: .08em;
        color: #86efac;
        font-size: 12px;
        font-weight: 800;
      }}
      .topology-title {{
        margin: 6px 0 0;
        font-size: 30px;
        line-height: 1.05;
      }}
      .topology-sub {{
        margin: 8px 0 0;
        color: #cbd5e1;
        max-width: 880px;
        line-height: 1.45;
      }}
      .topology-stats {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
      }}
      .topology-stat {{
        background: linear-gradient(180deg, rgba(15, 23, 42, .92), rgba(15, 23, 42, .78));
        border: 1px solid rgba(148, 163, 184, .14);
        border-radius: 16px;
        padding: 14px;
      }}
      .topology-stat .label {{
        display: block;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: #94a3b8;
        font-size: 11px;
        font-weight: 800;
      }}
      .topology-stat strong {{
        display: block;
        margin-top: 10px;
        font-size: 28px;
      }}
      .topology-workspace {{
        display: grid;
        grid-template-columns: minmax(0, 1.65fr) minmax(300px, .85fr);
        gap: 14px;
        align-items: start;
      }}
      .topology-panel {{
        background: linear-gradient(180deg, rgba(9, 15, 30, .95), rgba(7, 10, 19, .96));
        border: 1px solid rgba(148, 163, 184, .15);
        border-radius: 20px;
        overflow: hidden;
        box-shadow: 0 28px 60px rgba(0, 0, 0, .30);
      }}
      .topology-toolbar {{
        display: flex;
        justify-content: space-between;
        gap: 12px;
        flex-wrap: wrap;
        padding: 16px 18px;
        border-bottom: 1px solid rgba(148, 163, 184, .12);
        background: rgba(15, 23, 42, .70);
      }}
      .topology-toolbar .field {{
        min-width: 220px;
        margin: 0;
      }}
      .topology-toolbar input {{
        background: rgba(2, 6, 23, .65);
      }}
      .topology-controls {{
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        align-items: center;
      }}
      .topology-graph-wrap {{
        position: relative;
        min-height: 760px;
        background:
          radial-gradient(circle at top left, rgba(16, 185, 129, .10), transparent 30%),
          radial-gradient(circle at bottom right, rgba(59, 130, 246, .09), transparent 34%),
          linear-gradient(180deg, rgba(2, 6, 23, .30), rgba(2, 6, 23, .68));
      }}
      .topology-legend {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        padding: 0 18px 16px;
      }}
      .topology-legend span {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border-radius: 999px;
        padding: 7px 12px;
        background: rgba(15, 23, 42, .72);
        border: 1px solid rgba(148, 163, 184, .12);
        color: #e2e8f0;
        font-size: 12px;
      }}
      .topology-legend i {{
        width: 10px;
        height: 10px;
        border-radius: 999px;
        display: inline-block;
      }}
      .topology-detail {{
        position: sticky;
        top: 16px;
      }}
      .topology-detail-card {{
        display: grid;
        gap: 12px;
      }}
      .topology-node-list {{
        display: grid;
        gap: 10px;
      }}
      .topology-node-item {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(148, 163, 184, .12);
        background: rgba(15, 23, 42, .52);
        color: #e2e8f0;
      }}
      .topology-node-item strong {{
        display: block;
        font-size: 13px;
      }}
      .topology-node-item small {{
        display: block;
        color: #94a3b8;
        margin-top: 2px;
      }}
      .topology-node-item a {{
        color: #86efac;
        text-decoration: none;
        font-weight: 700;
        font-size: 12px;
      }}
      .topology-node-item.active {{
        border-color: rgba(134, 239, 172, .55);
        box-shadow: 0 0 0 1px rgba(134, 239, 172, .20);
      }}
      #topology-svg {{
        width: 100%;
        height: 760px;
        display: block;
        touch-action: none;
        user-select: none;
      }}
      .edge {{
        stroke-linecap: round;
        transition: opacity .2s ease, stroke .2s ease, stroke-width .2s ease;
      }}
      .edge.selected {{
        filter: drop-shadow(0 0 8px rgba(134, 239, 172, .25));
      }}
      .node circle {{
        transition: transform .15s ease, stroke .15s ease, fill .15s ease, opacity .15s ease;
      }}
      .node text {{
        font-family: inherit;
      }}
      .node-label {{
        fill: #e2e8f0;
        font-size: 12px;
        font-weight: 700;
        text-anchor: middle;
      }}
      .node[data-tier="core"] .node-label {{
        font-size: 13px;
        font-weight: 900;
      }}
      .node[data-tier="distribution"] .node-label {{
        font-size: 12px;
        font-weight: 800;
      }}
      .node-mini {{
        fill: #94a3b8;
        font-size: 10px;
        text-anchor: middle;
      }}
      .node-badge {{
        fill: #0f172a;
        stroke-width: 1;
      }}
      .node[data-kind="Rede"] circle {{ fill: #14b8a6; stroke: #86efac; }}
      .node[data-kind="Servidor"] circle {{ fill: #2563eb; stroke: #93c5fd; }}
      .node[data-kind="Wireless"] circle {{ fill: #7c3aed; stroke: #c4b5fd; }}
      .node[data-kind="Usuario"] circle {{ fill: #f97316; stroke: #fdba74; }}
      .node[data-kind="Outro"] circle {{ fill: #475569; stroke: #cbd5e1; }}
      .node.selected circle {{
        stroke-width: 4;
        filter: drop-shadow(0 0 12px rgba(134, 239, 172, .35));
      }}
      .node[data-tier="core"] circle {{
        filter: drop-shadow(0 0 10px rgba(52, 211, 153, .28));
      }}
      .node[data-tier="distribution"] circle {{
        filter: drop-shadow(0 0 8px rgba(96, 165, 250, .18));
      }}
      .node.dimmed {{
        opacity: .18;
      }}
      .edge.dimmed {{
        opacity: .10;
      }}
      .edge-label {{
        fill: #cbd5e1;
        font-size: 10px;
        font-weight: 700;
        text-anchor: middle;
        opacity: .75;
        pointer-events: none;
        paint-order: stroke;
        stroke: rgba(2, 6, 23, .82);
        stroke-width: 3;
        stroke-linejoin: round;
      }}
      .edge-label.dimmed {{
        opacity: .18;
      }}
      @media (max-width: 1180px) {{
        .topology-workspace {{
          grid-template-columns: 1fr;
        }}
        .topology-detail {{
          position: static;
        }}
        .topology-stats {{
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }}
      }}
      @media (max-width: 760px) {{
        .topology-stats {{
          grid-template-columns: 1fr;
        }}
        #topology-svg {{
          height: 620px;
        }}
      }}
    </style>
    <div class="topology-shell">
      <section class="topology-hero">
        <div>
          <div class="topology-kicker">Mapa interativo</div>
          <h2 class="topology-title">Topologia da rede</h2>
          <p class="topology-sub">Visualização interativa dos dispositivos localizados na varredura, com destaque para os vínculos inferidos pelo MAC das interfaces e para switches ligados diretamente entre si. Clique em um nó, filtre por nome e arraste para reorganizar o mapa.</p>
        </div>
        <div class="topology-controls">
          <a class="btn" href="/networks">IPAM</a>
          <a class="btn" href="/devices">Devices</a>
          <a class="btn" href="/discovery">Descoberta</a>
          <a class="btn primary" href="/networks#results">Abrir roteamento</a>
        </div>
      </section>
      {f'<div class="hero"><small>Erro</small><strong>{escape(page_error)}</strong></div>' if page_error else ''}
      <section class="topology-stats">
        <div class="topology-stat"><span class="label">Dispositivos localizados</span><strong>{graph.get("discovered_count", len(graph["nodes"]))}</strong></div>
        <div class="topology-stat"><span class="label">Switches / rede</span><strong>{graph.get("network_count", 0)}</strong></div>
        <div class="topology-stat"><span class="label">Ligações físicas</span><strong>{len(graph["edges"])}</strong></div>
        <div class="topology-stat"><span class="label">Nó central</span><strong>{escape(_normalize_text(graph["nodes"][0]["label"]) if graph["nodes"] else "—")}</strong></div>
        <div class="topology-stat"><span class="label">Prefixos IPAM</span><strong>{len(prefixes)}</strong></div>
      </section>
      <section class="topology-workspace">
        <div class="topology-panel">
          <div class="topology-toolbar">
            <div class="field" style="flex:1 1 280px;">
              <label for="topology-search">Filtrar device</label>
              <input id="topology-search" type="text" placeholder="Digite um nome, site, role ou IP..." />
            </div>
            <div class="topology-controls">
              <button class="btn" type="button" id="topology-relayout">Reorganizar</button>
              <button class="btn" type="button" id="topology-reset">Limpar filtro</button>
            </div>
          </div>
          <div class="topology-graph-wrap">
            <svg id="topology-svg" viewBox="0 0 1600 760" preserveAspectRatio="xMidYMid meet" aria-label="Mapa de topologia">
              <defs>
                <pattern id="topology-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(148,163,184,.10)" stroke-width="1" />
                </pattern>
                <linearGradient id="topology-edge-prefix" x1="0" x2="1" y1="0" y2="0">
                  <stop offset="0%" stop-color="#38bdf8" />
                  <stop offset="100%" stop-color="#34d399" />
                </linearGradient>
                <marker id="topology-arrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto" markerUnits="strokeWidth">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#34d399" />
                </marker>
              </defs>
              <rect width="1600" height="760" fill="url(#topology-grid)" opacity=".35"></rect>
              <g id="topology-links"></g>
              <g id="topology-nodes"></g>
              <g id="topology-overlay"></g>
            </svg>
          </div>
          <div class="topology-legend">
            <span><i style="background:#14b8a6"></i>Rede</span>
            <span><i style="background:#2563eb"></i>Servidor</span>
            <span><i style="background:#7c3aed"></i>Wireless</span>
            <span><i style="background:#f97316"></i>Usuário</span>
            <span><i style="background:#34d399"></i>Ligação ativa</span>
          </div>
        </div>
        <aside class="topology-panel topology-detail">
          <div style="padding:16px 18px; border-bottom:1px solid rgba(148,163,184,.12);">
            <div class="topology-kicker">Detalhes</div>
            <h3 id="topology-detail-title" style="margin:6px 0 0;">Selecione um device</h3>
            <p id="topology-detail-sub" style="margin:8px 0 0; color:#cbd5e1; line-height:1.45;">Clique em um nó do grafo para visualizar site, IP, função e vizinhos.</p>
          </div>
          <div style="padding:18px;" class="topology-detail-card">
            <div class="panel" style="margin:0; background:rgba(15,23,42,.65);">
              <div class="glpi-info-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
                <div class="glpi-info-item"><span class="label">Status</span><strong id="topology-detail-status">—</strong></div>
                <div class="glpi-info-item"><span class="label">Site</span><strong id="topology-detail-site">—</strong></div>
                <div class="glpi-info-item"><span class="label">Role</span><strong id="topology-detail-role">—</strong></div>
                <div class="glpi-info-item"><span class="label">IP</span><strong id="topology-detail-ip">—</strong></div>
              </div>
            </div>
            <div class="panel" style="margin:0; background:rgba(15,23,42,.65);">
              <div class="glpi-info-grid" style="grid-template-columns: repeat(2, minmax(0, 1fr));">
                <div class="glpi-info-item"><span class="label">Grau</span><strong id="topology-detail-degree">0</strong></div>
                <div class="glpi-info-item"><span class="label">Prefixos</span><strong id="topology-detail-prefixes">0</strong></div>
              </div>
            </div>
            <div class="panel" style="margin:0; background:rgba(15,23,42,.65);">
              <h4 style="margin:0 0 10px;">Vizinhos</h4>
              <div id="topology-neighbors" class="topology-node-list"></div>
            </div>
          </div>
        </aside>
      </section>
      <div class="panel">
        <h2>Mapa da rede</h2>
        <p>Visualização textual de apoio com as rotas e vínculos persistidos no IPAM.</p>
        <table>
          <thead>
            <tr>
              <th>Rede</th><th>Tipo</th><th>VLAN</th><th>Origem</th><th>Porta origem</th><th>Modo origem</th><th>Proximo salto</th><th>Porta destino</th><th>Modo destino</th><th>Observacoes</th>
            </tr>
          </thead>
          <tbody>{route_rows}</tbody>
        </table>
      </div>
    </div>
    <script id="topology-data" type="application/json">{graph_json}</script>
    <script>
      const topologyData = JSON.parse(document.getElementById('topology-data').textContent);
      const svg = document.getElementById('topology-svg');
      const linksLayer = document.getElementById('topology-links');
      const nodesLayer = document.getElementById('topology-nodes');
      const detailTitle = document.getElementById('topology-detail-title');
      const detailSub = document.getElementById('topology-detail-sub');
      const detailStatus = document.getElementById('topology-detail-status');
      const detailSite = document.getElementById('topology-detail-site');
      const detailRole = document.getElementById('topology-detail-role');
      const detailIp = document.getElementById('topology-detail-ip');
      const detailDegree = document.getElementById('topology-detail-degree');
      const detailPrefixes = document.getElementById('topology-detail-prefixes');
      const neighborsList = document.getElementById('topology-neighbors');
      const searchInput = document.getElementById('topology-search');
      const relayoutButton = document.getElementById('topology-relayout');
      const resetButton = document.getElementById('topology-reset');
      const nodeMap = new Map();
      const edgeElements = new Map();
      const edgeItems = [];
      const colors = {{
        'Rede': '#14b8a6',
        'Servidor': '#2563eb',
        'Wireless': '#7c3aed',
        'Usuario': '#f97316',
        'Outro': '#64748b',
      }};
      const state = {{
        selectedId: topologyData.core_nodes && topologyData.core_nodes.length ? topologyData.core_nodes[0] : '',
        query: '',
        draggingId: '',
        viewBox: {{ x: 0, y: 0, width: 1600, height: 760 }},
      }};

      function escapeHtml(value) {{
        return String(value ?? '')
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }}

      function toTitle(value) {{
        return String(value || '').trim() || '—';
      }}

      function kindColor(kind) {{
        return colors[kind] || colors.Outro;
      }}

      function tierLabel(node) {{
        const tier = String(node.topology_tier || 'leaf').toLowerCase();
        if (tier === 'core') {{
          return 'Core';
        }}
        if (tier === 'distribution') {{
          return 'Distribuição';
        }}
        return 'Borda';
      }}

      function createSvgElement(tag, attrs = {{}}) {{
        const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
        for (const [key, value] of Object.entries(attrs)) {{
          element.setAttribute(key, value);
        }}
        return element;
      }}

      function buildSearchText(node) {{
        return String(node.search_text || '').toLowerCase();
      }}

      function edgeStyle(edge) {{
        if (edge.edge_type === 'lldp-link') {{
          return {{ stroke: '#60a5fa', width: 3.6, dash: '9 4' }};
        }}
        if (edge.edge_type === 'cdp-link') {{
          return {{ stroke: '#f59e0b', width: 3.4, dash: '7 4' }};
        }}
        if (edge.edge_type === 'bridge-link') {{
          return {{ stroke: '#a78bfa', width: 3.2, dash: '4 4' }};
        }}
        if (edge.edge_type === 'mac-link') {{
          return {{ stroke: '#22c55e', width: 3.2, dash: '' }};
        }}
        if (edge.edge_type === 'device-link') {{
          return {{ stroke: '#34d399', width: 2.8, dash: '6 4' }};
        }}
        return {{ stroke: 'url(#topology-edge-prefix)', width: 2.2, dash: '10 7' }};
      }}

      function edgeKey(edge) {{
        const left = String(edge.source || '');
        const right = String(edge.target || '');
        return [left, right].sort().join('::');
      }}

      function hashValue(value) {{
        let hash = 0;
        const text = String(value || '');
        for (let index = 0; index < text.length; index += 1) {{
          hash = ((hash << 5) - hash) + text.charCodeAt(index);
          hash |= 0;
        }}
        return Math.abs(hash);
      }}

      function connectionsFor(nodeId) {{
        return (topologyData.edges || [])
          .filter((edge) => edge.source === nodeId || edge.target === nodeId)
          .map((edge) => {{
            const linkedId = edge.source === nodeId ? edge.target : edge.source;
            const linked = topologyData.nodes.find((item) => item.id === linkedId);
            return {{
              edge,
              id: linkedId,
              label: linked ? linked.label : linkedId,
              href: linked && linked.device_link ? linked.device_link : '',
              direction: edge.source === nodeId ? 'saída' : 'entrada',
            }};
          }});
      }}

      function initializePositions() {{
        const nodes = topologyData.nodes || [];
        const adjacency = new Map();
        for (const edge of topologyData.edges || []) {{
          if (!adjacency.has(edge.source)) {{
            adjacency.set(edge.source, []);
          }}
          if (!adjacency.has(edge.target)) {{
            adjacency.set(edge.target, []);
          }}
          adjacency.get(edge.source).push(edge);
          adjacency.get(edge.target).push(edge);
        }}
        const centerX = 800;
        const centerY = 380;
        const hubIds = new Set((topologyData.core_nodes && topologyData.core_nodes.length ? topologyData.core_nodes : nodes
          .slice()
          .sort((left, right) => Number(right.degree || 0) - Number(left.degree || 0))
          .slice(0, 5)
          .map((node) => node.id)));
        const hubs = nodes.filter((node) => hubIds.has(node.id));
        const baseHubRadius = 190;
        hubs.forEach((node, index) => {{
          const angle = (index / Math.max(1, hubs.length)) * Math.PI * 2 - Math.PI / 2;
          node.x = centerX + Math.cos(angle) * baseHubRadius;
          node.y = centerY + Math.sin(angle) * baseHubRadius;
          node.fx = node.x;
          node.fy = node.y;
        }});
        const hubLookup = new Map(hubs.map((node) => [node.id, node]));
        nodes.forEach((node, index) => {{
          if (hubLookup.has(node.id)) {{
            return;
          }}
          const linkedEdges = adjacency.get(node.id) || [];
          let anchor = hubs[0] || nodes[0] || null;
          if (linkedEdges.length) {{
            const sortedEdges = linkedEdges.slice().sort((left, right) => {{
              const leftOtherId = left.source === node.id ? left.target : left.source;
              const rightOtherId = right.source === node.id ? right.target : right.source;
              const leftOther = nodes.find((item) => item.id === leftOtherId);
              const rightOther = nodes.find((item) => item.id === rightOtherId);
              return Number(rightOther?.degree || 0) - Number(leftOther?.degree || 0);
            }});
            const bestEdge = sortedEdges[0];
            const bestOtherId = bestEdge ? (bestEdge.source === node.id ? bestEdge.target : bestEdge.source) : '';
            anchor = nodes.find((item) => item.id === bestOtherId) || anchor;
          }}
          const anchorX = anchor ? anchor.x : centerX;
          const anchorY = anchor ? anchor.y : centerY;
          const angle = ((hashValue(node.id) + index * 37) % 360) * (Math.PI / 180);
          const radius = 120 + Math.min(240, (node.degree || 0) * 28);
          const anchorRadius = hubLookup.has(anchor && anchor.id ? anchor.id : '') ? 108 : 88;
          node.x = anchorX + Math.cos(angle) * (anchorRadius + radius * 0.16);
          node.y = anchorY + Math.sin(angle) * (anchorRadius + radius * 0.16);
        }});

        for (let iteration = 0; iteration < 150; iteration += 1) {{
          for (const edge of topologyData.edges || []) {{
            const source = nodes.find((node) => node.id === edge.source);
            const target = nodes.find((node) => node.id === edge.target);
            if (!source || !target) continue;
            const dx = target.x - source.x;
            const dy = target.y - source.y;
            const distance = Math.max(20, Math.hypot(dx, dy));
            const ideal = 130 + Math.min(160, ((source.degree || 0) + (target.degree || 0)) * 8);
            const force = (distance - ideal) * 0.0012;
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            if (!source.fx) {{
              source.x += fx * 6;
              source.y += fy * 6;
            }}
            if (!target.fx) {{
              target.x -= fx * 6;
              target.y -= fy * 6;
            }}
          }}
          for (let a = 0; a < nodes.length; a += 1) {{
            for (let b = a + 1; b < nodes.length; b += 1) {{
              const left = nodes[a];
              const right = nodes[b];
              const dx = right.x - left.x;
              const dy = right.y - left.y;
              const distance = Math.max(18, Math.hypot(dx, dy));
              const repulsion = 22000 / (distance * distance);
              const fx = (dx / distance) * repulsion;
              const fy = (dy / distance) * repulsion;
              if (!left.fx) {{
                left.x -= fx;
                left.y -= fy;
              }}
              if (!right.fx) {{
                right.x += fx;
                right.y += fy;
              }}
            }}
          }}
          nodes.forEach((node) => {{
            if (node.fx) {{
              node.x = node.fx;
            }}
            if (node.fy) {{
              node.y = node.fy;
            }}
            node.x = Math.max(80, Math.min(1520, node.x));
            node.y = Math.max(70, Math.min(690, node.y));
          }});
        }}
      }}

      function nodeRadius(node) {{
        const degree = Number(node.degree || 0);
        const tier = String(node.topology_tier || 'leaf').toLowerCase();
        const base = tier === 'core' ? 40 : tier === 'distribution' ? 34 : node.group === 'switches' || node.group === 'network' ? 30 : 24;
        const scale = tier === 'core' ? 2.6 : tier === 'distribution' ? 2.4 : 2.1;
        return Math.max(24, Math.min(68, base + degree * scale));
      }}

      function nodeLabelLines(node) {{
        const raw = String(node.label || node.id || '').trim();
        if (!raw) {{
          return ['Device'];
        }}
        const tier = String(node.topology_tier || 'leaf').toLowerCase();
        const maxChars = tier === 'core' ? 20 : tier === 'distribution' ? 16 : 14;
        if (raw.length <= maxChars) {{
          return [raw];
        }}
        const words = raw.split(/\s+/).filter(Boolean);
        if (words.length <= 1) {{
          return [raw.slice(0, maxChars), raw.slice(maxChars, maxChars * 2)].filter(Boolean);
        }}
        const firstLine = [];
        let firstLength = 0;
        while (words.length) {{
          const nextWord = words[0];
          const proposed = firstLine.length ? firstLength + 1 + nextWord.length : nextWord.length;
          if (proposed > maxChars) {{
            break;
          }}
          firstLine.push(words.shift());
          firstLength = proposed;
        }}
        const secondLine = words.join(' ');
        return [firstLine.join(' '), secondLine].filter(Boolean).slice(0, 2);
      }}

      function edgePath(source, target, offset = 0) {{
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const distance = Math.max(1, Math.hypot(dx, dy));
        const nx = -dy / distance;
        const ny = dx / distance;
        const bend = Math.min(150, Math.max(52, distance * 0.24)) + Math.abs(offset) * 28;
        const signedBend = bend * (offset === 0 ? 1 : Math.sign(offset));
        const mx = (source.x + target.x) / 2 + nx * signedBend;
        const my = (source.y + target.y) / 2 + ny * signedBend;
        return 'M ' + source.x + ' ' + source.y + ' Q ' + mx + ' ' + my + ' ' + target.x + ' ' + target.y;
      }}

      function edgeLabelPosition(source, target, offset = 0) {{
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const distance = Math.max(1, Math.hypot(dx, dy));
        const nx = -dy / distance;
        const ny = dx / distance;
        const bend = Math.min(150, Math.max(52, distance * 0.24)) + Math.abs(offset) * 28;
        const signedBend = bend * (offset === 0 ? 1 : Math.sign(offset));
        return {{
          x: (source.x + target.x) / 2 + nx * (signedBend * .56),
          y: (source.y + target.y) / 2 + ny * (signedBend * .56),
        }};
      }}

      function renderGraph() {{
        nodesLayer.innerHTML = '';
        linksLayer.innerHTML = '';
        nodeMap.clear();
        edgeElements.clear();
        edgeItems.length = 0;

        const groupedEdges = new Map();
        for (const edge of topologyData.edges || []) {{
          const key = edgeKey(edge);
          if (!groupedEdges.has(key)) {{
            groupedEdges.set(key, []);
          }}
          groupedEdges.get(key).push(edge);
        }}

        for (const [pairKey, edges] of groupedEdges.entries()) {{
          const ordered = edges.slice().sort((left, right) => {{
            const priority = (value) => value === 'lldp-link' ? 0 : value === 'cdp-link' ? 1 : value === 'bridge-link' ? 2 : value === 'mac-link' ? 3 : value === 'device-link' ? 4 : 9;
            return priority(left.edge_type) - priority(right.edge_type) || String(left.label || left.prefix || '').localeCompare(String(right.label || right.prefix || ''));
          }});
          for (const [index, edge] of ordered.entries()) {{
            const style = edgeStyle(edge);
            const path = createSvgElement('path', {{
              d: '',
              class: 'edge',
              fill: 'none',
              stroke: style.stroke,
              'stroke-width': String(style.width),
              'stroke-dasharray': style.dash,
              'marker-end': 'url(#topology-arrow)',
              'data-source': edge.source,
              'data-target': edge.target,
              'data-pair': pairKey,
              'data-index': String(index),
            }});
            path.appendChild(createSvgElement('title'));
            path.querySelector('title').textContent = `${{edge.label || edge.prefix || 'Ligação'}}`;
            const label = createSvgElement('text', {{
              class: 'edge-label',
              'data-source': edge.source,
              'data-target': edge.target,
              'data-pair': pairKey,
              'data-index': String(index),
            }});
            label.textContent = edge.label || edge.prefix || edge.edge_type || 'Ligação';
            linksLayer.appendChild(path);
            linksLayer.appendChild(label);
            edgeItems.push({{ edge, path, label, index, count: ordered.length }});
            edgeElements.set(`${{edge.source}}::${{edge.target}}::${{index}}`, path);
          }}
        }}

        for (const node of topologyData.nodes || []) {{
          const group = createSvgElement('g', {{
            class: 'node',
            'data-id': node.id,
            'data-kind': node.kind || 'Outro',
            'data-tier': node.topology_tier || 'leaf',
            transform: `translate(${{node.x}}, ${{node.y}})`,
          }});

          const radius = nodeRadius(node);
          group.appendChild(createSvgElement('circle', {{
            r: radius,
            fill: kindColor(node.kind),
            stroke: '#d1d5db',
            'stroke-width': node.id === state.selectedId ? '4' : '2',
          }}));
          group.appendChild(createSvgElement('circle', {{
            class: 'node-badge',
            r: Math.max(10, radius * .32),
            cx: radius * .35,
            cy: -radius * .32,
            fill: '#0f172a',
          }}));

          const labelLines = nodeLabelLines(node);
          const mini = `${{tierLabel(node)}} • ${{Number(node.degree || 0)}}`;

          const text = createSvgElement('text', {{
            class: 'node-label',
            y: radius + 18,
          }});
          labelLines.forEach((line, lineIndex) => {{
            const tspan = createSvgElement('tspan', {{
              x: '0',
              dy: lineIndex === 0 ? '0' : '1.15em',
            }});
            tspan.textContent = line;
            text.appendChild(tspan);
          }});
          group.appendChild(text);

          const miniText = createSvgElement('text', {{
            class: 'node-mini',
            y: -radius - 8,
          }});
          miniText.textContent = mini;
          group.appendChild(miniText);

          group.appendChild(createSvgElement('title'));
          group.querySelector('title').textContent = `${{node.label}} | ${{node.site}} | ${{node.primary_ip}}`;

          group.addEventListener('pointerdown', (event) => {{
            event.preventDefault();
            state.selectedId = node.id;
            state.draggingId = node.id;
            const pointerMove = (moveEvent) => {{
              if (state.draggingId !== node.id) {{
                return;
              }}
              const point = svg.createSVGPoint();
              point.x = moveEvent.clientX;
              point.y = moveEvent.clientY;
              const cursor = point.matrixTransform(svg.getScreenCTM().inverse());
              node.x = Math.max(80, Math.min(1520, cursor.x));
              node.y = Math.max(70, Math.min(690, cursor.y));
              node.fx = node.x;
              node.fy = node.y;
              updateGraph();
            }};
            const pointerUp = () => {{
              state.draggingId = '';
              node.fx = node.x;
              node.fy = node.y;
              window.removeEventListener('pointermove', pointerMove);
              window.removeEventListener('pointerup', pointerUp);
            }};
            window.addEventListener('pointermove', pointerMove);
            window.addEventListener('pointerup', pointerUp);
            updateDetails(node);
            updateGraph();
          }});

          nodeMap.set(node.id, {{ node, element: group }});
          nodesLayer.appendChild(group);
        }}
      }}

      function updateDetails(node) {{
        if (!node) {{
          detailTitle.textContent = 'Selecione um device';
          detailSub.textContent = 'Clique em um nó do grafo para visualizar site, IP, função e vizinhos.';
          detailStatus.textContent = '—';
          detailSite.textContent = '—';
          detailRole.textContent = '—';
          detailIp.textContent = '—';
          detailDegree.textContent = '0';
          detailPrefixes.textContent = '0';
          neighborsList.innerHTML = '<div class="topology-node-item"><div><strong>Nenhum nó selecionado</strong><small>Use o filtro ou clique em um device no mapa.</small></div></div>';
          return;
        }}

        detailTitle.textContent = node.label;
        detailSub.textContent = `${{node.manufacturer || 'Fabricante não informado'}} ${{node.model && node.model !== '—' ? '• ' + node.model : ''}}`.trim();
        detailStatus.textContent = toTitle(node.status);
        detailSite.textContent = toTitle(node.site);
        detailRole.textContent = toTitle(node.role);
        detailIp.textContent = toTitle(node.primary_ip);
        detailDegree.textContent = `${{Number(node.degree || 0)}} (${{
          String(node.topology_tier || 'leaf').toLowerCase() === 'core' ? 'núcleo' :
          String(node.topology_tier || 'leaf').toLowerCase() === 'distribution' ? 'distribuição' : 'borda'
        }})`;
        detailPrefixes.textContent = String(node.prefix_count || 0);

        const connections = connectionsFor(node.id);
        neighborsList.innerHTML = connections.length ? connections.map((connection) => {{
          const linked = topologyData.nodes.find((item) => item.id === connection.id);
          const label = linked ? linked.label : connection.id;
          const href = connection.href || (linked && linked.device_link ? linked.device_link : '');
          const edge = connection.edge || {{}};
          const ports = [edge.source_port, edge.target_port].filter(Boolean).join(' ↔ ');
          const detail = [edge.edge_type ? edge.edge_type.replace('-link', '').toUpperCase() : '', ports, edge.remote_sys_name || ''].filter(Boolean).join(' • ');
          return `<div class="topology-node-item${{edge.edge_type === 'lldp-link' ? ' active' : ''}}"><div><strong>${{escapeHtml(label)}}</strong><small>${{escapeHtml(detail || connection.direction)}}${{edge.label ? ` • ${{escapeHtml(edge.label)}}` : ''}}</small></div>${{href ? `<a href="${{escapeHtml(href)}}">Abrir</a>` : ''}}</div>`;
        }}).join('') : '<div class="topology-node-item"><div><strong>Sem vizinhos</strong><small>Este device nao possui ligacoes registradas.</small></div></div>';
      }}

      function updateGraph() {{
        const query = String(state.query || '').trim().toLowerCase();
        const selected = topologyData.nodes.find((node) => node.id === state.selectedId) || topologyData.nodes[0] || null;
        if (selected) {{
          state.selectedId = selected.id;
          updateDetails(selected);
        }}
        const matchedIds = new Set();
        if (query) {{
          for (const node of topologyData.nodes || []) {{
            if (buildSearchText(node).includes(query)) {{
              matchedIds.add(node.id);
            }}
          }}
        }}
        const activeNeighborIds = new Set();
        if (state.selectedId) {{
          activeNeighborIds.add(state.selectedId);
          for (const connection of connectionsFor(state.selectedId)) {{
            activeNeighborIds.add(connection.id);
          }}
        }}

        for (const [nodeId, item] of nodeMap.entries()) {{
          const {{ node, element }} = item;
          element.setAttribute('transform', `translate(${{node.x}}, ${{node.y}})`);
          const activeByQuery = !query || matchedIds.has(nodeId);
          const activeBySelection = !state.selectedId || activeNeighborIds.has(nodeId);
          element.classList.toggle('dimmed', !(activeByQuery && activeBySelection));
          element.classList.toggle('selected', nodeId === state.selectedId);
          const circle = element.querySelector('circle');
          if (circle) {{
            circle.setAttribute('stroke-width', nodeId === state.selectedId ? '4' : '2');
          }}
          const textElements = element.querySelectorAll('text');
          textElements.forEach((text) => {{
            text.style.opacity = (activeByQuery && activeBySelection) ? '1' : '.25';
          }});
        }}

        for (const item of edgeItems) {{
          const {{ edge, path, label, index, count }} = item;
          const source = topologyData.nodes.find((node) => node.id === edge.source);
          const target = topologyData.nodes.find((node) => node.id === edge.target);
          if (!source || !target) continue;
          const offset = index - ((count - 1) / 2);
          path.setAttribute('d', edgePath(source, target, offset));
          const position = edgeLabelPosition(source, target, offset);
          label.setAttribute('x', String(position.x));
          label.setAttribute('y', String(position.y - 8));
          label.classList.toggle('dimmed', false);
          const isSelectedEdge = state.selectedId && (edge.source === state.selectedId || edge.target === state.selectedId);
          path.classList.toggle('selected', isSelectedEdge);
          const edgeText = String(edge.label || edge.prefix || edge.mac_address || edge.remote_sys_name || edge.source_port || edge.target_port || edge.peer_name || '').toLowerCase();
          const activeByQuery = !query || matchedIds.has(edge.source) || matchedIds.has(edge.target) || edgeText.includes(query);
          const activeBySelection = !state.selectedId || activeNeighborIds.has(edge.source) || activeNeighborIds.has(edge.target);
          const active = activeByQuery && activeBySelection;
          path.classList.toggle('dimmed', !active);
          label.classList.toggle('dimmed', !active);
        }}
      }}

      function fitToScreen() {{
        initializePositions();
        updateGraph();
      }}

      searchInput.addEventListener('input', () => {{
        state.query = searchInput.value;
        updateGraph();
      }});

      relayoutButton.addEventListener('click', () => {{
        fitToScreen();
      }});

      resetButton.addEventListener('click', () => {{
        searchInput.value = '';
        state.query = '';
        const defaultNode = topologyData.nodes.find((node) => topologyData.core_nodes.includes(node.id)) || topologyData.nodes[0] || null;
        state.selectedId = defaultNode ? defaultNode.id : '';
        fitToScreen();
      }});

      initializePositions();
      renderGraph();
      updateGraph();
      if (!state.selectedId && topologyData.nodes.length) {{
        state.selectedId = topologyData.nodes[0].id;
      }}
      updateGraph();
    </script>
    """
    return _render_management_page(
        title="Mapa interativo | infra-sync-api",
        active="networks",
        heading="Mapa interativo",
        subtitle="Ligacoes entre equipamentos, portas, VLANs e prefixes em uma visualizacao navegavel.",
        actions='<a class="btn" href="/networks">IPAM</a><a class="btn" href="/devices">Devices</a><a class="btn" href="/reports">Relatorios</a>',
        body=body,
    )


@app.post("/devices/save", include_in_schema=False)
async def save_device_page(request: Request):
    form = await _read_form(request)
    client = await _get_netbox_client_or_error(request)
    payload: dict[str, Any] = {}
    for key in ("name", "status", "comments", "serial"):
        value = _form_value(form, key)
        if value:
            payload[key] = value
    for key in ("site_id", "role_id", "device_type_id", "rack_id", "primary_ip4_id"):
        value = _form_value(form, key)
        if value:
            try:
                payload[key.replace("_id", "")] = int(value)
            except ValueError as exc:
                return HTMLResponse(await _render_crud_error(request, "devices", f"{key} precisa ser um inteiro válido"), status_code=status.HTTP_400_BAD_REQUEST)
    try:
        custom_fields = _parse_custom_fields_form(form, limit=6)
    except (ValueError, json.JSONDecodeError) as exc:
        return HTMLResponse(await _render_crud_error(request, "devices", str(exc)), status_code=status.HTTP_400_BAD_REQUEST)
    device_id = _form_value(form, "device_id")
    if custom_fields:
        existing_device: dict[str, Any] | None = None
        if device_id:
            with suppress(Exception):
                existing_device = await client.get_device(int(device_id))
        merged_custom_fields = dict(existing_device.get("custom_fields") or {}) if isinstance(existing_device, dict) else {}
        merged_custom_fields.update(custom_fields)
        payload["custom_fields"] = merged_custom_fields
    try:
        if device_id:
            await client.update_device(int(device_id), payload)
        else:
            await client.create_device(payload)
    except Exception as exc:
        return HTMLResponse(await _render_crud_error(request, "devices", str(exc)), status_code=status.HTTP_400_BAD_REQUEST)
    return RedirectResponse(url="/devices?saved=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/vlans", include_in_schema=False)
async def vlans_page(request: Request, saved: int = 0, error: str | None = None, edit: int | None = None):
    client = request.app.state.netbox_client
    vlans: list[dict[str, Any]] = []
    edit_vlan: dict[str, Any] | None = None
    page_error = error
    try:
        if client is not None:
            params: dict[str, Any] = {"limit": 50}
            q = _query_value(request, "q")
            if q:
                params["q"] = q
            vlans = await client.list_vlans(params=params)
            if edit is not None:
                edit_vlan = await client.get_vlan(edit)
    except Exception as exc:
        page_error = str(exc)
    rows = []
    for vlan in vlans:
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(_normalize_text(vlan.get('vid')) or '—')}</strong></td>
              <td>{escape(_normalize_text(vlan.get('name')) or '—')}</td>
              <td>{escape(_relation_label(vlan.get('status')))}</td>
              <td>{escape(_relation_label(vlan.get('site')))}</td>
              <td>{escape(_normalize_text(vlan.get('description')) or '—')}</td>
              <td><a href="/vlans?edit={escape(_related_id(vlan.get('id')))}">Editar</a></td>
            </tr>
            """
        )
    banner = "<div class='hero'><small>Salvo</small><strong>VLAN atualizada com sucesso.</strong></div>" if saved else ""
    if page_error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(page_error)}</strong></div>"
    body = f"""
    <div class="panels" style="grid-template-columns: 1fr 1.2fr;">
      {_vlan_form(edit_vlan)}
      <div class="panel">
        <h2>VLANs cadastradas</h2>
        <p>Segmentações registradas no NetBox.</p>
        <table>
          <thead><tr><th>VID</th><th>Nome</th><th>Status</th><th>Site</th><th>Descrição</th><th></th></tr></thead>
          <tbody>{''.join(rows) if rows else _render_table_empty('Nenhuma VLAN encontrada.', 6)}</tbody>
        </table>
      </div>
    </div>
    """
    return HTMLResponse(
        _render_management_page(
            title="VLANs | infra-sync-api",
            active="vlans",
            heading="VLANs",
            subtitle="Criar, editar e visualizar segmentações de rede.",
            actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/reports">Imprimir relatório</a>',
            body=body,
            banner=banner,
        )
    )


@app.post("/vlans/save", include_in_schema=False)
async def save_vlan_page(request: Request):
    form = await _read_form(request)
    client = await _get_netbox_client_or_error(request)
    payload: dict[str, Any] = {}
    for key in ("vid", "name", "status", "description"):
        value = _form_value(form, key)
        if value:
            payload[key] = value if key != "vid" else int(value)
    site_id = _form_value(form, "site_id")
    if site_id:
        try:
            payload["site"] = int(site_id)
        except ValueError:
            return HTMLResponse(await _render_crud_error(request, "vlans", "site_id precisa ser um inteiro válido"), status_code=status.HTTP_400_BAD_REQUEST)
    vlan_id = _form_value(form, "vlan_id")
    try:
        if vlan_id:
            await client.update_vlan(int(vlan_id), payload)
        else:
            await client.create_vlan(payload)
    except Exception as exc:
        return HTMLResponse(await _render_crud_error(request, "vlans", str(exc)), status_code=status.HTTP_400_BAD_REQUEST)
    return RedirectResponse(url="/vlans?saved=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/networks", include_in_schema=False)
async def networks_page(request: Request, saved: int = 0, error: str | None = None, edit: int | None = None):
    client = request.app.state.netbox_client
    prefixes: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []
    ip_rows: list[dict[str, Any]] = []
    topology_state = load_network_topology()
    edit_prefix: dict[str, Any] | None = None
    edit_topology: dict[str, Any] | None = None
    page_error = error
    try:
        if client is not None:
            params: dict[str, Any] = {"limit": 50}
            q = _query_value(request, "q")
            if q:
                params["q"] = q
            prefixes = await client.list_prefixes(params=params)
            devices = await client.list_devices(params={"limit": 100})
            ip_rows = await _collect_ipam_address_rows(client, q)
            if edit is not None:
                edit_prefix = await client.get_prefix(edit)
                edit_topology = _topology_entry_for_prefix(topology_state, edit)
    except Exception as exc:
        page_error = str(exc)
    rows = []
    for prefix in prefixes:
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(_normalize_text(prefix.get('prefix')) or '?')}</strong></td>
              <td>{escape(_normalize_text(prefix.get('description')) or '?')}</td>
              <td>{escape(_relation_label(prefix.get('status')))}</td>
              <td>{escape(_relation_label(prefix.get('site')))}</td>
              <td>{escape(_relation_label(prefix.get('vlan')))}</td>
              <td><a href="/networks?edit={escape(_related_id(prefix.get('id')))}">Editar</a></td>
            </tr>
            """
        )
    banner = "<div class='hero'><small>Salvo</small><strong>Rede atualizada com sucesso.</strong></div>" if saved else ""
    if page_error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(page_error)}</strong></div>"
    device_lookup = {
        _related_id(device.get("id")): _normalize_text(device.get("name"))
        for device in devices
        if isinstance(device, dict)
    }
    used_ip_rows = [row for row in ip_rows if _normalize_text(row.get("device_id")) or _normalize_text(row.get("assigned_label")) not in {"", "—"}]
    used_ip_count = len([row for row in ip_rows if _normalize_text(row.get("device_id"))])
    body = f"""
    <div class="panels" style="grid-template-columns: 1fr 1.2fr;">
      {_prefix_form(edit_prefix, edit_topology, devices)}
      <div class="panel">
        <h2>Redes e prefixes</h2>
        <p>Blocos IP cadastrados no IPAM do NetBox.</p>
        <table>
          <thead><tr><th>Prefixo</th><th>Descricao</th><th>Status</th><th>Site</th><th>VLAN</th><th></th></tr></thead>
          <tbody>{''.join(rows) if rows else _render_table_empty('Nenhuma rede encontrada.', 6)}</tbody>
        </table>
      </div>
    </div>
    <div class="panel" style="margin-top:14px;">
      <h2>IPs em uso</h2>
      <p>Quando o IP estiver associado a uma interface NetBox, o link leva diretamente ao device dono daquele endereço.</p>
      <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:12px; color:#cbd5e1;">
        <span><strong>{used_ip_count}</strong> IPs vinculados a devices</span>
        <span><strong>{len(ip_rows)}</strong> IPs carregados do IPAM</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>IP</th><th>Status</th><th>Device</th><th>Interface</th><th>Alocação</th><th>Tenant</th><th>Descrição</th>
          </tr>
        </thead>
        <tbody>
          {"".join(
            f"<tr><td><strong>{escape(row['address'])}</strong></td><td>{escape(row['status'])}</td><td>{row['device_link']}</td><td>{escape(row['interface_name'])}</td><td>{escape(row['assigned_label'])}</td><td>{escape(row['tenant'])}</td><td>{escape(row['description'])}</td></tr>"
            for row in used_ip_rows
          ) if used_ip_rows else _render_table_empty('Nenhum IP vinculado encontrado.', 7)}
        </tbody>
      </table>
    </div>
    <div class="panel" style="margin-top:14px;">
      <h2>Mapa da rede</h2>
      <p>Origem, porta, modo e proximo salto de cada rede ou VLAN mapeada.</p>
      <table>
        <thead>
          <tr>
            <th>Rede</th><th>Tipo</th><th>VLAN</th><th>Origem</th><th>Porta origem</th><th>Modo origem</th><th>Proximo salto</th><th>Porta destino</th><th>Modo destino</th><th>Observacoes</th>
          </tr>
        </thead>
        <tbody>{_render_topology_rows(prefixes, topology_state, device_lookup)}</tbody>
      </table>
    </div>
    """
    return HTMLResponse(
        _render_management_page(
            title="IPAM | infra-sync-api",
            active="networks",
            heading="IPAM",
            subtitle="Criar, editar e revisar prefixes, redes e IPs em uso.",
            actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/topology">Mapa</a><a class="btn" href="/reports">Imprimir relat?rio</a>',
            body=body,
            banner=banner,
        )
    )


@app.post("/networks/save", include_in_schema=False)
async def save_network_page(request: Request):
    form = await _read_form(request)
    client = await _get_netbox_client_or_error(request)
    payload: dict[str, Any] = {}
    for key in ("prefix", "status", "description"):
        value = _form_value(form, key)
        if value:
            payload[key] = value
    site_id = _form_value(form, "site_id")
    if site_id:
        try:
            payload["site"] = int(site_id)
        except ValueError:
            return HTMLResponse(await _render_crud_error(request, "networks", "site_id precisa ser um inteiro v?lido"), status_code=status.HTTP_400_BAD_REQUEST)
    vlan_id = _form_value(form, "vlan_id")
    if vlan_id:
        try:
            payload["vlan"] = int(vlan_id)
        except ValueError:
            return HTMLResponse(await _render_crud_error(request, "networks", "vlan_id precisa ser um inteiro v?lido"), status_code=status.HTTP_400_BAD_REQUEST)
    prefix_id = _form_value(form, "prefix_id")
    try:
        if prefix_id:
            saved_prefix = await client.update_prefix(int(prefix_id), payload)
        else:
            saved_prefix = await client.create_prefix(payload)
    except Exception as exc:
        return HTMLResponse(await _render_crud_error(request, "networks", str(exc)), status_code=status.HTTP_400_BAD_REQUEST)
    if isinstance(saved_prefix, dict):
        topology_state = load_network_topology()
        entry = {
            "prefix_id": _related_id(saved_prefix.get("id")),
            "network_kind": _form_value(form, "network_kind", "prefix") or "prefix",
            "origin_device_id": _form_value(form, "origin_device_id"),
            "origin_interface": _form_value(form, "origin_interface"),
            "origin_mode": _form_value(form, "origin_mode"),
            "next_device_id": _form_value(form, "next_device_id"),
            "next_interface": _form_value(form, "next_interface"),
            "next_mode": _form_value(form, "next_mode"),
            "route_notes": _form_value(form, "route_notes"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        entries = _network_topology_entries(topology_state)
        updated = False
        for existing in entries:
            if str(existing.get("prefix_id")) == str(entry["prefix_id"]):
                existing.update({key: value for key, value in entry.items() if value != ""})
                updated = True
                break
        if not updated:
            entries.append({key: value for key, value in entry.items() if value != ""})
        topology_state["entries"] = entries
        save_network_topology(topology_state)
    return RedirectResponse(url="/networks?saved=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/topology", include_in_schema=False)
async def topology_page(request: Request):
    client = request.app.state.netbox_client
    prefixes: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []
    topology_state = load_network_topology()
    page_error: str | None = None
    discovery_state = load_last_scan()
    probe_state = load_last_probe()
    try:
        if client is not None:
            prefixes = await client.list_all("/api/ipam/prefixes/", params={"limit": 200})
            devices = await client.list_all("/api/dcim/devices/", params={"limit": 200})
    except Exception as exc:
        page_error = str(exc)
    netbox_by_mac = await _build_topology_netbox_mac_index(client, devices)
    inventory_devices = _topology_inventory_devices(discovery_state, devices, netbox_by_mac)
    try:
        connection_edges = await _collect_topology_connection_edges(client, inventory_devices, devices, probe_state, netbox_by_mac)
    except Exception:
        connection_edges = []
    graph = _topology_graph_payload(prefixes, topology_state, inventory_devices, devices, connection_edges, netbox_by_mac)
    return HTMLResponse(_render_topology_graph_page(graph, prefixes, topology_state, page_error=page_error))


@app.get("/api/alerts")
async def api_alerts(request: Request):
    client: ZabbixClient | None = request.app.state.zabbix_client
    if client is None:
        return {"alerts": [], "count": 0}
    try:
        alerts = await client.list_problems(limit=50)
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as exc:
        return {"alerts": [], "count": 0, "error": str(exc)}


@app.get("/alerts", include_in_schema=False)
async def alerts_page(request: Request, info: str | None = None, error: str | None = None):
    refresh_seconds = _refresh_interval_seconds(request.app.state.runtime)
    payload = await api_alerts(request)
    payload = dict(payload)
    payload["sound"] = request.app.state.runtime.get("alert_sound")
    if info:
        payload["info"] = info
    if error:
        payload["error"] = error
    return HTMLResponse(_render_alerts_page(payload, refresh_seconds))


@app.get("/api/cpd")
async def api_cpd(request: Request):
    return await _collect_cpd_snapshot(request)


@app.get("/cpd", include_in_schema=False)
async def cpd_page(request: Request):
    snapshot = await api_cpd(request)
    return HTMLResponse(_render_cpd_page(snapshot))


@app.post("/alerts/email/send", include_in_schema=False)
async def send_alerts_email(request: Request):
    runtime = request.app.state.runtime
    email_config = runtime.get("email")
    payload = await api_alerts(request)
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    try:
        result = await asyncio.to_thread(send_alert_email, email_config, alerts, source="Zabbix")
        message = f"E-mail enviado para {len(result['recipients'])} destinatario(s) com {result['alerts']} alerta(s)."
        return RedirectResponse(url=f"/alerts?info={quote(message)}", status_code=status.HTTP_303_SEE_OTHER)
    except EmailNotificationError as exc:
        return RedirectResponse(url=f"/alerts?error={quote(str(exc))}", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(url=f"/alerts?error={quote(str(exc))}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/reports", include_in_schema=False)
async def reports_page(request: Request):
    snapshot = await _collect_snapshot(request)
    return HTMLResponse(_render_reports_page(snapshot))


def _render_alerts_page(payload: dict[str, Any], refresh_seconds: int) -> str:
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    error_message = _normalize_text(payload.get("error"))
    info_message = _normalize_text(payload.get("info"))
    sound = _normalize_alert_sound_config(payload.get("sound"))
    rows = []
    for alert in alerts:
        hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
        host_name = _relation_label(hosts[0]) if hosts else "—"
        rows.append(
            f"""
            <tr>
              <td>{escape(_normalize_text(alert.get('name')) or '—')}</td>
              <td>{escape(_normalize_text(alert.get('severity')) or '—')}</td>
              <td>{escape(_normalize_text(host_name))}</td>
              <td>{escape(_normalize_text(alert.get('clock')) or '—')}</td>
            </tr>
            """
        )
    banner = ""
    if error_message:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(error_message)}</strong><div class='sub' style='margin: 6px 0 0;'>O Zabbix respondeu sem permissão suficiente para problem.get. O painel segue operando com o inventário e demais telas.</div></div>"
    elif info_message:
        banner = f"<div class='hero'><small>OK</small><strong>{escape(info_message)}</strong></div>"
    body = f"""
    {banner}
    <div class="panel">
      <h2>Alertas ativos</h2>
      <p>Atualiza automaticamente pelo Zabbix em carregamentos de página e via API.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin: 0 0 14px;">
        <form method="post" action="/alerts/email/send" style="margin:0;">
          <button class="btn primary" type="submit">Enviar e-mail de alertas</button>
        </form>
        <a class="btn" href="/settings">Configurar SMTP</a>
      </div>
      <table>
        <thead><tr><th>Problema</th><th>Severidade</th><th>Host</th><th>Clock</th></tr></thead>
        <tbody id="alerts-body">{''.join(rows) if rows else _render_table_empty('Nenhum alerta aberto no momento.', 4)}</tbody>
      </table>
    </div>
    <script>
      function escapeHtml(value) {{
        return String(value ?? '')
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }}
      function severityValue(value) {{
        const text = String(value ?? '').trim().toLowerCase();
        const numeric = Number.parseInt(text, 10);
        if (!Number.isNaN(numeric)) {{
          return numeric;
        }}
        const mapping = {{
          'not classified': 0,
          'sem classe': 0,
          'information': 1,
          'informacao': 1,
          'info': 1,
          'warning': 2,
          'aviso': 2,
          'average': 3,
          'media': 3,
          'high': 4,
          'alta': 4,
          'disaster': 5,
          'desastre': 5,
        }};
        return mapping[text] ?? -1;
      }}
      function alertSignature(alerts) {{
        return (alerts || [])
          .map((alert) => `${{alert.name || ''}}|${{alert.clock || ''}}|${{alert.severity || ''}}`)
          .join('||');
      }}
      function playAlertSound() {{
        try {{
          const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
          if (!AudioContextCtor) {{
            return;
          }}
          const context = new AudioContextCtor();
          const oscillator = context.createOscillator();
          const gain = context.createGain();
          oscillator.type = 'sine';
          oscillator.frequency.value = 880;
          gain.gain.value = 0.0001;
          oscillator.connect(gain);
          gain.connect(context.destination);
          oscillator.start();
          const now = context.currentTime;
          gain.gain.exponentialRampToValueAtTime(0.2, now + 0.02);
          gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.45);
          oscillator.stop(now + 0.5);
          oscillator.onended = () => context.close();
        }} catch (error) {{}}
      }}
      const soundEnabled = {str(bool(sound.get("enabled"))).lower()};
      const soundMinSeverity = {int(sound.get("min_severity", 4))};
      let lastSoundSignature = '';
      async function refreshAlerts() {{
        try {{
          const response = await fetch('/api/alerts');
          const data = await response.json();
          const alerts = data.alerts || [];
          const rows = alerts.map((alert) => {{
            const host = (alert.hosts && alert.hosts[0] && (alert.hosts[0].name || alert.hosts[0].host || alert.hosts[0].hostid)) || '????????';
            return `<tr><td>${{escapeHtml(alert.name || '????????')}}</td><td>${{escapeHtml(alert.severity || '????????')}}</td><td>${{escapeHtml(host)}}</td><td>${{escapeHtml(alert.clock || '????????')}}</td></tr>`;
          }}).join('');
          document.getElementById('alerts-body').innerHTML = rows || '<tr><td colspan="4">Nenhum alerta aberto no momento.</td></tr>';
          if (soundEnabled) {{
            const severeAlerts = alerts.filter((alert) => severityValue(alert.severity) >= soundMinSeverity);
            const signature = alertSignature(severeAlerts);
            if (signature && signature !== lastSoundSignature) {{
              playAlertSound();
              lastSoundSignature = signature;
            }} else if (!signature) {{
              lastSoundSignature = '';
            }}
          }}
        }} catch (error) {{}}
      }}
      const refreshSeconds = Math.max(5, {int(refresh_seconds)});
      setInterval(refreshAlerts, refreshSeconds * 1000);
      refreshAlerts();
    </script>

    """
    return _render_management_page(
        title="Alertas | infra-sync-api",
        active="alerts",
        heading="Alertas em tempo real",
        subtitle="Problemas e eventos abertos no Zabbix.",
        actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/reports">Imprimir relatório</a>',
        body=body,
    )


def _render_cpd_page(snapshot: dict[str, Any]) -> str:
    config = snapshot.get("cpd_dashboard") if isinstance(snapshot.get("cpd_dashboard"), dict) else _default_cpd_dashboard_config()
    groups = snapshot.get("cpd_groups") if isinstance(snapshot.get("cpd_groups"), dict) else {}
    devices = groups.get("devices") if isinstance(groups.get("devices"), list) else []
    services = groups.get("services") if isinstance(groups.get("services"), list) else []
    links = groups.get("links") if isinstance(groups.get("links"), list) else []
    recent_alerts = snapshot.get("alerts") if isinstance(snapshot.get("alerts"), list) else []

    def render_group_rows(entries: list[dict[str, Any]], empty_message: str) -> str:
        if not entries:
            return f"<tr><td colspan='4'>{escape(empty_message)}</td></tr>"
        rows = []
        for item in entries:
            rows.append(
                f"""
                <tr>
                  <td><strong>{escape(_normalize_text(item.get('name')))}</strong></td>
                  <td><span class="pill {escape(_normalize_text(item.get('pill')) or 'warn')}">{escape(_normalize_text(item.get('status')))}</span></td>
                  <td>{escape(_normalize_text(item.get('alert')) or '—')}</td>
                  <td>{escape(_normalize_text(item.get('clock')) or '—')}</td>
                </tr>
                """
            )
        return "".join(rows)

    def render_alert_rows(entries: list[dict[str, Any]]) -> str:
        if not entries:
            return "<tr><td colspan='4'>Nenhum alerta aberto no momento.</td></tr>"
        rows = []
        for alert in entries[:10]:
            hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
            host_name = _relation_label(hosts[0]) if hosts else "—"
            rows.append(
                f"""
                <tr>
                  <td>{escape(_normalize_text(alert.get('name')) or '—')}</td>
                  <td>{escape(_normalize_text(alert.get('severity')) or '—')}</td>
                  <td>{escape(_normalize_text(host_name))}</td>
                  <td>{escape(_normalize_text(alert.get('clock')) or '—')}</td>
                </tr>
                """
            )
        return "".join(rows)

    snapshot_json = json.dumps(snapshot, ensure_ascii=False).replace("</", "<\\/")
    body = f"""
    <div class="cpd-shell">
      <section class="cpd-hero">
        <div>
          <div class="cpd-kicker">CPD / Painel de operacao</div>
          <h1 id="cpd-title">{escape(_normalize_text(config.get("title")) or "CPD - Painel de saude")}</h1>
          <p id="cpd-summary">Tela fixa para acompanhar servidores, roteadores, switches, links, servicos e alertas criticos sem alternar entre sistemas.</p>
        </div>
        <div class="cpd-actions">
          <a class="cpd-btn" href="/settings">Configurar CPD</a>
          <a class="cpd-btn" href="/alerts">Alertas</a>
          <a class="cpd-btn" href="/reports">Relatorios</a>
        </div>
      </section>

      <section class="cpd-metrics">
        <article class="cpd-card">
          <div class="cpd-label">Atualizacao</div>
          <div class="cpd-value" id="cpd-updated">{escape(snapshot.get("cpd_updated_at", ""))}</div>
          <div class="cpd-note">Recarrega a cada 2 segundos sem derrubar a tela.</div>
        </article>
        <article class="cpd-card">
          <div class="cpd-label">Saude geral</div>
          <div class="cpd-value" id="cpd-health">{escape(_normalize_text(snapshot.get("health")) or "—")}</div>
          <div class="cpd-note" id="cpd-headline">{escape(_normalize_text(snapshot.get("headline")) or "—")}</div>
        </article>
        <article class="cpd-card">
          <div class="cpd-label">Telemetria</div>
          <div class="cpd-value" id="cpd-telemetry">{escape(str(snapshot.get("telemetry_score", 0)))}</div>
          <div class="cpd-note">NetBox, Zabbix, GLPI e n8n.</div>
        </article>
        <article class="cpd-card">
          <div class="cpd-label">Alertas</div>
          <div class="cpd-value" id="cpd-alerts-count">{escape(str(len(recent_alerts)))}</div>
          <div class="cpd-note">Problemas ativos no Zabbix.</div>
        </article>
      </section>

      <section class="cpd-grid">
        <article class="cpd-panel">
          <h2>Dispositivos criticos</h2>
          <p>Servidores, roteadores e switches monitorados com base nos eventos e na conectividade.</p>
          <table>
            <thead><tr><th>Nome</th><th>Status</th><th>Ultimo alerta</th><th>Horario</th></tr></thead>
            <tbody id="cpd-devices">{render_group_rows(devices, "Nenhum device critico configurado.")}</tbody>
          </table>
        </article>
        <article class="cpd-panel">
          <h2>Links e servicos</h2>
          <p>Visao operacional dos troncos, uplinks e servicos essenciais da rede.</p>
          <table>
            <thead><tr><th>Nome</th><th>Status</th><th>Ultimo alerta</th><th>Horario</th></tr></thead>
            <tbody id="cpd-links">{render_group_rows(links, "Nenhum link critico configurado.")}{render_group_rows(services, "Nenhum servico critico configurado.")}</tbody>
          </table>
        </article>
      </section>

      <section class="cpd-grid cpd-grid-bottom">
        <article class="cpd-panel">
          <h2>Alertas recentes</h2>
          <p>Os eventos mais importantes entram nesta lista enquanto a tela permanece aberta.</p>
          <table>
            <thead><tr><th>Problema</th><th>Severidade</th><th>Host</th><th>Horario</th></tr></thead>
            <tbody id="cpd-alerts">{render_alert_rows(recent_alerts)}</tbody>
          </table>
        </article>
        <article class="cpd-panel">
          <h2>Criticos configurados</h2>
          <p>Base de referencia usada para destacar os elementos mais sensiveis do ambiente.</p>
          <div class="cpd-tags">
            <span class="cpd-tag">Dispositivos: {escape(", ".join(_split_dashboard_entries(config.get("critical_devices"))) or "nenhum")}</span>
            <span class="cpd-tag">Links: {escape(", ".join(_split_dashboard_entries(config.get("critical_links"))) or "nenhum")}</span>
            <span class="cpd-tag">Servicos: {escape(", ".join(_split_dashboard_entries(config.get("critical_services"))) or "nenhum")}</span>
            <span class="cpd-tag">Severidade destaque: {escape(str(config.get("highlight_severity", 4)))}</span>
          </div>
          <div class="cpd-footnote">A tela nao possui logout automatico e foi pensada para TV/monitor do CPD.</div>
        </article>
      </section>
    </div>

    <style>
      :root {{
        color-scheme: dark;
      }}
      body {{
        margin: 0;
        background: #070707;
        color: #f4f4f5;
        font-family: Inter, Segoe UI, Arial, sans-serif;
      }}
      .cpd-shell {{
        min-height: 100vh;
        padding: 22px;
        background:
          linear-gradient(180deg, rgba(185,28,28,.16), rgba(0,0,0,0) 240px),
          radial-gradient(circle at top left, rgba(185,28,28,.16), transparent 36%),
          #070707;
      }}
      .cpd-hero {{
        display: flex;
        justify-content: space-between;
        gap: 18px;
        align-items: flex-start;
        margin-bottom: 18px;
      }}
      .cpd-kicker {{
        text-transform: uppercase;
        font-size: 12px;
        letter-spacing: .08em;
        color: #fca5a5;
        font-weight: 800;
      }}
      #cpd-title {{
        margin: 6px 0 0;
        font-size: 34px;
        line-height: 1.05;
      }}
      #cpd-summary {{
        margin: 10px 0 0;
        max-width: 980px;
        color: #d6d3d1;
        line-height: 1.45;
      }}
      .cpd-actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: flex-end;
      }}
      .cpd-btn {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 42px;
        padding: 10px 14px;
        border-radius: 10px;
        background: #111111;
        border: 1px solid rgba(255,255,255,.1);
        color: #fff;
        text-decoration: none;
        font-weight: 700;
      }}
      .cpd-metrics {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
        margin-bottom: 18px;
      }}
      .cpd-card, .cpd-panel {{
        background: rgba(15, 15, 15, .94);
        border: 1px solid rgba(255,255,255,.08);
        border-radius: 14px;
        box-shadow: 0 16px 32px rgba(0,0,0,.34);
      }}
      .cpd-card {{
        padding: 16px;
        border-top: 4px solid #b91c1c;
      }}
      .cpd-label {{
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: .08em;
        font-size: 11px;
        font-weight: 800;
      }}
      .cpd-value {{
        margin-top: 10px;
        font-size: 30px;
        font-weight: 900;
      }}
      .cpd-note {{
        margin-top: 8px;
        color: #d4d4d8;
        line-height: 1.35;
      }}
      .cpd-grid {{
        display: grid;
        grid-template-columns: 1.25fr .95fr;
        gap: 14px;
        margin-bottom: 14px;
      }}
      .cpd-panel {{
        padding: 18px;
      }}
      .cpd-panel h2 {{
        margin: 0 0 8px;
        font-size: 18px;
      }}
      .cpd-panel p {{
        margin: 0 0 14px;
        color: #a1a1aa;
        line-height: 1.45;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
      }}
      th, td {{
        text-align: left;
        padding: 11px 10px;
        border-bottom: 1px solid rgba(255,255,255,.08);
        font-size: 14px;
        vertical-align: top;
      }}
      th {{
        color: #a1a1aa;
        text-transform: uppercase;
        letter-spacing: .06em;
        font-size: 12px;
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 12px;
        font-weight: 800;
      }}
      .ok {{ background: rgba(34,197,94,.18); color: #86efac; }}
      .warn {{ background: rgba(250,204,21,.16); color: #fde68a; }}
      .bad {{ background: rgba(239,68,68,.18); color: #fca5a5; }}
      .muted {{ background: rgba(255,255,255,.06); color: #d4d4d8; }}
      .cpd-tags {{
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }}
      .cpd-tag {{
        display: inline-flex;
        padding: 10px 12px;
        border-radius: 10px;
        background: rgba(255,255,255,.05);
        border: 1px solid rgba(255,255,255,.08);
        color: #f4f4f5;
        line-height: 1.3;
      }}
      .cpd-footnote {{
        margin-top: 14px;
        color: #a1a1aa;
      }}
      @media (max-width: 1120px) {{
        .cpd-metrics, .cpd-grid {{
          grid-template-columns: 1fr 1fr;
        }}
      }}
      @media (max-width: 760px) {{
        .cpd-hero, .cpd-grid, .cpd-metrics {{
          grid-template-columns: 1fr;
          display: grid;
        }}
        .cpd-actions {{
          justify-content: flex-start;
        }}
      }}
    </style>

    <script>
      const cpdSnapshot = {snapshot_json};
      function escapeHtml(value) {{
        return String(value ?? '')
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }}
      function renderRows(items) {{
        if (!items || !items.length) {{
          return '<tr><td colspan="4">Nenhum item configurado.</td></tr>';
        }}
        return items.map((item) => `
          <tr>
            <td><strong>${{escapeHtml(item.name || '—')}}</strong></td>
            <td><span class="pill ${{escapeHtml(item.pill || 'warn')}}">${{escapeHtml(item.status || '—')}}</span></td>
            <td>${{escapeHtml(item.alert || '—')}}</td>
            <td>${{escapeHtml(item.clock || '—')}}</td>
          </tr>
        `).join('');
      }}
      async function refreshCpd() {{
        try {{
          const response = await fetch('/api/cpd', {{ cache: 'no-store' }});
          const data = await response.json();
          const groups = data.cpd_groups || {{}};
          document.getElementById('cpd-title').textContent = data.cpd_dashboard?.title || 'CPD - Painel de saude';
          document.getElementById('cpd-updated').textContent = data.cpd_updated_at || '—';
          document.getElementById('cpd-health').textContent = data.health || '—';
          document.getElementById('cpd-headline').textContent = data.headline || '—';
          document.getElementById('cpd-telemetry').textContent = String(data.telemetry_score ?? 0);
          document.getElementById('cpd-alerts-count').textContent = String((data.alerts || []).length);
          document.getElementById('cpd-devices').innerHTML = renderRows(groups.devices || []);
          document.getElementById('cpd-links').innerHTML = renderRows([...(groups.links || []), ...(groups.services || [])]);
          document.getElementById('cpd-alerts').innerHTML = renderRows((data.alerts || []).slice(0, 10).map((alert) => {{
            const host = (alert.hosts && alert.hosts[0] && (alert.hosts[0].name || alert.hosts[0].host || alert.hosts[0].hostid)) || '—';
            return {{
              name: alert.name || '—',
              status: alert.severity || '—',
              pill: 'warn',
              alert: host,
              clock: alert.clock || '—',
            }};
          }}));
        }} catch (error) {{
          console.error('CPD refresh failed', error);
        }}
      }}
      refreshCpd();
      setInterval(refreshCpd, 2000);
    </script>
    """
    return _render_shell(f"{_normalize_text(config.get('title')) or 'CPD - Painel de saude'} | infra-sync-api", body)


@app.get("/snmp", include_in_schema=False)
async def snmp_page(request: Request, saved: int = 0, error: str | None = None):
    state = load_last_probe()
    return HTMLResponse(_render_snmp_page(state, saved=bool(saved), error=error))


@app.post("/snmp/probe", include_in_schema=False)
async def snmp_probe_page(request: Request):
    form = await _read_form(request)
    ip = _form_value(form, "ip")
    community = _form_value(form, "community", "public") or "public"
    timeout = float(_form_value(form, "timeout", "1.0") or "1.0")
    retries = int(_form_value(form, "retries", "0") or "0")
    max_ports = int(_form_value(form, "max_ports", "48") or "48")
    try:
        await probe_snmp_device(ip, community, timeout=timeout, retries=retries, max_ports=max_ports)
        return HTMLResponse(_render_snmp_page(load_last_probe(), saved=True))
    except Exception as exc:
        return HTMLResponse(_render_snmp_page(load_last_probe(), error=str(exc)), status_code=status.HTTP_400_BAD_REQUEST)


@app.post("/snmp/sync", include_in_schema=False)
async def snmp_sync_page(request: Request):
    form = await _read_form(request)
    ip = _form_value(form, "ip")
    community = _form_value(form, "community", "public") or "public"
    timeout = float(_form_value(form, "timeout", "1.0") or "1.0")
    retries = int(_form_value(form, "retries", "0") or "0")
    max_ports = int(_form_value(form, "max_ports", "48") or "48")
    settings: Settings = request.app.state.settings
    client: NetBoxClient = request.app.state.netbox_client
    try:
        snapshot = await probe_snmp_device(ip, community, timeout=timeout, retries=retries, max_ports=max_ports)
        profile = infer_device_profile(
            sys_descr=_normalize_text(snapshot.get("sys_descr")),
            sys_name=_normalize_text(snapshot.get("sys_name")) or _normalize_text(snapshot.get("ip")) or ip,
            sys_object_id=_normalize_text(snapshot.get("sys_object_id")),
        )
        role_id = _discovery_role_id_for_group(profile["group"], settings)
        payload = SyncDeviceRequest(
            hostid=_normalize_text(snapshot.get("ip")) or ip,
            hostname=_normalize_text(snapshot.get("sys_name")) or _normalize_text(snapshot.get("ip")) or ip,
            display_name=_normalize_text(snapshot.get("sys_name")) or _normalize_text(snapshot.get("ip")) or ip,
            ip=_normalize_text(snapshot.get("ip")) or ip,
            fabricante=profile["manufacturer"],
            modelo=profile["model"] or profile["device_type"] or "Generico",
            site_id=settings.default_site_id,
            role_id=role_id or settings.default_role_id,
            mac_address=next(
                (_normalize_mac_text(port.get("mac_address")) for port in snapshot.get("ports", []) if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))),
                None,
            ),
            comments_summary=_normalize_text(snapshot.get("notes")) or "Leitura SNMP sincronizada com sucesso.",
            netbox_status="active",
            ports=snapshot.get("ports") if isinstance(snapshot.get("ports"), list) else None,
        )
        result = await sync_device(payload, client, settings.default_site_id, dry_run=False)
        return HTMLResponse(_render_snmp_page(load_last_probe(), saved=True))
    except Exception as exc:
        return HTMLResponse(_render_snmp_page(load_last_probe(), error=str(exc)), status_code=status.HTTP_400_BAD_REQUEST)


def _render_snmp_page(state: dict[str, Any], saved: bool = False, error: str | None = None) -> str:
    last_probe = state.get("last_probe") if isinstance(state.get("last_probe"), dict) else None
    ports = last_probe.get("ports") if last_probe and isinstance(last_probe.get("ports"), list) else []
    active_ports = len([port for port in ports if isinstance(port, dict) and _normalize_text(port.get("oper_status")).lower() == "up"])
    down_ports = len([port for port in ports if isinstance(port, dict) and _normalize_text(port.get("oper_status")).lower() == "down"])
    ports_with_mac = len([port for port in ports if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))])
    first_mac = next((_normalize_mac_text(port.get("mac_address")) for port in ports if isinstance(port, dict) and _normalize_mac_text(port.get("mac_address"))), "—")
    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Leitura SNMP atualizada com sucesso.</strong></div>"
    if error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(error)}</strong></div>"
    summary = ""
    if last_probe:
        summary = f"""
        <div class="metrics">
          <article class="metric-card"><div class="metric-label">SysName</div><div class="metric-value" style="font-size:22px">{escape(_normalize_text(last_probe.get("sys_name")) or '—')}</div><div class="metric-note">{escape(_normalize_text(last_probe.get("sys_descr")) or 'Sem descrição')}</div></article>
          <article class="metric-card"><div class="metric-label">Interfaces</div><div class="metric-value">{escape(_normalize_text(last_probe.get("if_number")) or '—')}</div><div class="metric-note">Portas/links vistos pelo SNMP.</div></article>
          <article class="metric-card"><div class="metric-label">Memória</div><div class="metric-value">{escape(_normalize_text(last_probe.get("hr_memory_size")) or '—')}</div><div class="metric-note">Total reportado pelo agente.</div></article>
          <article class="metric-card"><div class="metric-label">CPU média</div><div class="metric-value">{escape(_normalize_text(last_probe.get("processor_load_average")) or '—')}</div><div class="metric-note">Média dos processadores coletados.</div></article>
          <article class="metric-card"><div class="metric-label">MAC</div><div class="metric-value" style="font-size:22px">{escape(first_mac)}</div><div class="metric-note">{ports_with_mac} interface(s) com endereço físico.</div></article>
          <article class="metric-card"><div class="metric-label">Portas ativas</div><div class="metric-value">{active_ports}</div><div class="metric-note">{down_ports} portas inativas ou down.</div></article>
        </div>
        """
    rows = []
    for port in ports:
        if not isinstance(port, dict):
            continue
        rows.append(
            f"""
            <tr>
              <td>{escape(_normalize_text(port.get('index')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('name')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('description')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('alias')) or '—')}</td>
              <td>{_render_port_status_badge(_normalize_text(port.get('admin_status')) or '—')}</td>
              <td>{_render_port_status_badge(_normalize_text(port.get('oper_status')) or '—')}</td>
              <td>{escape(_normalize_mac_text(port.get('mac_address')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('speed_bps')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('in_octets')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('out_octets')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('in_rate_bps')) or '—')}</td>
              <td>{escape(_normalize_text(port.get('out_rate_bps')) or '—')}</td>
            </tr>
            """
        )
    body = f"""
    {banner}
    <div class="panel" style="margin-bottom:14px;">
      <h2>Consulta SNMP</h2>
      <p>Informe o IP privado do switch ou servidor e a community para coletar portas, CPU, memória e tráfego.</p>
      <form method="post" action="/snmp/probe">
        <div class="form-grid">
          <div class="field"><label for="ip">IP</label><input id="ip" name="ip" type="text" value="{escape(_normalize_text(last_probe.get('ip')) if last_probe else '')}" placeholder="10.0.0.24" /></div>
          <div class="field"><label for="community">Community</label><input id="community" name="community" type="password" value="" placeholder="public" /></div>
          <div class="field"><label for="timeout">Timeout</label><input id="timeout" name="timeout" type="text" value="1.0" /></div>
          <div class="field"><label for="retries">Retries</label><input id="retries" name="retries" type="text" value="0" /></div>
          <div class="field"><label for="max_ports">Máximo de portas</label><input id="max_ports" name="max_ports" type="text" value="48" /></div>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Consultar SNMP</button>
          <button class="btn" type="submit" formaction="/snmp/sync">Salvar no NetBox</button>
          <a class="btn" href="/devices">Voltar aos devices</a>
        </div>
      </form>
    </div>
    {summary}
    <div class="panel" style="margin-top:14px;">
      <h2>Portas</h2>
      <p>Descrição, alias, status e contadores por interface.</p>
      <table>
        <thead>
          <tr>
            <th>Índice</th><th>Nome</th><th>Descrição</th><th>Alias</th><th>Admin</th><th>Oper</th><th>MAC</th><th>Speed</th><th>Entrada</th><th>Saída</th><th>Rate In</th><th>Rate Out</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) if rows else _render_table_empty('Nenhuma porta coletada ainda.', 12)}</tbody>
      </table>
    </div>
    """
    return _render_management_page(
        title="SNMP | infra-sync-api",
        active="snmp",
        heading="SNMP",
        subtitle="Leitura detalhada de portas, CPU, memória e tráfego por equipamento.",
        actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/devices">Devices</a>',
        body=body,
    )


def _render_reports_page(snapshot: dict[str, Any]) -> str:
    alerts = snapshot.get("alerts") if isinstance(snapshot.get("alerts"), list) else []
    alert_rows = []
    for alert in alerts[:10]:
        hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
        host_name = _relation_label(hosts[0]) if hosts else "—"
        alert_rows.append(
            f"<tr><td>{escape(_normalize_text(alert.get('name')) or '—')}</td><td>{escape(_normalize_text(host_name))}</td><td>{escape(_normalize_text(alert.get('severity')) or '—')}</td></tr>"
        )
    body = f"""
    <style>
      @media print {{
        .topbar, .actions, .sidebar, .foot a {{ display: none !important; }}
        .content {{ padding: 0; }}
        .panel {{ break-inside: avoid; }}
      }}
    </style>
    <div class="panel">
      <h2>Relatório executivo</h2>
      <p>Resumo operacional pronto para impressão ou PDF do navegador.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom: 14px;">
        <button class="btn primary" type="button" onclick="window.print()">Imprimir</button>
        <a class="btn" href="/alerts">Ver alertas</a>
        <a class="btn" href="/devices">Ver devices</a>
      </div>
      <table>
        <thead><tr><th>Métrica</th><th>Valor</th></tr></thead>
        <tbody>
          {''.join(f'<tr><td>{escape(card["label"])}</td><td>{escape(str(card["value"]))}</td></tr>' for card in snapshot["cards"])}
        </tbody>
      </table>
    </div>
    <div class="panel" style="margin-top:14px;">
      <h2>Alertas recentes</h2>
      <table>
        <thead><tr><th>Problema</th><th>Host</th><th>Severidade</th></tr></thead>
        <tbody>{''.join(alert_rows) if alert_rows else _render_table_empty('Nenhum alerta aberto.', 3)}</tbody>
      </table>
    </div>
    """
    return _render_management_page(
        title="Relatórios | infra-sync-api",
        active="reports",
        heading="Relatórios",
        subtitle="Resumo executivo para imprimir, salvar em PDF ou compartilhar.",
        actions='<button class="btn primary" type="button" onclick="window.print()">Imprimir</button><a class="btn" href="/">Dashboard</a>',
        body=body,
    )


async def _render_crud_error(request: Request, active: str, message: str) -> str:
    title_map = {"devices": "Devices", "vlans": "VLANs", "networks": "Redes"}
    return _render_management_page(
        title=f"{title_map.get(active, 'Operação')} | infra-sync-api",
        active=active,
        heading=title_map.get(active, "Operação"),
        subtitle="Houve um problema ao salvar os dados.",
        actions='<a class="btn" href="/">Dashboard</a>',
        body=f"<div class='hero'><small>Erro</small><strong>{escape(message)}</strong></div>",
    )

