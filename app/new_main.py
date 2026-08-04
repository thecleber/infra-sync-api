from __future__ import annotations

import copy
import asyncio
import hmac
import ipaddress
import json
import logging
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
from .discovery import classify_discovered_device, load_last_scan, save_group_selections, scan_network
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
        return "nÃƒÆ’Ã‚Â£o configurado"
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
    client = request.client
    client_host = getattr(client, "host", None)

    if settings is not None and client_host:
        try:
            client_ip = ipaddress.ip_address(client_host)
        except ValueError:
            client_ip = None
        if client_ip is not None:
            allowed = any(client_ip in network for network in settings.allowed_client_networks())
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
        ("netbox", "NetBox", "InventÃƒÆ’Ã‚Â¡rio, IPAM e documentaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o"),
        ("zabbix", "Zabbix", "Telemetria, eventos e SNMP"),
        ("glpi", "GLPI", "Chamados e histÃƒÆ’Ã‚Â³rico operacional"),
        ("n8n", "n8n", "AutomaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o segura e ajustes pequenos"),
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
            "url": _normalize_text(connector.get("url")) or "nÃƒÆ’Ã‚Â£o informado",
            "token": _mask_secret(_normalize_text(connector.get("token"))),
            "note": note,
        })

    health_status = "ok" if netbox_connected and (zabbix_client is None or zabbix_connected) else "degraded"
    headline = "Sistema central pronto" if health_status == "ok" else "Sistema central parcialmente indisponÃƒÆ’Ã‚Â­vel"
    detail = (
        f"NetBox {'online' if netbox_connected else 'offline'}"
        + (
            f", Zabbix {'online' if zabbix_connected else 'offline'}"
            if zabbix_client is not None
            else ", Zabbix nÃƒÆ’Ã‚Â£o configurado"
        )
        + f". Redes permitidas: {len(settings.allowed_client_networks())}."
    )

    inventory_cards = [
        {"label": "Devices", "value": counts["devices"], "note": "Dispositivos no inventÃƒÆ’Ã‚Â¡rio"},
        {"label": "IPs", "value": counts["ips"], "note": "EndereÃƒÆ’Ã‚Â§os e consumo"},
        {"label": "VLANs", "value": counts["vlans"], "note": "SegmentaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o de rede"},
        {"label": "Interfaces", "value": counts["interfaces"], "note": "Portas, uplinks e trunks"},
        {"label": "Prefixes", "value": counts["prefixes"], "note": "Blocos e pools"},
        {"label": "Sites", "value": counts["sites"], "note": "Locais e unidades"},
        {"label": "Racks", "value": counts["racks"], "note": "Racks fÃƒÆ’Ã‚Â­sicos"},
        {"label": "Zabbix hosts", "value": counts["zabbix_hosts"], "note": "Hosts monitorados"},
        {"label": "Alertas", "value": counts["zabbix_problems"], "note": "Problemas abertos no Zabbix"},
        {"label": "Descobertos", "value": discovery_count, "note": "Dispositivos vistos na ÃƒÆ’Ã‚Âºltima varredura"},
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
            <div class="sub">Painel central para NetBox, Zabbix, GLPI e n8n. A visÃƒÆ’Ã‚Â£o principal do ambiente fica aqui, com inventÃƒÆ’Ã‚Â¡rio, telemetria e automaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o reunidos em um sÃƒÆ’Ã‚Â³ lugar.</div>
          </div>
          <div class="actions">
            <a class="btn primary" href="/settings">Configurar integraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes</a>
            <a class="btn" href="/docs">API</a>
            <a class="btn" href="/health">SaÃƒÆ’Ã‚Âºde</a>
            <a class="btn" href="/version">VersÃƒÆ’Ã‚Â£o</a>
          </div>
        </section>
        <section class="hero">
          <small>ÃƒÆ’Ã…Â¡ltima checagem</small>
          <strong>{escape(snapshot["headline"])}</strong>
          <div class="sub" style="margin: 6px 0 0;">{escape(snapshot["detail"])}</div>
        </section>
        <section class="grid">{cards_markup}</section>
        <section class="panels">
          <div class="panel">
            <h2>Conectores centrais</h2>
            <p>Os tokens e URLs ficam editÃƒÆ’Ã‚Â¡veis no prÃƒÆ’Ã‚Â³prio sistema. Assim vocÃƒÆ’Ã‚Âª consegue ligar ou trocar a origem sem sair do painel.</p>
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
            <p>Rotas e aÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes principais para a operaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o do dia a dia.</p>
            <table>
              <thead>
                <tr>
                  <th>AÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o</th>
                  <th>Destino</th>
                </tr>
              </thead>
              <tbody>
                <tr><td>SaÃƒÆ’Ã‚Âºde da API</td><td><a href="/health">/health</a></td></tr>
                <tr><td>DocumentaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o</td><td><a href="/docs">/docs</a></td></tr>
                <tr><td>Editar integraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes</td><td><a href="/settings">/settings</a></td></tr>
                <tr><td>VersÃƒÆ’Ã‚Â£o</td><td><a href="/version">/version</a></td></tr>
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
        "ConfiguraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes | infra-sync-api",
        f"""
        <section class="topbar">
          <div>
            <h1>ConfiguraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes</h1>
            <div class="sub">Aqui vocÃƒÆ’Ã‚Âª insere e altera os tokens e URLs que alimentam o sistema central. A atualizaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o vale na hora para o painel e para os conectores.</div>
          </div>
          <div class="actions">
            <a class="btn" href="/">Dashboard</a>
            <a class="btn" href="/docs">API</a>
          </div>
        </section>
        {"<div class='hero'><small>Salvo</small><strong>ConfiguraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes atualizadas com sucesso.</strong><div class='sub' style='margin: 6px 0 0;'>As conexÃƒÆ’Ã‚Âµes foram recarregadas sem sair do sistema.</div></div>" if saved else ""}
        <form method="post" action="/settings">
          <div class="panel" style="margin-bottom:14px;">
            <h2>Chave de sincronizaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o</h2>
            <p>Essa chave protege os endpoints de sync. Se vocÃƒÆ’Ã‚Âª trocar aqui, os processos que usam API key precisam ser atualizados tambÃƒÆ’Ã‚Â©m.</p>
            <div class="form-grid">
              <div class="field">
                <label for="sync_api_key">SYNC API key</label>
                <input id="sync_api_key" name="sync_api_key" type="password" value="" placeholder="Deixe em branco para manter a atual" />
                <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(runtime["sync_api_key"])))}</div>
              </div>
            </div>
          </div>
          <div class="form-grid">
            {connector_block("netbox", "NetBox", "InventÃƒÆ’Ã‚Â¡rio, IPAM, VLANs, racks e dispositivos.", "https://netbox.example.local")}
            {connector_block("zabbix", "Zabbix", "Telemetria, eventos e SNMP.", "https://zabbix.example.local/zabbix/api_jsonrpc.php")}
            {connector_block("glpi", "GLPI", "Chamados e histÃƒÆ’Ã‚Â³rico de atendimento.", "https://glpi.example.local/apirest.php")}
            {connector_block("n8n", "n8n", "AutomaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o e pequenas correÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes controladas.", "https://n8n.example.local")}
          </div>
          <div style="display:flex; gap:10px; margin-top:16px; flex-wrap:wrap;">
            <button class="btn primary" type="submit">Salvar configuraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes</button>
            <a class="btn" href="/">Voltar ao dashboard</a>
          </div>
        </form>
        <div class="foot">
          <div>Os valores vazios mantÃƒÆ’Ã‚Âªm o que jÃƒÆ’Ã‚Â¡ estÃƒÆ’Ã‚Â¡ salvo.</div>
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
            <a class="btn primary" href="/settings">Configurar integraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes</a>
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
            <p>Cadastro e ediÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o de equipamentos do inventÃƒÆ’Ã‚Â¡rio central.</p>
            <table>
              <thead><tr><th>AÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o</th><th>Destino</th></tr></thead>
              <tbody>
                <tr><td>Listar devices</td><td><a href="/devices">/devices</a></td></tr>
                <tr><td>Imprimir relatÃƒÆ’Ã‚Â³rio</td><td><a href="/reports">/reports</a></td></tr>
              </tbody>
            </table>
          </div>
          <div class="panel">
            <h2>Resumo</h2>
            <p>Dados atuais do inventÃƒÆ’Ã‚Â¡rio para apoiar a operaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o.</p>
            <table>
              <thead><tr><th>MÃƒÆ’Ã‚Â©trica</th><th>Valor</th></tr></thead>
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
            <p>CriaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o e ediÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o de VLANs com acesso direto ao NetBox.</p>
            <a class="btn primary" href="/vlans">Abrir VLANs</a>
          </div>
          <div class="panel">
            <h2>Consumo</h2>
            <p>VisÃƒÆ’Ã‚Â£o rÃƒÆ’Ã‚Â¡pida da segmentaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o de rede.</p>
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
            <p>Consumo do espaÃƒÆ’Ã‚Â§o de endereÃƒÆ’Ã‚Â§amento do ambiente.</p>
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
                    f'<tr><td>{escape(_normalize_text(alert.get("name")) or "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â")}</td><td>{escape(_relation_label((alert.get("hosts") or [{}])[0]) if isinstance(alert.get("hosts"), list) and alert.get("hosts") else "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â")}</td></tr>'
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
            <h2>RelatÃƒÆ’Ã‚Â³rios</h2>
            <p>Resumo pronto para impressÃƒÆ’Ã‚Â£o ou exportaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o via navegador.</p>
            <div style="display:flex; gap:10px; flex-wrap:wrap;">
              <a class="btn primary" href="/reports">Abrir relatÃƒÆ’Ã‚Â³rio</a>
              <button class="btn" type="button" onclick="window.print()">Imprimir pÃƒÆ’Ã‚Â¡gina</button>
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
          <p>Essa chave protege os endpoints de sync. Se voce trocar aqui, os automations e integraÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes que usam API key precisam receber o novo valor.</p>
          <div class="form-grid">
            <div class="field">
              <label for="sync_api_key">SYNC API key</label>
              <input id="sync_api_key" name="sync_api_key" type="password" value="" placeholder="Deixe em branco para manter a atual" />
              <div class="sub" style="margin:6px 0 0;">Atual: {escape(_mask_secret(_normalize_text(runtime["sync_api_key"])))}</div>
            </div>
          </div>
        </div>
        <div class="panel" style="margin-bottom:14px;">
          <h2>AtualizaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o automÃƒÆ’Ã‚Â¡tica</h2>
          <p>Escolha de quanto em quanto tempo o painel deve recarregar os dados vindos dos devices e dos conectores integrados.</p>
          <div class="form-grid">
            <div class="field">
              <label for="refresh_enabled">Habilitar atualizaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o automÃƒÆ’Ã‚Â¡tica</label>
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
    return HTMLResponse(_render_discovery_page(state, error=error, saved=bool(saved)))


@app.post("/discovery/scan", include_in_schema=False)
async def discovery_scan(request: Request):
    form = await _read_form(request)
    network = form.get("network", "10.0.0.0/24").strip()
    community = form.get("community", "public").strip() or "public"
    timeout = float(form.get("timeout", "1.0") or "1.0")
    retries = int(form.get("retries", "0") or "0")
    max_hosts = int(form.get("max_hosts", "1024") or "1024")
    try:
        payload = await scan_network(network, community, timeout=timeout, retries=retries, max_hosts=max_hosts)
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
    saved_devices: list[dict[str, Any]] = []

    for device in devices:
        if not isinstance(device, dict):
            continue
        ip = str(device.get("ip", "")).strip()
        key = _device_key(ip)
        include = form.get(f"include_{key}") in {"on", "true", "True", "1", "checked", "yes"}
        group = form.get(f"group_{key}") or str(device.get("group") or "hosts")
        subgroup = form.get(f"subgroup_{key}") or str(device.get("subgroup") or "fixed")
        classified_group, classified_subgroup, notes = classify_discovered_device(
            sys_descr=str(device.get("sys_descr") or ""),
            sys_name=str(device.get("sys_name") or ""),
            sys_object_id=str(device.get("sys_object_id") or ""),
        )
        saved_devices.append(
            {
                **device,
                "include": include,
                "group": group,
                "subgroup": subgroup,
                "suggested_group": classified_group,
                "suggested_subgroup": classified_subgroup,
                "notes": notes,
            }
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
        ("servers", "Servidores", ["hypervisor", "physical"]),
        ("hosts", "Hosts", ["mobile", "notebook", "tablet", "desktop", "fixed"]),
    ]


def _render_discovery_page(state: dict[str, Any], error: str | None = None, saved: bool = False) -> str:
    devices = state.get("devices") if isinstance(state.get("devices"), list) else []
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
              <td>{escape(str(device.get("sys_name") or '?'))}</td>
              <td>{escape(str(device.get("manufacturer") or '?'))}</td>
              <td>{escape(str(device.get("model") or '?'))}</td>
              <td>{escape(str(device.get("device_type") or '?'))}</td>
              <td style="max-width:280px;">{escape(str(device.get("sys_descr") or '?'))}</td>
              <td>
                <select name="group_{key}">
                  <option value="routers" {"selected" if device.get("group") == "routers" else ""}>Roteadores</option>
                  <option value="switches" {"selected" if device.get("group") == "switches" else ""}>Switches</option>
                  <option value="servers" {"selected" if device.get("group") == "servers" else ""}>Servidores</option>
                  <option value="hosts" {"selected" if device.get("group") == "hosts" else ""}>Hosts</option>
                </select>
              </td>
              <td>
                <select name="subgroup_{key}">
                  <option value="core" {"selected" if device.get("subgroup") == "core" else ""}>core</option>
                  <option value="access" {"selected" if device.get("subgroup") == "access" else ""}>access</option>
                  <option value="wireless" {"selected" if device.get("subgroup") == "wireless" else ""}>wireless</option>
                  <option value="hypervisor" {"selected" if device.get("subgroup") == "hypervisor" else ""}>hypervisor</option>
                  <option value="physical" {"selected" if device.get("subgroup") == "physical" else ""}>physical</option>
                  <option value="mobile" {"selected" if device.get("subgroup") == "mobile" else ""}>mobile</option>
                  <option value="notebook" {"selected" if device.get("subgroup") == "notebook" else ""}>notebook</option>
                  <option value="tablet" {"selected" if device.get("subgroup") == "tablet" else ""}>tablet</option>
                  <option value="desktop" {"selected" if device.get("subgroup") == "desktop" else ""}>desktop</option>
                  <option value="fixed" {"selected" if device.get("subgroup") == "fixed" else ""}>fixed</option>
                </select>
              </td>
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
      <div class="panel" style="margin-bottom:14px;">
        <h2>Executar varredura</h2>
        <p>Use uma rede privada como 10.0.0.0/24. O sistema consulta SNMP e monta uma lista de dispositivos com sugestao de grupo.</p>
        <form method="post" action="/discovery/scan">
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
            <div class="field">
              <label for="max_hosts">Limite de hosts</label>
              <input id="max_hosts" name="max_hosts" type="text" value="1024" />
            </div>
          </div>
          <div style="display:flex; gap:10px; margin-top:14px; flex-wrap:wrap;">
            <button class="btn primary" type="submit">Varredura SNMP</button>
          </div>
        </form>
      </div>
      <div id="results" class="panel">
        <h2>Resultados</h2>
        <p>{escape(str(len(devices)))} dispositivo(s) encontrados na ultima varredura.</p>
        <form method="post" action="/discovery/save">
          <input type="hidden" name="network" value="{escape(state.get("network") or "")}" />
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Nome</th>
                <th>Fabricante</th>
                <th>Modelo</th>
                <th>Tipo</th>
                <th>Descri??o</th>
                <th>Grupo</th>
                <th>Subgrupo</th>
                <th>Incluir</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows) if rows else '<tr><td colspan="9">Nenhum dispositivo na ultima varredura.</td></tr>'}
            </tbody>
          </table>
          <div style="display:flex; gap:10px; margin-top:14px; flex-wrap:wrap;">
            <button class="btn primary" type="submit">Salvar classificacao</button>
            <a class="btn" href="/discovery">Recarregar</a>
          </div>
        </form>
      </div>
      <div class="foot">
        <div>Grupo padrao: switches, servidores e hosts.</div>
        <div>O resultado fica salvo em disco para revisao posterior.</div>
      </div>
    </section>
    """
    return _render_shell("Descoberta SNMP | infra-sync-api", body)


def _management_nav(active: str) -> str:
    items = [
        ("overview", "/", "Dashboard", "Resumo operacional"),
        ("devices", "/devices", "Devices", "Criar e editar equipamentos"),
        ("vlans", "/vlans", "VLANs", "Segmentacao e tags"),
        ("networks", "/networks", "Redes", "Prefixes e blocos IP"),
        ("snmp", "/snmp", "SNMP", "Portas, CPU e trÃƒÆ’Ã‚Â¡fego"),
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
        return "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â"
    text = _normalize_text(value)
    return text or "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â"


def _status_value(value: Any, default: str = "active") -> str:
    if isinstance(value, dict):
        for key in ("value", "slug", "name", "label"):
            text = _normalize_text(value.get(key))
            if text:
                return text
        return default
    text = _normalize_text(value)
    return text or default


def _related_id(value: Any) -> str:
    if isinstance(value, dict):
        text = value.get("id")
        return str(text) if text is not None else ""
    return _normalize_text(value)


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
        if site and site != "ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â":
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
        <p>Central de operaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o para inventÃƒÆ’Ã‚Â¡rio, IPAM, alertas e automaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o.</p>
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


DEVICE_KIND_ORDER = ("all", "computers", "servers", "network", "wireless", "printers", "phones", "monitors", "other")
DEVICE_KIND_LABELS = {
    "all": "Todos",
    "computers": "Computadores",
    "servers": "Servidores",
    "network": "Dispositivos de rede",
    "wireless": "Wireless / APs",
    "printers": "Impressoras",
    "phones": "Telefonia",
    "monitors": "Monitores",
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
      <p>Use este formulÃƒÆ’Ã‚Â¡rio para cadastrar ou corrigir um equipamento no NetBox.</p>
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
          <p>Adicione qualquer informaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Â£o extra do device. Ex.: acesso L2/L3, usuÃƒÆ’Ã‚Â¡rio, senha de apoio, VLAN de gerÃƒÆ’Ã‚Âªncia ou observaÃƒÆ’Ã‚Â§ÃƒÆ’Ã‚Âµes.</p>
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
    device_id = _related_id(device.get("id"))
    prefix_lookup = {str(prefix.get("id")): prefix for prefix in prefixes if isinstance(prefix, dict)}
    topology_rows = []
    for entry in _network_topology_entries(topology_state):
        if str(entry.get("origin_device_id")) != device_id and str(entry.get("next_device_id")) != device_id:
            continue
        prefix = prefix_lookup.get(str(entry.get("prefix_id")))
        topology_rows.append(
            f"""
            <tr>
              <td>{escape(_normalize_text(prefix.get('prefix')) if isinstance(prefix, dict) else 'Ã¢â‚¬â€')}</td>
              <td>{escape(_normalize_text(entry.get('network_kind')) or ('VLAN' if prefix and _related_id(prefix.get('vlan')) else 'Prefixo'))}</td>
              <td>{escape(_normalize_text(entry.get('origin_interface')) or 'Ã¢â‚¬â€')}</td>
              <td>{escape(_normalize_text(entry.get('next_interface')) or 'Ã¢â‚¬â€')}</td>
              <td>{escape(_normalize_text(entry.get('route_notes')) or 'Ã¢â‚¬â€')}</td>
            </tr>
            """
        )
    interface_rows = []
    for interface in interfaces:
        if not isinstance(interface, dict):
            continue
        interface_rows.append(
            f"""
            <tr>
              <td><strong>{escape(_normalize_text(interface.get('name')) or 'Ã¢â‚¬â€')}</strong></td>
              <td>{escape(_normalize_text(interface.get('description')) or 'Ã¢â‚¬â€')}</td>
              <td>{escape(_relation_label(interface.get('enabled')) if isinstance(interface.get('enabled'), dict) else _normalize_text(interface.get('enabled')) or 'Ã¢â‚¬â€')}</td>
              <td>{escape(_relation_label(interface.get('type')))}</td>
              <td>{escape(_normalize_text(interface.get('mode')) or 'Ã¢â‚¬â€')}</td>
              <td>{escape(_relation_label(interface.get('untagged_vlan')))}</td>
              <td>{escape(_normalize_text(interface.get('mac_address')) or 'Ã¢â‚¬â€')}</td>
            </tr>
            """
        )

    status = _relation_label(device.get("status"))
    site = _relation_label(device.get("site"))
    role = _relation_label(device.get("role"))
    rack = _relation_label(device.get("rack"))
    device_type = _relation_label(device.get("device_type"))
    primary_ip = _relation_label(device.get("primary_ip4"))
    custom_fields = device.get("custom_fields") if isinstance(device.get("custom_fields"), dict) else {}
    custom_rows = "".join(
        f"<tr><td>{escape(str(key))}</td><td>{escape(_normalize_text(value) or 'Ã¢â‚¬â€')}</td></tr>"
        for key, value in custom_fields.items()
    ) or _render_table_empty("Sem campos personalizados.", 2)
    detail_nav = """
      <div class="detail-nav">
        <a href="#resumo"><span>Resumo</span><small>Status, site e rack</small></a>
        <a href="#relacoes"><span>RelaÃ§Ãµes</span><small>Rotas e vÃ­nculos</small></a>
        <a href="#interfaces"><span>Interfaces</span><small>Portas e SNMP</small></a>
        <a href="#campos"><span>Campos</span><small>Custom fields</small></a>
      </div>
    """
    body = f"""
    <div class="panels" style="grid-template-columns: 240px minmax(0, 1.2fr) minmax(360px, .9fr); align-items:start;">
      <aside class="panel">
        <h2>Ativo</h2>
        <p>Menu lateral do device no estilo de inventÃ¡rio do GLPI.</p>
        {detail_nav}
        <div style="margin-top:14px; display:flex; flex-direction:column; gap:8px;">
          <a class="btn" href="/devices">Voltar para ativos</a>
          <a class="btn" href="/networks">Relacionar redes</a>
          <a class="btn" href="/vlans">Relacionar VLANs</a>
          <a class="btn" href="/topology">Ver topologia</a>
        </div>
      </aside>
      <div class="panel">
        <h2 id="resumo">{escape(_normalize_text(device.get('name')) or 'Device')}</h2>
        <p>VisÃ£o detalhada do ativo com relaÃ§Ãµes para IP, rack, VLAN, interfaces e rota.</p>
        <div class="detail-meta">
          <article class="metric-card"><div class="metric-label">Status</div><div class="metric-value" style="font-size:24px;">{escape(status)}</div><div class="metric-note">SituaÃ§Ã£o atual do device no NetBox.</div></article>
          <article class="metric-card"><div class="metric-label">Site</div><div class="metric-value" style="font-size:24px;">{escape(site)}</div><div class="metric-note">Local fÃ­sico ou unidade.</div></article>
          <article class="metric-card"><div class="metric-label">Rack</div><div class="metric-value" style="font-size:24px;">{escape(rack)}</div><div class="metric-note">PosiÃ§Ã£o no rack e sala.</div></article>
          <article class="metric-card"><div class="metric-label">Role</div><div class="metric-value" style="font-size:24px;">{escape(role)}</div><div class="metric-note">FunÃ§Ã£o operacional.</div></article>
          <article class="metric-card"><div class="metric-label">Tipo</div><div class="metric-value" style="font-size:24px;">{escape(device_type)}</div><div class="metric-note">Modelo e classe do device.</div></article>
          <article class="metric-card"><div class="metric-label">IP</div><div class="metric-value" style="font-size:24px;">{escape(primary_ip)}</div><div class="metric-note">IP principal associado.</div></article>
        </div>
        <div class="panel" id="relacoes" style="margin-top:14px; background:#0f0f12;">
          <h3 style="margin-top:0;">Rota e vÃ­nculos</h3>
          <table>
            <thead><tr><th>Prefixo</th><th>Tipo</th><th>Origem</th><th>Destino</th><th>ObservaÃ§Ã£o</th></tr></thead>
            <tbody>{''.join(topology_rows) if topology_rows else _render_table_empty('Nenhuma rota vinculada a este device.', 5)}</tbody>
          </table>
        </div>
        <div class="panel" id="interfaces" style="margin-top:14px; background:#0f0f12;">
          <h3 style="margin-top:0;">Interfaces</h3>
          <table>
            <thead><tr><th>Nome</th><th>DescriÃ§Ã£o</th><th>Ativa</th><th>Tipo</th><th>Modo</th><th>VLAN</th><th>MAC</th></tr></thead>
            <tbody>{''.join(interface_rows) if interface_rows else _render_table_empty('Nenhuma interface encontrada.', 7)}</tbody>
          </table>
        </div>
        <div class="panel" id="campos" style="margin-top:14px; background:#0f0f12;">
          <h3 style="margin-top:0;">Campos personalizados</h3>
          <table>
            <thead><tr><th>Campo</th><th>Valor</th></tr></thead>
            <tbody>{custom_rows}</tbody>
          </table>
        </div>
      </div>
      {_device_form(device)}
    </div>
    """
    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Device atualizado com sucesso.</strong></div>"
    if error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(error)}</strong></div>"
    return _render_management_page(
        title=f"{escape(_normalize_text(device.get('name')) or 'Device')} | infra-sync-api",
        active="devices",
        heading=_normalize_text(device.get("name")) or "Device",
        subtitle="Detalhe do device com relaÃ§Ãµes, interfaces e ediÃ§Ã£o centralizada.",
        actions='<a class="btn" href="/devices">Lista de devices</a><a class="btn" href="/networks">Redes</a><a class="btn" href="/vlans">VLANs</a><a class="btn" href="/topology">Topologia</a>',
        banner=banner,
        body=body,
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

    rows = []
    for device in filtered_devices:
        device_type = device.get("device_type") if isinstance(device.get("device_type"), dict) else {}
        manufacturer = _relation_label(device_type.get("manufacturer")) if isinstance(device_type, dict) else "?"
        model = _normalize_text(device_type.get("model")) if isinstance(device_type, dict) else _relation_label(device.get("device_type"))
        kind = _inventory_kind_label(_inventory_kind_for_device(device))
        rows.append(
            f"""
            <tr>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}"><strong>{escape(_normalize_text(device.get('name')) or '?')}</strong></a></td>
              <td><span class="pill muted">{escape(kind)}</span></td>
              <td>{escape(_relation_label(device.get('status')))}</td>
              <td>{escape(manufacturer or '?')}</td>
              <td>{escape(model or '?')}</td>
              <td>{escape(_relation_label(device.get('site')))}</td>
              <td>{escape(_relation_label(device.get('rack')))}</td>
              <td>{escape(_relation_label(device.get('primary_ip4')))}</td>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}">Detalhe</a> | <a href="/devices?edit={escape(_related_id(device.get('id')))}&kind={escape(active_kind)}">Editar</a></td>
            </tr>
            """
        )

    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Device atualizado com sucesso.</strong></div>"
    if page_error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(page_error)}</strong></div>"

    kind_menu = _inventory_kind_menu(active_kind, inventory_counts, search)
    body = f"""
    <div class="panels" style="grid-template-columns: 280px minmax(0, 1.15fr) minmax(360px, .9fr); align-items:start;">
      <div class="panel">
        <h2>Ativos</h2>
        <p>Menu de inventÃ¡rio por tipo, semelhante ao GLPI.</p>
        <div class="inventory-kind-menu">{kind_menu}</div>
        <div class="inventory-summary" style="margin-top:14px;">
          <div class="metric-card" style="min-height:92px;"><div class="metric-label">Total</div><div class="metric-value" style="font-size:28px;">{len(devices)}</div><div class="metric-note">Devices cadastrados e carregados do NetBox.</div></div>
          <div class="metric-card" style="min-height:92px; margin-top:12px;"><div class="metric-label">Filtro atual</div><div class="metric-value" style="font-size:24px;">{escape(_inventory_kind_label(active_kind))}</div><div class="metric-note">Clique em um tipo para listar os ativos correspondentes.</div></div>
        </div>
        <div style="margin-top:14px;">
          <a class="btn" href="/devices">Todos os ativos</a>
          <a class="btn" style="margin-top:8px; display:inline-flex;" href="/topology">Topologia</a>
        </div>
      </div>
      <div class="panel">
        <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-end; margin-bottom:12px; flex-wrap:wrap;">
          <div>
            <h2 style="margin-bottom:6px;">{escape(_inventory_kind_label(active_kind))}</h2>
            <p style="margin:0; color:var(--muted);">{len(filtered_devices)} device(s) nesta categoria.</p>
            <p style="margin:6px 0 0; color:var(--muted);">Devices cadastrados | Leitura SNMP | ediÃ§Ã£o centralizada.</p>
          </div>
          <form method="get" action="/devices" style="display:flex; gap:8px; align-items:end; flex-wrap:wrap; margin:0;">
            <input type="hidden" name="kind" value="{escape(active_kind)}" />
            <div class="field" style="margin:0; min-width:260px;"><label for="q">Pesquisar</label><input id="q" name="q" type="text" value="{escape(search)}" placeholder="Nome, IP, modelo..." /></div>
            <button class="btn primary" type="submit">Pesquisar</button>
          </form>
        </div>
        <table>
          <thead><tr><th>Nome</th><th>Tipo</th><th>Status</th><th>Fabricante</th><th>Modelo</th><th>Site</th><th>Rack</th><th>IP</th><th>AÃ§Ãµes</th></tr></thead>
          <tbody>{''.join(rows) if rows else _render_table_empty('Nenhum device encontrado nesta categoria.', 9)}</tbody>
        </table>
      </div>
      {_device_form(edit_device)}
    </div>
    """
    return HTMLResponse(
        _render_management_page(
            title="Assets | infra-sync-api",
            active="devices",
            heading="Ativos",
            subtitle="Lista e detalhe dos equipamentos com navegaÃ§Ã£o por tipo, como no GLPI.",
            actions=f'<a class="btn" href="/">Dashboard</a><a class="btn" href="/snmp">Leitura SNMP</a><a class="btn" href="/reports">Imprimir relatÃ³rio</a>',
            body=body,
            banner=banner,
        )
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
      <p>Cadastro de segmentaÃ§Ã£o L2 para a rede central.</p>
      <form method="post" action="/vlans/save">
        <input type="hidden" name="vlan_id" value="{escape(_related_id(vlan.get('id')))}" />
        <div class="form-grid">
          <div class="field"><label>VID</label><input name="vid" type="text" value="{escape(_normalize_text(vlan.get('vid')))}" /></div>
          <div class="field"><label>Nome</label><input name="name" type="text" value="{escape(_normalize_text(vlan.get('name')))}" /></div>
          <div class="field"><label>Status</label><input name="status" type="text" value="{escape(_status_value(vlan.get('status')))}" /></div>
          <div class="field"><label>Site ID</label><input name="site_id" type="text" value="{escape(_related_id(vlan.get('site')))}" /></div>
        </div>
        <div class="field"><label>DescriÃ§Ã£o</label><input name="description" type="text" value="{escape(_normalize_text(vlan.get('description')))}" /></div>
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
        <div class="field"><label>DescriÃ§Ã£o</label><input name="description" type="text" value="{escape(_normalize_text(prefix.get('description')))}" /></div>
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
        origin_device = device_lookup.get(_normalize_text(entry.get("origin_device_id")), "â€”")
        next_device = device_lookup.get(_normalize_text(entry.get("next_device_id")), "â€”")
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(_normalize_text(prefix.get('prefix')) or 'â€”')}</strong></td>
              <td>{escape(_normalize_text(entry.get('network_kind')) or ('VLAN' if _related_id(prefix.get('vlan')) else 'Prefixo'))}</td>
              <td>{escape(_related_id(prefix.get('vlan')) or 'â€”')}</td>
              <td>{escape(origin_device)}</td>
              <td>{escape(_normalize_text(entry.get('origin_interface')) or 'â€”')}</td>
              <td>{escape(_normalize_text(entry.get('origin_mode')) or 'â€”')}</td>
              <td>{escape(next_device)}</td>
              <td>{escape(_normalize_text(entry.get('next_interface')) or 'â€”')}</td>
              <td>{escape(_normalize_text(entry.get('next_mode')) or 'â€”')}</td>
              <td>{escape(_normalize_text(entry.get('route_notes')) or 'â€”')}</td>
            </tr>
            """
        )
    return "".join(rows) if rows else _render_table_empty("Nenhuma rota cadastrada ainda.", 10)


@app.get("/devices", include_in_schema=False)
async def devices_page(request: Request, saved: int = 0, error: str | None = None, edit: int | None = None):
    client = request.app.state.netbox_client
    devices: list[dict[str, Any]] = []
    edit_device: dict[str, Any] | None = None
    page_error = error
    try:
        if client is not None:
            params: dict[str, Any] = {"limit": 50}
            q = _query_value(request, "q")
            if q:
                params["q"] = q
            devices = await client.list_devices(params=params)
            if edit is not None:
                edit_device = await client.get_device(edit)
    except Exception as exc:
        page_error = str(exc)

    rows = []
    for device in devices:
        rows.append(
            f"""
            <tr>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}"><strong>{escape(_normalize_text(device.get('name')) or '?')}</strong></a></td>
              <td>{escape(_relation_label(device.get('status')))}</td>
              <td>{escape(_relation_label(device.get('site')))}</td>
              <td>{escape(_relation_label(device.get('role')))}</td>
              <td>{escape(_relation_label(device.get('device_type')))}</td>
              <td>{escape(_relation_label(device.get('primary_ip4')))}</td>
              <td>{escape(_normalize_text(device.get('serial')) or '?')}</td>
              <td><a href="/devices/view/{escape(_related_id(device.get('id')))}">Detalhe</a> | <a href="/devices?edit={escape(_related_id(device.get('id')))}">Editar</a></td>
            </tr>
            """
        )
    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Device atualizado com sucesso.</strong></div>"
    if page_error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(page_error)}</strong></div>"
    body = f"""
    <div class="panels" style="grid-template-columns: 1fr 1.2fr;">
      {_device_form(edit_device)}
      <div class="panel">
        <h2>Devices cadastrados</h2>
        <p>Lista dos ativos mais recentes no NetBox.</p>
        <table>
          <thead><tr><th>Nome</th><th>Status</th><th>Site</th><th>Role</th><th>Tipo</th><th>IP</th><th>Serial</th><th></th></tr></thead>
          <tbody>{''.join(rows) if rows else _render_table_empty('Nenhum device encontrado.', 8)}</tbody>
        </table>
      </div>
    </div>
    """
    return HTMLResponse(
        _render_management_page(
            title="Devices | infra-sync-api",
            active="devices",
            heading="Devices",
            subtitle="Criar, editar e inspecionar equipamentos do inventÃ¡rio.",
            actions=f'<a class="btn" href="/">Dashboard</a><a class="btn" href="/snmp">Leitura SNMP</a><a class="btn" href="/reports">Imprimir relatÃ³rio</a>',
            body=body,
            banner=banner,
        )
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
                return HTMLResponse(await _render_crud_error(request, "devices", f"{key} precisa ser um inteiro vÃ¡lido"), status_code=status.HTTP_400_BAD_REQUEST)
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
              <td><strong>{escape(_normalize_text(vlan.get('vid')) or 'â€”')}</strong></td>
              <td>{escape(_normalize_text(vlan.get('name')) or 'â€”')}</td>
              <td>{escape(_relation_label(vlan.get('status')))}</td>
              <td>{escape(_relation_label(vlan.get('site')))}</td>
              <td>{escape(_normalize_text(vlan.get('description')) or 'â€”')}</td>
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
        <p>SegmentaÃ§Ãµes registradas no NetBox.</p>
        <table>
          <thead><tr><th>VID</th><th>Nome</th><th>Status</th><th>Site</th><th>DescriÃ§Ã£o</th><th></th></tr></thead>
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
            subtitle="Criar, editar e visualizar segmentaÃ§Ãµes de rede.",
            actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/reports">Imprimir relatÃ³rio</a>',
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
            return HTMLResponse(await _render_crud_error(request, "vlans", "site_id precisa ser um inteiro vÃ¡lido"), status_code=status.HTTP_400_BAD_REQUEST)
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
            title="Redes | infra-sync-api",
            active="networks",
            heading="Redes",
            subtitle="Criar, editar e revisar blocos IP e prefixes.",
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
    try:
        if client is not None:
            prefixes = await client.list_prefixes(params={"limit": 100})
            devices = await client.list_devices(params={"limit": 100})
    except Exception as exc:
        page_error = str(exc)
    device_lookup = {
        _related_id(device.get("id")): _normalize_text(device.get("name"))
        for device in devices
        if isinstance(device, dict)
    }
    body = f"""
    <div class="panel">
      <h2>Mapa da rede</h2>
      <p>Visualizacao central das rotas entre redes, VLANs, switches e equipamentos.</p>
      {f'<div class="hero"><small>Erro</small><strong>{escape(page_error)}</strong></div>' if page_error else ''}
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
            title="Mapa | infra-sync-api",
            active="networks",
            heading="Mapa da rede",
            subtitle="Ligacoes entre equipamentos, portas, VLANs e prefixes.",
            actions='<a class="btn" href="/networks">Redes</a><a class="btn" href="/devices">Devices</a>',
            body=body,
        )
    )


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
        host_name = _relation_label(hosts[0]) if hosts else "â€”"
        rows.append(
            f"""
            <tr>
              <td>{escape(_normalize_text(alert.get('name')) or 'â€”')}</td>
              <td>{escape(_normalize_text(alert.get('severity')) or 'â€”')}</td>
              <td>{escape(_normalize_text(host_name))}</td>
              <td>{escape(_normalize_text(alert.get('clock')) or 'â€”')}</td>
            </tr>
            """
        )
    banner = ""
    if error_message:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(error_message)}</strong><div class='sub' style='margin: 6px 0 0;'>O Zabbix respondeu sem permissÃ£o suficiente para problem.get. O painel segue operando com o inventÃ¡rio e demais telas.</div></div>"
    elif info_message:
        banner = f"<div class='hero'><small>OK</small><strong>{escape(info_message)}</strong></div>"
    body = f"""
    {banner}
    <div class="panel">
      <h2>Alertas ativos</h2>
      <p>Atualiza automaticamente pelo Zabbix em carregamentos de pÃ¡gina e via API.</p>
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
        actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/reports">Imprimir relatÃ³rio</a>',
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


def _render_snmp_page(state: dict[str, Any], saved: bool = False, error: str | None = None) -> str:
    last_probe = state.get("last_probe") if isinstance(state.get("last_probe"), dict) else None
    ports = last_probe.get("ports") if last_probe and isinstance(last_probe.get("ports"), list) else []
    banner = ""
    if saved:
        banner = "<div class='hero'><small>Salvo</small><strong>Leitura SNMP atualizada com sucesso.</strong></div>"
    if error:
        banner = f"<div class='hero'><small>Erro</small><strong>{escape(error)}</strong></div>"
    summary = ""
    if last_probe:
        summary = f"""
        <div class="metrics">
          <article class="metric-card"><div class="metric-label">SysName</div><div class="metric-value" style="font-size:22px">{escape(_normalize_text(last_probe.get("sys_name")) or 'â€”')}</div><div class="metric-note">{escape(_normalize_text(last_probe.get("sys_descr")) or 'Sem descriÃ§Ã£o')}</div></article>
          <article class="metric-card"><div class="metric-label">Interfaces</div><div class="metric-value">{escape(_normalize_text(last_probe.get("if_number")) or 'â€”')}</div><div class="metric-note">Portas/links vistos pelo SNMP.</div></article>
          <article class="metric-card"><div class="metric-label">MemÃ³ria</div><div class="metric-value">{escape(_normalize_text(last_probe.get("hr_memory_size")) or 'â€”')}</div><div class="metric-note">Total reportado pelo agente.</div></article>
          <article class="metric-card"><div class="metric-label">CPU mÃ©dia</div><div class="metric-value">{escape(_normalize_text(last_probe.get("processor_load_average")) or 'â€”')}</div><div class="metric-note">MÃ©dia dos processadores coletados.</div></article>
        </div>
        """
    rows = []
    for port in ports:
        if not isinstance(port, dict):
            continue
        rows.append(
            f"""
            <tr>
              <td>{escape(_normalize_text(port.get('index')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('name')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('description')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('alias')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('admin_status')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('oper_status')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('speed_bps')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('in_octets')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('out_octets')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('in_rate_bps')) or 'â€”')}</td>
              <td>{escape(_normalize_text(port.get('out_rate_bps')) or 'â€”')}</td>
            </tr>
            """
        )
    body = f"""
    {banner}
    <div class="panel" style="margin-bottom:14px;">
      <h2>Consulta SNMP</h2>
      <p>Informe o IP privado do switch ou servidor e a community para coletar portas, CPU, memÃ³ria e trÃ¡fego.</p>
      <form method="post" action="/snmp/probe">
        <div class="form-grid">
          <div class="field"><label for="ip">IP</label><input id="ip" name="ip" type="text" value="{escape(_normalize_text(last_probe.get('ip')) if last_probe else '')}" placeholder="10.0.0.24" /></div>
          <div class="field"><label for="community">Community</label><input id="community" name="community" type="password" value="" placeholder="public" /></div>
          <div class="field"><label for="timeout">Timeout</label><input id="timeout" name="timeout" type="text" value="1.0" /></div>
          <div class="field"><label for="retries">Retries</label><input id="retries" name="retries" type="text" value="0" /></div>
          <div class="field"><label for="max_ports">MÃ¡ximo de portas</label><input id="max_ports" name="max_ports" type="text" value="48" /></div>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <button class="btn primary" type="submit">Consultar SNMP</button>
          <a class="btn" href="/devices">Voltar aos devices</a>
        </div>
      </form>
    </div>
    {summary}
    <div class="panel" style="margin-top:14px;">
      <h2>Portas</h2>
      <p>DescriÃ§Ã£o, alias, status e contadores por interface.</p>
      <table>
        <thead>
          <tr>
            <th>Ãndice</th><th>Nome</th><th>DescriÃ§Ã£o</th><th>Alias</th><th>Admin</th><th>Oper</th><th>Speed</th><th>Entrada</th><th>SaÃ­da</th><th>Rate In</th><th>Rate Out</th>
          </tr>
        </thead>
        <tbody>{''.join(rows) if rows else _render_table_empty('Nenhuma porta coletada ainda.', 11)}</tbody>
      </table>
    </div>
    """
    return _render_management_page(
        title="SNMP | infra-sync-api",
        active="snmp",
        heading="SNMP",
        subtitle="Leitura detalhada de portas, CPU, memÃ³ria e trÃ¡fego por equipamento.",
        actions='<a class="btn" href="/">Dashboard</a><a class="btn" href="/devices">Devices</a>',
        body=body,
    )


def _render_reports_page(snapshot: dict[str, Any]) -> str:
    alerts = snapshot.get("alerts") if isinstance(snapshot.get("alerts"), list) else []
    alert_rows = []
    for alert in alerts[:10]:
        hosts = alert.get("hosts") if isinstance(alert.get("hosts"), list) else []
        host_name = _relation_label(hosts[0]) if hosts else "â€”"
        alert_rows.append(
            f"<tr><td>{escape(_normalize_text(alert.get('name')) or 'â€”')}</td><td>{escape(_normalize_text(host_name))}</td><td>{escape(_normalize_text(alert.get('severity')) or 'â€”')}</td></tr>"
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
      <h2>RelatÃ³rio executivo</h2>
      <p>Resumo operacional pronto para impressÃ£o ou PDF do navegador.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom: 14px;">
        <button class="btn primary" type="button" onclick="window.print()">Imprimir</button>
        <a class="btn" href="/alerts">Ver alertas</a>
        <a class="btn" href="/devices">Ver devices</a>
      </div>
      <table>
        <thead><tr><th>MÃ©trica</th><th>Valor</th></tr></thead>
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
        title="RelatÃ³rios | infra-sync-api",
        active="reports",
        heading="RelatÃ³rios",
        subtitle="Resumo executivo para imprimir, salvar em PDF ou compartilhar.",
        actions='<button class="btn primary" type="button" onclick="window.print()">Imprimir</button><a class="btn" href="/">Dashboard</a>',
        body=body,
    )


async def _render_crud_error(request: Request, active: str, message: str) -> str:
    title_map = {"devices": "Devices", "vlans": "VLANs", "networks": "Redes"}
    return _render_management_page(
        title=f"{title_map.get(active, 'OperaÃ§Ã£o')} | infra-sync-api",
        active=active,
        heading=title_map.get(active, "OperaÃ§Ã£o"),
        subtitle="Houve um problema ao salvar os dados.",
        actions='<a class="btn" href="/">Dashboard</a>',
        body=f"<div class='hero'><small>Erro</small><strong>{escape(message)}</strong></div>",
    )

