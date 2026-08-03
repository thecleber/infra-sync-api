from __future__ import annotations

import copy
import hmac
import ipaddress
import json
import logging
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import parse_qs
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import __version__
from .config import Settings, get_settings
from .discovery import classify_discovered_device, load_last_scan, save_group_selections, scan_network
from .models import SyncDeviceRequest, ZabbixHostSyncRequest
from .netbox_client import NetBoxClient, NetBoxClientError
from .services import SyncError, sync_device, sync_zabbix_host
from .zabbix_client import ZabbixClient, ZabbixClientError


RUNTIME_CONFIG_PATH = Path("data") / "integrations.json"


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def default_runtime(settings: Settings) -> dict[str, Any]:
    return {
        "sync_api_key": settings.sync_api_key,
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
    }


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    if cleaned and not cleaned.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return cleaned


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
    for key in ("sync_api_key", "netbox", "zabbix", "glpi", "n8n"):
        if key not in stored:
            continue
        if key == "sync_api_key" and isinstance(stored[key], str):
            payload[key] = _normalize_text(stored[key])
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
    return JSONResponse(status_code=exc.status_code or status.HTTP_502_BAD_GATEWAY, content={"detail": "Zabbix request failed", "message": str(exc)})


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

    counts = {"devices": 0, "interfaces": 0, "ips": 0, "prefixes": 0, "vlans": 0, "sites": 0, "racks": 0, "zabbix_hosts": 0}
    if netbox_connected and netbox_client is not None:
        counts["devices"] = await netbox_client.count("/api/dcim/devices/")
        counts["interfaces"] = await netbox_client.count("/api/dcim/interfaces/")
        counts["ips"] = await netbox_client.count("/api/ipam/ip-addresses/")
        counts["prefixes"] = await netbox_client.count("/api/ipam/prefixes/")
        counts["vlans"] = await netbox_client.count("/api/ipam/vlans/")
        counts["sites"] = await netbox_client.count("/api/dcim/sites/")
        counts["racks"] = await netbox_client.count("/api/dcim/racks/")

    if zabbix_connected and zabbix_client is not None:
        counts["zabbix_hosts"] = await zabbix_client.count_hosts()

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

    discovery_state = load_last_scan()
    discovered_devices = discovery_state.get("devices") if isinstance(discovery_state.get("devices"), list) else []
    discovery_count = len(discovered_devices)

    inventory_cards = [
        {"label": "Devices", "value": counts["devices"], "note": "Dispositivos no inventário"},
        {"label": "IPs", "value": counts["ips"], "note": "Endereços e consumo"},
        {"label": "VLANs", "value": counts["vlans"], "note": "Segmentação de rede"},
        {"label": "Interfaces", "value": counts["interfaces"], "note": "Portas, uplinks e trunks"},
        {"label": "Prefixes", "value": counts["prefixes"], "note": "Blocos e pools"},
        {"label": "Sites", "value": counts["sites"], "note": "Locais e unidades"},
        {"label": "Racks", "value": counts["racks"], "note": "Racks físicos"},
        {"label": "Zabbix hosts", "value": counts["zabbix_hosts"], "note": "Hosts monitorados"},
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
        "metric_bars": [
            {"label": "Devices", "value": counts["devices"]},
            {"label": "IPs", "value": counts["ips"]},
            {"label": "VLANs", "value": counts["vlans"]},
            {"label": "Interfaces", "value": counts["interfaces"]},
            {"label": "Prefixes", "value": counts["prefixes"]},
            {"label": "Sites", "value": counts["sites"]},
            {"label": "Racks", "value": counts["racks"]},
            {"label": "Zabbix", "value": counts["zabbix_hosts"]},
        ],
        "discovery": {
            "network": discovery_state.get("network", ""),
            "count": discovery_count,
            "scanned_at": discovery_state.get("scanned_at", ""),
            "devices": discovered_devices,
        },
    }


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
    input[type="text"], input[type="password"] {{
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
    input[type="text"], input[type="password"] {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #0f0f12;
      color: var(--ink);
      padding: 10px 12px;
      font: inherit;
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

      <div class="foot">
        <div>infra-sync-api v{escape(__version__)}</div>
        <div>Atualizado em {escape(datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"))}</div>
      </div>
    </section>
        """,
        extra_script=extra_script,
    )


def _render_settings(runtime: dict[str, Any], saved: bool = False) -> str:
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
    max_hosts = int(form.get("max_hosts", "128") or "128")
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
              <td><strong>{escape(ip or '—')}</strong></td>
              <td>{escape(str(device.get("sys_name") or '—'))}</td>
              <td style="max-width:280px;">{escape(str(device.get("sys_descr") or '—'))}</td>
              <td>
                <select name="group_{key}">
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
                <th>Descrição</th>
                <th>Grupo</th>
                <th>Subgrupo</th>
                <th>Incluir</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows) if rows else '<tr><td colspan="6">Nenhum dispositivo na ultima varredura.</td></tr>'}
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
