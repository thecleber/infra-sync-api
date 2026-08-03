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

    cards = [
        {"label": "Devices", "value": counts["devices"], "note": "Dispositivos no inventário"},
        {"label": "IPs", "value": counts["ips"], "note": "Endereços e consumo"},
        {"label": "VLANs", "value": counts["vlans"], "note": "Segmentação de rede"},
        {"label": "Interfaces", "value": counts["interfaces"], "note": "Portas, uplinks e trunks"},
        {"label": "Prefixes", "value": counts["prefixes"], "note": "Blocos e pools"},
        {"label": "Sites", "value": counts["sites"], "note": "Locais e unidades"},
        {"label": "Racks", "value": counts["racks"], "note": "Racks físicos"},
        {"label": "Zabbix hosts", "value": counts["zabbix_hosts"], "note": "Hosts monitorados"},
    ]

    return {
        "health": health_status,
        "headline": headline,
        "detail": detail,
        "cards": cards,
        "connectors": connectors,
        "runtime": runtime,
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
