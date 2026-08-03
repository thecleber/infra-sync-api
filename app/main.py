from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from . import __version__
from .config import Settings, get_settings
from .models import SyncDeviceRequest
from .netbox_client import NetBoxClient, NetBoxClientError
from .services import SyncError, sync_device


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    app.state.settings = settings
    app.state.netbox_client = NetBoxClient(settings.netbox_url, settings.netbox_token, settings.request_timeout)
    try:
        yield
    finally:
        await app.state.netbox_client.aclose()


app = FastAPI(title="infra-sync-api", version=__version__, lifespan=lifespan)


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key"), settings: Settings = Depends(get_settings)) -> None:
    if x_api_key is None or not hmac.compare_digest(x_api_key, settings.sync_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def get_client(request: Request) -> NetBoxClient:
    return request.app.state.netbox_client


@app.exception_handler(NetBoxClientError)
async def netbox_error_handler(request: Request, exc: NetBoxClientError):
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={"detail": "NetBox request failed", "message": str(exc)},
    )


@app.exception_handler(SyncError)
async def sync_error_handler(request: Request, exc: SyncError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": str(exc)},
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logging.getLogger("infra-sync-api").exception("Unhandled error")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.head("/", include_in_schema=False)
async def root_head():
    return RedirectResponse(url="/docs", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.get("/health")
async def health(request: Request):
    client: NetBoxClient = request.app.state.netbox_client
    connected = await client.health_status()
    return {"service": "infra-sync-api", "status": "ok" if connected else "degraded", "netbox_connected": connected}


@app.get("/version")
async def version():
    return {"service": "infra-sync-api", "version": __version__}


@app.post("/sync/device")
async def sync_device_endpoint(
    payload: SyncDeviceRequest,
    request: Request,
    _: None = Depends(require_api_key),
):
    client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_device(payload, client, settings.default_site_id, dry_run=False)
    return result.as_dict()


@app.post("/sync/device/dry-run")
async def sync_device_dry_run_endpoint(
    payload: SyncDeviceRequest,
    request: Request,
    _: None = Depends(require_api_key),
):
    client: NetBoxClient = request.app.state.netbox_client
    settings: Settings = request.app.state.settings
    result = await sync_device(payload, client, settings.default_site_id, dry_run=True)
    return result.as_dict()
