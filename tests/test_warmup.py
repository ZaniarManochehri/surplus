"""Regression tests for the non-blocking startup (v0.2.1).

The socket binds before the tunnel and the first catalog load, so:
- a gated request waits for the warm-up instead of being called "unknown",
- GET /v1/models waits briefly instead of answering an empty list,
- swapping the upstream client schedules the catalog reload in the background
  (admin endpoints never wait on a slow marketplace).

No network and no lifespan: the ASGI app is driven in-process.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from surplus import main
from surplus.catalog import Catalog
from surplus.config import AppConfig
from surplus.filters import UNKNOWN_MODEL


def bare_state(**attrs) -> main.State:
    """A State without running __init__ (no config load, no real client)."""
    state = main.State.__new__(main.State)
    state.cfg = AppConfig()
    state.client = None
    state.client_proxy_url = None
    state.catalog = Catalog("https://upstream.example")
    state.catalog_ready = asyncio.Event()
    for name, value in attrs.items():
        setattr(state, name, value)
    return state


# ----------------------------------------------------------- wait_for_catalog


async def test_wait_for_catalog_is_immediate_once_loaded() -> None:
    state = bare_state()
    state.catalog.models = {"m": object()}
    assert await state.wait_for_catalog(0.001) is True


async def test_wait_for_catalog_gives_up_after_the_budget() -> None:
    state = bare_state()
    assert await state.wait_for_catalog(0.01) is False


async def test_wait_for_catalog_wakes_when_the_first_load_lands() -> None:
    state = bare_state()

    async def first_load() -> None:
        await asyncio.sleep(0.02)
        state.catalog.models = {"m": object()}
        state.catalog_ready.set()

    loader = asyncio.create_task(first_load())
    assert await state.wait_for_catalog(2.0) is True
    await loader


# --------------------------------------------------------------- sync_client


async def test_sync_client_schedules_a_background_refresh(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(main.State, "swap_client", lambda self, client: calls.append("swap"))
    monkeypatch.setattr(
        main.State, "refresh_catalog_soon", lambda self: calls.append("refresh")
    )
    monkeypatch.setattr(main, "build_client", lambda timeout, proxy=None: "CLIENT")
    state = bare_state(tunnel=SimpleNamespace(proxy_url=lambda: "http://127.0.0.1:1"))

    await state.sync_client()

    assert calls == ["swap", "refresh"]  # scheduled, never awaited inline
    assert state.client_proxy_url == "http://127.0.0.1:1"

    # Nothing to do while the proxy URL is unchanged (the usual supervisor tick).
    await state.sync_client()
    assert calls == ["swap", "refresh"]


# ------------------------------------------------------- the /v1 warm-up gate


@pytest.fixture
def warmup_waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Isolate the app state, drop any stored key, record warm-up waits."""
    monkeypatch.setattr(main.state, "cfg", AppConfig())
    monkeypatch.setattr(main.state, "catalog", Catalog("https://upstream.example"))
    monkeypatch.setattr(main, "maybe_reload_config", lambda: main.state.cfg)
    monkeypatch.delenv("SURPLUS_API_KEY", raising=False)
    main.state.cfg.file_api_key = ""
    waits: list[float] = []

    async def fake_wait(self: main.State, timeout: float) -> bool:
        waits.append(timeout)
        return False

    monkeypatch.setattr(main.State, "wait_for_catalog", fake_wait)
    return waits


def router_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app), base_url="http://router.test"
    )


async def test_gated_request_waits_for_warmup_then_stays_fail_closed(
    warmup_waits: list[float],
) -> None:
    main.state.cfg.filters.allow_unknown_models = False
    async with router_client() as api:
        response = await api.post(
            "/v1/chat/completions", json={"model": "some-model", "messages": []}
        )
    assert warmup_waits == [main.CATALOG_WARMUP_SECONDS]
    # The wait loaded nothing: the gate must still refuse, never forward.
    assert response.status_code == 403
    assert response.json()["error"]["failed_filters"] == [UNKNOWN_MODEL]


async def test_requests_skip_the_wait_when_unknown_models_are_allowed(
    warmup_waits: list[float],
) -> None:
    main.state.cfg.filters.allow_unknown_models = True
    async with router_client() as api:
        response = await api.post(
            "/v1/chat/completions", json={"model": "some-model", "messages": []}
        )
    assert warmup_waits == []  # nothing to validate against the catalog
    # No key configured in this test: the next gate in line answers.
    assert response.status_code == 503
    assert response.json()["error"]["type"] == "api_key_missing"


async def test_model_list_waits_briefly_for_the_first_load(
    warmup_waits: list[float],
) -> None:
    async with router_client() as api:
        response = await api.get("/v1/models")
    assert response.status_code == 200
    assert warmup_waits == [main.CATALOG_LIST_WAIT_SECONDS]
    assert main.CATALOG_LIST_WAIT_SECONDS < main.CATALOG_WARMUP_SECONDS
