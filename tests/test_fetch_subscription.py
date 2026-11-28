"""Tests for the subscription fetch ladder (User-Agent negotiation).

Some panels answer 403 to a User-Agent they do not know and send different
formats to different clients, so the fetch tries several in a row. Nothing
here touches the network: a mock transport answers every request.
"""

from __future__ import annotations

import base64
import json

import httpx

from surplus.subscription import ROUTE_PROTOCOLS
from surplus.tunnel import SUBSCRIPTION_USER_AGENTS, fetch_subscription

# Stands in for a real subscription URL; nothing may ever echo it back.
TOKEN_URL = "https://panel.example/sub/SECRET-TOKEN-123"
LINKS = base64.b64encode(b"vless://a@one.example:80#one").decode()
UUID = "11111111-2222-3333-4444-555555666666"


def xray_json(address: str = "edge.example") -> str:
    return json.dumps(
        [
            {
                "log": {"loglevel": "warning"},
                "inbounds": [{"tag": "in", "port": 10808, "protocol": "socks"}],
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{"address": address, "port": 443, "users": [{"id": UUID}]}]
                        },
                        "streamSettings": {"network": "tcp"},
                    },
                    {"tag": "direct", "protocol": "freedom", "settings": {}},
                    {"tag": "block", "protocol": "blackhole", "settings": {}},
                ],
                "remarks": "some remark",
            }
        ]
    )


async def test_first_working_user_agent_wins() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        agent = request.headers["user-agent"]
        seen.append(agent)
        if agent == SUBSCRIPTION_USER_AGENTS[0]:
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(
            200, text=LINKS, headers={"date": "Sat, 28 Nov 2026 10:00:00 GMT"}
        )

    result = await fetch_subscription(TOKEN_URL, transport=httpx.MockTransport(handler))

    assert result.ok is True
    assert [server.address for server in result.servers] == ["one.example"]
    assert seen == list(SUBSCRIPTION_USER_AGENTS[:2])  # stopped at the first success
    assert SUBSCRIPTION_USER_AGENTS[1] in result.detail
    assert "base64-links" in result.detail
    assert result.date_header == "Sat, 28 Nov 2026 10:00:00 GMT"
    assert "SECRET-TOKEN" not in result.detail


async def test_xray_json_panel_is_understood() -> None:
    """The shape that made a real Marzban-family subscription unusable."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=xray_json(), headers={"content-type": "application/json"})

    result = await fetch_subscription(TOKEN_URL, transport=httpx.MockTransport(handler))

    assert result.ok is True
    assert [server.name for server in result.servers] == ["some remark"]
    assert "xray-json" in result.detail
    assert "1 route(s)" in result.detail


async def test_unusable_bodies_try_every_user_agent() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers["user-agent"])
        return httpx.Response(200, text="<html><head><title>panel</title></head></html>")

    result = await fetch_subscription(TOKEN_URL, transport=httpx.MockTransport(handler))

    assert result.ok is False
    assert result.servers == []
    assert calls == list(SUBSCRIPTION_USER_AGENTS)
    assert result.detail.count("html with no usable route") == len(SUBSCRIPTION_USER_AGENTS)
    assert "SECRET-TOKEN" not in result.detail


async def test_transport_error_stops_the_ladder_and_hides_the_host() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers["user-agent"])
        raise httpx.ConnectError("[Errno 11001] getaddrinfo failed", request=request)

    result = await fetch_subscription(TOKEN_URL, transport=httpx.MockTransport(handler))

    assert result.ok is False
    assert len(calls) == 1  # same host for every attempt: no point retrying
    assert "cannot connect" in result.detail
    assert "getaddrinfo" not in result.detail  # raw messages can carry host names
    assert "SECRET-TOKEN" not in result.detail


async def test_timeout_is_named_plainly() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    result = await fetch_subscription(TOKEN_URL, transport=httpx.MockTransport(handler))
    assert result.ok is False
    assert "timed out" in result.detail


def test_ladder_leads_with_the_v2rayn_agent_and_ends_with_singbox() -> None:
    assert SUBSCRIPTION_USER_AGENTS[0].startswith("v2rayN/")
    assert "sing-box" in SUBSCRIPTION_USER_AGENTS[-1]
    assert len(set(SUBSCRIPTION_USER_AGENTS)) == len(SUBSCRIPTION_USER_AGENTS)


def test_route_protocols_cover_what_xray_runs() -> None:
    assert set(ROUTE_PROTOCOLS) == {"vless", "vmess", "trojan", "shadowsocks"}
