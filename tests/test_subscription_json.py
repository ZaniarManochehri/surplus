"""Tests for JSON subscriptions and format detection.

Panels disagree about what to return: some send Xray client configs as JSON
(a list of full configs, one config, or a bare list of outbounds), others
send sing-box JSON. All fixtures below are synthetic.
"""

from __future__ import annotations

import base64
import json

from surplus.subscription import (
    ROUTE_PROTOCOLS,
    Server,
    build_client_config,
    detect_format,
    parse_subscription,
)

UUID = "11111111-2222-3333-4444-555555666666"
DIRECT = {"tag": "direct", "protocol": "freedom", "settings": {}}
BLOCK = {"tag": "block", "protocol": "blackhole", "settings": {}}


def vless_outbound(address: str = "edge.example", port: int = 443, **extra) -> dict:
    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": address, "port": port, "users": [{"id": UUID}]}]
        },
        "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/"}},
    }
    outbound.update(extra)
    return outbound


def xray_config(remarks: str, outbounds: list[dict]) -> dict:
    """The shape Marzban-family panels return for Xray-capable clients."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": []},
        "remarks": remarks,
    }


# ------------------------------------------------------------------- Xray JSON


def test_list_of_xray_configs_yields_one_route_each() -> None:
    body = json.dumps(
        [
            xray_config("Iran | ws 1", [vless_outbound("one.example", 80), DIRECT, BLOCK]),
            xray_config("Iran | ws 2", [vless_outbound("two.example", 80), DIRECT, BLOCK]),
        ]
    )
    servers, skipped = parse_subscription(body)
    assert skipped == []
    assert [server.name for server in servers] == ["Iran | ws 1", "Iran | ws 2"]
    assert [server.address for server in servers] == ["one.example", "two.example"]
    assert [server.protocol for server in servers] == ["vless", "vless"]
    # the route is emitted as the default outbound: tag rewritten, body verbatim
    assert servers[0].outbound["tag"] == "proxy"
    assert servers[0].outbound["settings"]["vnext"][0]["users"][0]["id"] == UUID
    config = build_client_config(servers[0], 1080)
    assert [o["protocol"] for o in config["outbounds"]] == ["vless", "blackhole"]


def test_single_xray_config_object() -> None:
    body = json.dumps(xray_config("solo", [vless_outbound(), DIRECT]))
    servers, skipped = parse_subscription(body)
    assert skipped == []
    assert len(servers) == 1 and servers[0].name == "solo" and servers[0].port == 443


def test_bare_list_of_outbounds() -> None:
    body = json.dumps([vless_outbound("bare.example", 8443), BLOCK])
    servers, skipped = parse_subscription(body)
    assert skipped == []
    assert len(servers) == 1 and servers[0].address == "bare.example"
    assert servers[0].port == 8443


def test_freedom_first_pattern_still_finds_the_proxy() -> None:
    """Xray docs make a freedom outbound the default that chains to 'proxy'."""
    freedom = {
        "tag": "direct-out",
        "protocol": "freedom",
        "settings": {},
        "proxySettings": {"tag": "proxy"},
    }
    body = json.dumps(xray_config("chained", [freedom, vless_outbound("hop.example"), BLOCK]))
    servers, _ = parse_subscription(body)
    assert len(servers) == 1
    assert servers[0].address == "hop.example"
    assert servers[0].chain == []  # the proxy itself depends on nothing


def test_proxy_settings_dependency_is_kept_as_a_chain() -> None:
    wireguard = {
        "tag": "wg",
        "protocol": "wireguard",
        "settings": {"secretKey": "k", "address": ["10.0.0.2/32"], "peers": []},
    }
    proxy = vless_outbound("inside-wg.example", 443, proxySettings={"tag": "wg"})
    servers, skipped = parse_subscription(json.dumps(xray_config("wg-hop", [proxy, wireguard])))
    assert skipped == []
    assert [o["tag"] for o in servers[0].chain] == ["wg"]
    config = build_client_config(servers[0], 1080)
    assert [o["protocol"] for o in config["outbounds"]] == ["vless", "wireguard", "blackhole"]


def test_every_route_protocol_is_accepted() -> None:
    outbounds = []
    for protocol in ROUTE_PROTOCOLS:
        entry = {"address": f"{protocol}.example", "port": 443}
        if protocol in ("vless", "vmess"):
            settings = {"vnext": [dict(entry, users=[{"id": UUID}])]}
        elif protocol == "trojan":
            settings = {"servers": [dict(entry, password="pw")]}
        else:
            settings = {"servers": [dict(entry, method="aes-128-gcm", password="pw")]}
        outbounds.append({"tag": protocol, "protocol": protocol, "settings": settings})
    servers, skipped = parse_subscription(json.dumps([*outbounds, BLOCK]))
    assert skipped == []
    assert [server.protocol for server in servers] == list(ROUTE_PROTOCOLS)


def test_unsupported_and_empty_configs_are_reported_not_fatal() -> None:
    body = json.dumps(
        [
            xray_config("tor", [{"tag": "t", "protocol": "tor", "settings": {}}]),
            xray_config("only-direct", [DIRECT, BLOCK]),
            xray_config("fine", [vless_outbound("ok.example")]),
            "not an object",
        ]
    )
    servers, skipped = parse_subscription(body)
    assert [server.address for server in servers] == ["ok.example"]
    assert any("tor: unsupported protocol" in reason for reason in skipped)
    assert any("config #2: no proxy outbound" in reason for reason in skipped)
    assert any("not an object" in reason for reason in skipped)


def test_outbound_without_address_is_skipped() -> None:
    broken = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": "", "port": 0}]},
    }
    servers, skipped = parse_subscription(json.dumps(xray_config("broken", [broken])))
    assert servers == []
    assert any("no address/port" in reason for reason in skipped)


# ------------------------------------------------------------------- sing-box


def singbox(outbounds: list[dict]) -> str:
    return json.dumps(
        {
            "log": {"level": "warn"},
            "dns": {"servers": [{"tag": "dns", "address": "1.1.1.1"}]},
            "inbounds": [{"type": "tun", "tag": "tun-in"}],
            "outbounds": [
                {"type": "selector", "tag": "select", "outbounds": ["urltest", "direct"]},
                {"type": "urltest", "tag": "urltest", "outbounds": ["a", "b"]},
                {"type": "direct", "tag": "direct"},
                *outbounds,
            ],
        }
    )


def test_singbox_outbounds_are_converted() -> None:
    body = singbox(
        [
            {
                "type": "vless",
                "tag": "a",
                "server": "cdn.example",
                "server_port": 443,
                "uuid": UUID,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "sni.example",
                    "alpn": ["h2", "http/1.1"],
                    "utls": {"enabled": True, "fingerprint": "firefox"},
                },
                "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "front.example"}},
            },
            {"type": "vmess", "tag": "b", "server": "vm.example", "server_port": 80, "uuid": UUID},
            {
                "type": "trojan",
                "tag": "c",
                "server": "tro.example",
                "server_port": 443,
                "password": "pw",
            },
            {
                "type": "shadowsocks",
                "tag": "d",
                "server": "ss.example",
                "server_port": 8388,
                "method": "aes-256-gcm",
                "password": "sspw",
            },
            {
                "type": "hysteria2",
                "tag": "e",
                "server": "hy.example",
                "server_port": 443,
                "password": "x",
            },
        ]
    )
    servers, skipped = parse_subscription(body)
    assert [server.protocol for server in servers] == ["vless", "vmess", "trojan", "shadowsocks"]
    assert [server.address for server in servers] == [
        "cdn.example",
        "vm.example",
        "tro.example",
        "ss.example",
    ]
    assert any("hysteria2: unsupported protocol" in reason for reason in skipped)
    assert not any("selector" in reason or "urltest" in reason for reason in skipped)

    vless = servers[0].outbound
    user = vless["settings"]["vnext"][0]["users"][0]
    assert user == {"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}
    stream = vless["streamSettings"]
    assert stream["network"] == "ws"
    assert stream["security"] == "tls"
    assert stream["wsSettings"] == {"path": "/ws", "headers": {"Host": "front.example"}}
    assert stream["tlsSettings"] == {
        "serverName": "sni.example",
        "alpn": ["h2", "http/1.1"],
        "fingerprint": "firefox",
    }

    vmess = servers[1].outbound
    assert vmess["protocol"] == "vmess"
    assert vmess["settings"]["vnext"][0]["users"][0] == {
        "id": UUID,
        "alterId": 0,
        "security": "auto",
    }
    assert vmess["streamSettings"] == {"network": "tcp", "security": "none"}
    assert servers[2].outbound["settings"]["servers"][0]["password"] == "pw"
    assert servers[3].outbound["settings"]["servers"][0] == {
        "address": "ss.example",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "sspw",
    }


def test_singbox_reality_and_grpc() -> None:
    body = singbox(
        [
            {
                "type": "vless",
                "tag": "r",
                "server": "re.example",
                "server_port": 443,
                "uuid": UUID,
                "tls": {
                    "enabled": True,
                    "server_name": "cover.example",
                    "reality": {"enabled": True, "public_key": "PBK", "short_id": "abcd"},
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                },
                "transport": {"type": "grpc", "service_name": "svc", "mode": "multi"},
            }
        ]
    )
    servers, _ = parse_subscription(body)
    stream = servers[0].outbound["streamSettings"]
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["publicKey"] == "PBK"
    assert stream["realitySettings"]["shortId"] == "abcd"
    assert stream["realitySettings"]["serverName"] == "cover.example"
    assert stream["grpcSettings"] == {"serviceName": "svc", "multiMode": True}


def test_singbox_shadowsocks_plugin_is_reported() -> None:
    body = singbox(
        [
            {
                "type": "shadowsocks",
                "tag": "s",
                "server": "ss.example",
                "server_port": 8388,
                "method": "aes-128-gcm",
                "password": "pw",
                "plugin": "obfs-local",
            }
        ]
    )
    servers, skipped = parse_subscription(body)
    assert servers == []
    assert any("plugins are not supported" in reason for reason in skipped)


# ------------------------------------------------------------- base64 / format


def test_urlsafe_base64_link_list_is_decoded() -> None:
    links = "vless://a@one.example:80?type=ws#one\nvless://b@two.example:80#two"
    # a URL-safe body has '-' or '_' characters; force them through a long payload
    body = base64.urlsafe_b64encode(
        (links + "\nvless://c@three.example:80?path=/" + "x" * 40 + "#three").encode()
    ).decode().rstrip("=")
    assert "-" in body or "_" in body, "fixture must exercise the URL-safe alphabet"
    servers, skipped = parse_subscription(body)
    assert skipped == []
    assert [server.address for server in servers] == [
        "one.example",
        "two.example",
        "three.example",
    ]


def test_detect_format_names_every_shape() -> None:
    links = "vless://a@one.example:80#one"
    blob = base64.b64encode(links.encode()).decode()
    assert detect_format(blob) == "base64-links"
    assert detect_format(links) == "plain-links"
    assert detect_format(json.dumps([xray_config("x", [vless_outbound()])])) == "xray-json"
    assert detect_format(json.dumps(xray_config("x", [vless_outbound()]))) == "xray-json"
    assert detect_format(json.dumps([vless_outbound()])) == "xray-json"
    assert detect_format(singbox([])) == "sing-box-json"
    assert detect_format("proxies:\n  - name: a\n    type: vless\n") == "clash-yaml"
    assert detect_format("<!DOCTYPE html><html><title>403</title></html>") == "html"
    assert detect_format("") == "empty"
    assert detect_format("[not json") == "invalid-json"
    assert detect_format('{"hello": "world"}') == "json"
    assert detect_format("just some text") == "unknown"


def test_invalid_json_falls_back_to_link_parsing() -> None:
    # Not valid JSON (trailing comma), but a link sits on its own line.
    servers, skipped = parse_subscription('[{"broken": true},]\nvless://a@one.example:80#a')
    assert [server.address for server in servers] == ["one.example"]
    assert skipped == []


def test_singbox_config_with_only_selectors_is_detected() -> None:
    assert detect_format(singbox([])) == "sing-box-json"


def test_empty_body_is_reported() -> None:
    assert parse_subscription("   ") == ([], ["subscription body is empty"])


def test_route_summary_never_contains_credentials() -> None:
    body = json.dumps(xray_config("n", [vless_outbound()]))
    servers, _ = parse_subscription(body)
    dumped = str(servers[0].summary())
    assert UUID not in dumped
    assert "users" not in dumped


def test_server_chain_defaults_to_empty() -> None:
    server = Server("n", "vless", "a.example", 443, {"tag": "proxy", "protocol": "vless"})
    assert server.chain == []
    config = build_client_config(server, 1080)
    assert len(config["outbounds"]) == 2
