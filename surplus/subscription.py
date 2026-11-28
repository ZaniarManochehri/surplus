"""Subscription parsing and Xray client-config generation.

A subscription body may arrive in several shapes, and panels disagree about
which one to send (some even answer 403 to an unknown User-Agent), so every
shape below is understood and the panel's ordering is preserved - the tunnel
rotates through the routes exactly as subscribed:

- share links, plain or inside a base64 blob: ``vless://``, ``vmess://``,
  ``trojan://``, ``ss://``;
- Xray JSON: full client configs (``{"outbounds": [...], "remarks": ...}``, a
  list of them, or a bare list of outbounds) - the proxy outbounds are used
  verbatim, so nothing is lost in translation;
- sing-box JSON (``{"outbounds": [{"type": "vless", ...}]}``) - vless, vmess,
  trojan and shadowsocks outbounds are converted to Xray outbounds; types
  Xray cannot speak (hysteria2, tuic, ...) are reported as unsupported.

Secrets: links and configs carry server credentials (UUIDs, passwords). This
module never logs them; the only place they surface is the generated outbound
object and the credential-free summaries used by the admin API.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

LINK_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")
ANY_LINK = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Protocols Xray-core can run towards the marketplace; everything else is a
# utility outbound (direct, block, DNS) that is never a route.
ROUTE_PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")
UTILITY_PROTOCOLS = {
    "freedom",
    "blackhole",
    "dns",
    "loopback",
    "http",
    "socks",
    "socks5",
    "mtproto",
    "wireguard",
    "lut",
}


@dataclass
class Server:
    """One subscribed route: display metadata plus a ready Xray outbound.

    ``chain`` holds extra outbounds the main one depends on (``proxySettings``
    referencing a sibling by tag, e.g. a WireGuard hop); they are emitted after
    the route in the generated config so the reference keeps working.
    """

    name: str
    protocol: str
    address: str
    port: int
    outbound: dict
    chain: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        """Safe-to-display view: no credentials."""
        return {
            "name": self.name,
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
        }


_B64_TO_STANDARD = str.maketrans("-_", "+/")


def _decode_base64_text(compact: str) -> str | None:
    """Decode base64 (standard or URL-safe alphabet) to UTF-8 text, or None."""
    # One alphabet for both variants: map URL-safe characters onto the standard ones.
    standard = compact.translate(_B64_TO_STANDARD)
    padded = standard + "=" * (-len(standard) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    # Last resort: stray characters mixed into the blob - discard them.
    try:
        return base64.b64decode(padded, validate=False).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def decode_subscription(text: str) -> str:
    """Return the link list inside a subscription body.

    Panels answer with either plain links or a base64 blob of them; anything
    that already contains ``://`` is treated as plain text.
    """
    body = (text or "").strip()
    if not body or "://" in body:
        return body
    decoded = _decode_base64_text("".join(body.split()))
    return decoded if decoded and "://" in decoded else body


def extract_links(text: str) -> list[str]:
    """Every share-link line in a subscription body, in panel order.

    Recognizes any ``scheme://`` line (so unsupported protocols can be reported
    in the tunnel status instead of vanishing silently) except plain http(s),
    which panels use for metadata and messages rather than proxy links.
    """
    links = []
    for line in decode_subscription(text).splitlines():
        line = line.strip()
        if ANY_LINK.match(line) and not line.lower().startswith(("http://", "https://")):
            links.append(line)
    return links


def detect_format(text: str) -> str:
    """Name the shape of a subscription body (for status and diagnostics)."""
    body = (text or "").strip()
    if not body:
        return "empty"
    if body[0] in "[{":
        try:
            data = json.loads(body)
        except ValueError:
            return "invalid-json"
        # A full config has an "outbounds" list of objects. A sing-box
        # selector/urltest also has "outbounds", but as a list of tag strings.
        def is_config(item: object) -> bool:
            outbounds = item.get("outbounds") if isinstance(item, dict) else None
            return isinstance(outbounds, list) and all(
                isinstance(entry, dict) for entry in outbounds
            )

        flat: list = []
        if isinstance(data, list):
            for item in data:
                flat.extend(item["outbounds"] if is_config(item) else [item])
        elif is_config(data):
            flat = list(data["outbounds"])
        if flat and all(isinstance(item, dict) for item in flat):
            if any("type" in item and "protocol" not in item for item in flat):
                return "sing-box-json"
            if any("protocol" in item for item in flat):
                return "xray-json"
        return "json"
    head = body[:600].lower()
    if "<html" in head or "<!doctype html" in head:
        return "html"
    if re.search(r"(?m)^proxies:\s*$", body):
        return "clash-yaml"
    if extract_links(body):
        return "plain-links" if "://" in body else "base64-links"
    return "unknown"


def parse_subscription(text: str) -> tuple[list[Server], list[str]]:
    """Parse every usable route in a subscription body.

    Returns ``(servers, skipped_reasons)``. Links, Xray JSON and sing-box JSON
    are all accepted; one bad entry never discards the rest.
    """
    body = (text or "").strip()
    if not body:
        return [], ["subscription body is empty"]
    if body[0] in "[{":
        with contextlib.suppress(ValueError):
            return _parse_json(json.loads(body))
    servers: list[Server] = []
    skipped: list[str] = []
    for link in extract_links(body):
        scheme = link.split("://", 1)[0].lower()
        try:
            if scheme == "vless":
                servers.append(_parse_vless(link))
            elif scheme == "vmess":
                servers.append(_parse_vmess(link))
            elif scheme == "trojan":
                servers.append(_parse_trojan(link))
            elif scheme == "ss":
                servers.append(_parse_ss(link))
            else:
                skipped.append(f"{scheme}: unsupported protocol")
        except Exception as exc:  # noqa: BLE001 - one bad link must not kill the list
            skipped.append(f"{scheme}: {exc}")
    return servers, skipped


def build_client_config(server: Server, port: int) -> dict:
    """Xray client config: one local HTTP proxy inbound, one outbound.

    The router's httpx client speaks HTTP CONNECT to the loopback inbound, so
    no TUN device and no system proxy setting is involved anywhere.
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "router-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "http",
                "settings": {},
            }
        ],
        "outbounds": [
            dict(server.outbound),
            *(dict(outbound) for outbound in server.chain),
            {"tag": "blocked", "protocol": "blackhole"},
        ],
    }


# ---------------------------------------------------------------------- JSON


def _parse_json(data: object) -> tuple[list[Server], list[str]]:
    """Routes out of Xray JSON (configs, a list of configs, bare outbounds)."""
    servers: list[Server] = []
    skipped: list[str] = []
    configs: list[object]
    if isinstance(data, list) and data and all(
        isinstance(item, dict) and "protocol" in item and "outbounds" not in item
        for item in data
    ):
        configs = [{"outbounds": data}]  # a bare list of outbound objects
    else:
        configs = data if isinstance(data, list) else [data]

    for index, config in enumerate(configs):
        label = f"config #{index + 1}" if len(configs) > 1 else "config"
        if not isinstance(config, dict):
            skipped.append(f"{label}: not an object")
            continue
        outbounds = config.get("outbounds")
        if not isinstance(outbounds, list):
            skipped.append(f"{label}: no outbounds")
            continue
        name = str(config.get("remarks") or config.get("tag") or "").strip()
        before = len(skipped)
        found = 0
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            if "type" in outbound and "protocol" not in outbound:
                converted, reason = _singbox_to_xray(outbound)
                if converted is None:
                    if reason:
                        skipped.append(f"{label}: {reason}")
                    continue
                outbound = converted
            protocol = str(outbound.get("protocol") or "").lower()
            if not protocol or protocol in UTILITY_PROTOCOLS:
                continue
            if protocol not in ROUTE_PROTOCOLS:
                skipped.append(f"{label}: {protocol}: unsupported protocol")
                continue
            endpoint = _endpoint(protocol, outbound.get("settings") or {})
            if endpoint is None:
                skipped.append(f"{label}: {protocol} outbound has no address/port")
                continue
            address, port = endpoint
            route = dict(outbound)
            route["tag"] = "proxy"
            route_name = name or str(outbound.get("tag") or "")
            if found:
                route_name = f"{route_name} #{found + 1}".strip()
            servers.append(
                Server(
                    route_name,
                    protocol,
                    address,
                    port,
                    route,
                    chain=_chained_outbounds(outbound, outbounds),
                )
            )
            found += 1
        if not found and len(skipped) == before:
            skipped.append(f"{label}: no proxy outbound")
    return servers, skipped


def _endpoint(protocol: str, settings: dict) -> tuple[str, int] | None:
    """(address, port) of the first server/vnext entry in an Xray outbound."""
    if protocol in ("vless", "vmess"):
        entries = settings.get("vnext")
    else:
        entries = settings.get("servers")
    first = entries[0] if isinstance(entries, list) and entries else None
    if not isinstance(first, dict):
        return None
    address = str(first.get("address") or "").strip()
    try:
        port = int(first.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if not address or not 1 <= port <= 65535:
        return None
    return address, port


def _chained_outbounds(outbound: dict, outbounds: list) -> list[dict]:
    """Siblings the route depends on through ``proxySettings.tag``."""
    chain: list[dict] = []
    seen = {outbound.get("tag")}
    tag = (outbound.get("proxySettings") or {}).get("tag")
    while tag and tag not in seen:
        seen.add(tag)
        dependency = next(
            (
                item
                for item in outbounds
                if isinstance(item, dict) and item.get("tag") == tag
            ),
            None,
        )
        if dependency is None:
            break
        chain.append(dependency)
        tag = (dependency.get("proxySettings") or {}).get("tag")
    return chain


# ------------------------------------------------------------------ sing-box

SINGBOX_ROUTE_TYPES = {"vless", "vmess", "trojan", "shadowsocks"}
SINGBOX_IGNORED_TYPES = {
    "selector",
    "urltest",
    "direct",
    "block",
    "dns",
    "tun",
    "mixed",
    "socks",
    "http",
    "resolver",
}


def _singbox_to_xray(outbound: dict) -> tuple[dict | None, str | None]:
    """Convert one sing-box outbound; ``(None, reason)`` when it cannot run."""
    kind = str(outbound.get("type") or "").lower()
    if kind in SINGBOX_IGNORED_TYPES:
        return None, None
    if kind not in SINGBOX_ROUTE_TYPES:
        return None, f"{kind or 'unknown'}: unsupported protocol"
    host = str(outbound.get("server") or "").strip()
    try:
        port = int(outbound.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not host or not 1 <= port <= 65535:
        return None, f"{kind}: missing server or port"

    if kind in ("vless", "vmess"):
        user: dict = {"id": str(outbound.get("uuid") or "")}
        if kind == "vless":
            user["encryption"] = "none"
            if outbound.get("flow"):
                user["flow"] = str(outbound["flow"])
        else:
            try:
                user["alterId"] = int(outbound.get("alter_id") or 0)
            except (TypeError, ValueError):
                user["alterId"] = 0
            user["security"] = str(outbound.get("security") or "auto")
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif kind == "trojan":
        settings = {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "password": str(outbound.get("password") or ""),
                }
            ]
        }
    else:
        if outbound.get("plugin"):
            return None, "shadowsocks: plugins are not supported"
        settings = {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "method": str(outbound.get("method") or ""),
                    "password": str(outbound.get("password") or ""),
                }
            ]
        }

    converted: dict = {
        "tag": str(outbound.get("tag") or "proxy"),
        "protocol": kind,
        "settings": settings,
        "streamSettings": _singbox_stream(outbound, host),
    }
    if str(outbound.get("packet_encoding") or "") in ("xudp", "packetaddr"):
        converted["packetEncoding"] = str(outbound["packet_encoding"])
    return converted, None


def _singbox_stream(outbound: dict, host: str) -> dict:
    """sing-box ``transport`` + ``tls`` blocks -> an Xray streamSettings."""
    stream: dict = {"network": "tcp", "security": "none"}
    transport = outbound.get("transport") or {}
    kind = str(transport.get("type") or "tcp").lower()
    if kind == "ws":
        ws: dict = {"path": str(transport.get("path") or "/")}
        host_header = (transport.get("headers") or {}).get("Host")
        if host_header:
            ws["headers"] = {"Host": str(host_header)}
        stream["network"] = "ws"
        stream["wsSettings"] = ws
    elif kind == "http":
        path = transport.get("path")
        paths = [str(path)] if isinstance(path, str) else [str(p) for p in path or []]
        hosts = transport.get("host")
        host_list = (
            [str(hosts)] if isinstance(hosts, str) else [str(h) for h in hosts or []]
        )
        h2: dict = {"path": paths or ["/"]}
        if host_list:
            h2["host"] = host_list
        stream["network"] = "http"
        stream["httpSettings"] = h2
    elif kind == "grpc":
        grpc: dict = {"serviceName": str(transport.get("service_name") or "")}
        if str(transport.get("mode") or "").lower() == "multi":
            grpc["multiMode"] = True
        stream["network"] = "grpc"
        stream["grpcSettings"] = grpc
    elif kind == "quic":
        stream["network"] = "quic"
        stream["quicSettings"] = {"security": "none", "key": "", "header": {"type": "none"}}

    tls = outbound.get("tls") or {}
    if not tls.get("enabled"):
        return stream
    server_name = str(tls.get("server_name") or host)
    utls = tls.get("utls") or {}
    fingerprint = (
        str(utls.get("fingerprint") or "") if utls.get("enabled") else ""
    )
    reality = tls.get("reality") or {}
    if reality.get("enabled"):
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": server_name,
            "publicKey": str(reality.get("public_key") or ""),
            "shortId": str(reality.get("short_id") or ""),
            "fingerprint": fingerprint or "chrome",
            "spiderX": "/",
        }
        return stream
    settings: dict = {"serverName": server_name}
    if tls.get("insecure"):
        settings["allowInsecure"] = True
    if tls.get("alpn"):
        settings["alpn"] = [str(item) for item in tls["alpn"]]
    if fingerprint:
        settings["fingerprint"] = fingerprint
    stream["security"] = "tls"
    stream["tlsSettings"] = settings
    return stream


# --------------------------------------------------------------------- links


def _b64decode(data: str) -> bytes:
    compact = "".join(data.split())
    return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))


def _params(link: str) -> dict[str, str]:
    parsed = urlparse(link)
    return {key: values[0] for key, values in parse_qs(parsed.query).items()}


def _fragment_name(link: str) -> str:
    try:
        return unquote(urlparse(link).fragment).strip()
    except ValueError:
        return ""


def _split_hostport(value: str) -> tuple[str, int]:
    host, sep, port_text = value.rpartition(":")
    if not sep:
        raise ValueError("missing port")
    host = host.strip("[]").strip()
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    if not host or not 1 <= port <= 65535:
        raise ValueError("invalid address")
    return host, port


def _stream_settings(
    params: dict[str, str], network: str, security: str, address: str
) -> dict:
    """Map share-link parameters onto an Xray streamSettings object."""
    stream: dict = {"network": network, "security": security}
    if network == "ws":
        ws: dict = {"path": params.get("path") or "/"}
        host = params.get("host")
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict = {
            "serviceName": params.get("serviceName") or params.get("path") or ""
        }
        if params.get("mode") == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc
    elif network in {"h2", "http"}:
        h2: dict = {"path": params.get("path") or "/"}
        host = params.get("host")
        if host:
            h2["host"] = [part.strip() for part in host.split(",") if part.strip()]
        stream["httpSettings"] = h2
    elif network == "tcp" and params.get("headerType") == "http":
        request: dict = {"path": [params.get("path") or "/"]}
        host = params.get("host")
        if host:
            request["headers"] = {"Host": [host]}
        stream["tcpSettings"] = {"header": {"type": "http", "request": request}}

    if security == "tls":
        tls: dict = {"serverName": params.get("sni") or params.get("host") or address}
        if params.get("alpn"):
            tls["alpn"] = [
                part.strip() for part in params["alpn"].split(",") if part.strip()
            ]
        if params.get("fp"):
            tls["fingerprint"] = params["fp"]
        if str(params.get("allowInsecure", "")).lower() in {"1", "true", "yes"}:
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni") or address,
            "publicKey": params.get("pbk") or "",
            "shortId": params.get("sid") or "",
            "fingerprint": params.get("fp") or "chrome",
            "spiderX": params.get("spx") or "/",
        }
    return stream


def _parse_vless(link: str) -> Server:
    parsed = urlparse(link)
    user_id = unquote(parsed.username or "")
    if not user_id:
        raise ValueError("missing id")
    if not parsed.hostname or not parsed.port:
        raise ValueError("missing address")
    params = _params(link)
    network = (params.get("type") or "tcp").lower()
    if network == "raw":
        network = "tcp"
    security = (params.get("security") or "none").lower()

    user: dict = {"id": user_id}
    # Post-quantum VLESS encryption values (e.g. mlkem768x25519plus...) must be
    # passed through verbatim; Xray decides how to negotiate them.
    user["encryption"] = params.get("encryption") or "none"
    if params.get("flow"):
        user["flow"] = params["flow"]

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {"address": parsed.hostname, "port": parsed.port, "users": [user]}
            ]
        },
        "streamSettings": _stream_settings(params, network, security, parsed.hostname),
    }
    return Server(
        name=_fragment_name(link),
        protocol="vless",
        address=parsed.hostname,
        port=parsed.port,
        outbound=outbound,
    )


def _parse_vmess(link: str) -> Server:
    try:
        data = json.loads(_b64decode(link.split("://", 1)[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid vmess payload") from exc
    address = str(data.get("add") or "").strip()
    user_id = str(data.get("id") or "").strip()
    try:
        port = int(data.get("port") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not address or not user_id or not 1 <= port <= 65535:
        raise ValueError("missing add/port/id")

    network = str(data.get("net") or "tcp").lower()
    if network == "raw":
        network = "tcp"
    params = {
        "path": str(data.get("path") or ""),
        "host": str(data.get("host") or ""),
        "sni": str(data.get("sni") or ""),
        "serviceName": str(data.get("path") or ""),
        "alpn": str(data.get("alpn") or ""),
    }
    security = "tls" if str(data.get("tls") or "").lower() == "tls" else "none"
    outbound = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": user_id,
                            "alterId": int(data.get("aid") or 0),
                            "security": str(data.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": _stream_settings(params, network, security, address),
    }
    name = str(data.get("ps") or "").strip() or f"vmess-{address}"
    return Server(name=name, protocol="vmess", address=address, port=port, outbound=outbound)


def _parse_trojan(link: str) -> Server:
    parsed = urlparse(link)
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("missing password")
    if not parsed.hostname or not parsed.port:
        raise ValueError("missing address")
    params = _params(link)
    network = (params.get("type") or "tcp").lower()
    if network == "raw":
        network = "tcp"
    security = (params.get("security") or "tls").lower()
    outbound = {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [
                {"address": parsed.hostname, "port": parsed.port, "password": password}
            ]
        },
        "streamSettings": _stream_settings(params, network, security, parsed.hostname),
    }
    return Server(
        name=_fragment_name(link),
        protocol="trojan",
        address=parsed.hostname,
        port=parsed.port,
        outbound=outbound,
    )


def _parse_ss(link: str) -> Server:
    body = link.split("://", 1)[1].split("#", 1)[0]
    if "?" in body:
        body, query = body.split("?", 1)
        if "plugin=" in query:
            raise ValueError("Shadowsocks plugins are not supported")
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            # Base64 userinfo: "base64(method:password)@host:port".
            method, _, password = _b64decode(userinfo).decode("utf-8").partition(":")
    else:
        # Legacy form: "base64(method:password@host:port)".
        userinfo, _, hostport = (
            _b64decode(body).decode("utf-8").rpartition("@")
        )
        method, _, password = userinfo.partition(":")
    if not method or not password:
        raise ValueError("invalid Shadowsocks credentials")
    address, port = _split_hostport(hostport)
    outbound = {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "method": method,
                    "password": password,
                }
            ]
        },
    }
    return Server(
        name=_fragment_name(link),
        protocol="ss",
        address=address,
        port=port,
        outbound=outbound,
    )