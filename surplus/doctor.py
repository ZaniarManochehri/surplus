"""Environment diagnostics: ``surplus doctor``.

Answers the two support questions that otherwise take a long back-and-forth -
"the browser did not open" and "my subscription does not connect" - in one
run: config, API key, ambient proxy variables, direct reachability, DNS,
subscription fetch and parsing, the Xray binary, and a real tunnel attempt
with a probe through it.

Nothing secret is printed: the API key, the subscription URL and share links
are only ever shown masked (host names are fine, paths and tokens are not).

CLI output is English, per the project rules.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import os
import platform
import shutil
import socket
import sys
import time
from collections import Counter
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import __version__
from .config import (
    AppConfig,
    ProxyConfig,
    load_config,
    mask_key,
    mask_secret_url,
    normalize_proxy_url,
    resolve_api_key,
    user_config_dir,
)
from .subscription import extract_links, parse_subscription
from .tunnel import SUBSCRIPTION_USER_AGENT, Tunnel

NAME_WIDTH = 13
PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
SUPPORTED_PROTOCOLS = ("vless", "vmess", "trojan", "ss")

# Resolver answers that some national filters return for blocked names; no real
# CDN front ever lives in these ranges.
FILTERED_IP_PREFIXES = ("10.10.34.", "10.10.35.", "10.202.10.")
AMBIENT_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy")


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []
        self.hints: list[str] = []
        self.facts: dict[str, object] = {}

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.rows.append((status, name, detail))
        print(f"{status:<5} {name:<{NAME_WIDTH}} {detail}".rstrip())

    def hint(self, text: str) -> None:
        if text not in self.hints:
            self.hints.append(text)

    @property
    def failed(self) -> int:
        return sum(1 for status, _, _ in self.rows if status == FAIL)


def _xray_binary_name() -> str:
    return "xray.exe" if os.name == "nt" else "xray"


async def _direct_probe(base_url: str, proxy: str | None) -> tuple[bool, str]:
    """One GET to the marketplace. Any HTTP answer means the path works."""
    timeout = httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=10.0)
    kwargs: dict = {"proxy": proxy, "trust_env": False} if proxy else {"trust_env": False}
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, **kwargs) as client:
            response = await client.get(f"{base_url.rstrip('/')}/v1/models")
    except Exception as exc:  # noqa: BLE001 - the error text is the diagnosis
        return False, f"{type(exc).__name__}: {_short(exc)}"
    ms = int((time.perf_counter() - started) * 1000)
    return True, f"HTTP {response.status_code} in {ms} ms"


def _short(exc: BaseException, limit: int = 150) -> str:
    text = " ".join(str(exc).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _looks_filtered(ip: str) -> bool:
    return ip.startswith(FILTERED_IP_PREFIXES)


async def _check_clock(report: Report, response: httpx.Response | None) -> None:
    """TLS fails silently when the system clock is far off; check against Date."""
    raw = response.headers.get("date") if response is not None else None
    if not raw:
        return
    try:
        remote = parsedate_to_datetime(raw).timestamp()
    except (TypeError, ValueError):
        return
    skew = abs(time.time() - remote)
    if skew > 300:
        report.add(
            FAIL,
            "clock",
            f"system clock is {skew / 60:.0f} minutes off (TLS handshakes will fail)",
        )
        report.hint("Fix the Windows date/time (set it automatically), then retry.")
    else:
        report.add(PASS, "clock", f"within {skew:.0f} s of server time")


async def run(config_path: Path | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):  # old consoles, redirected pipes
            stream.reconfigure(errors="replace")

    print(f"Surplus Router doctor  v{__version__}\n")
    report = Report()

    # ---------------------------------------------------------- environment
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 11):
        report.add(PASS, "python", f"{platform.python_version()} on {platform.system()}")
    else:
        report.add(FAIL, "python", f"{platform.python_version()} - 3.11 or newer is required")

    path = config_path or Path("config.ini")
    if path.exists():
        report.add(PASS, "config file", str(path))
    else:
        report.add(
            FAIL,
            "config file",
            f"{path} does not exist - run `surplus` once to create it",
        )
    cfg = load_config(path) if path.exists() else AppConfig(config_path=path)
    report.facts["config_path"] = str(path)

    key, key_source = resolve_api_key(cfg)
    if key:
        report.add(PASS, "api key", f"source={key_source} {mask_key(key)}")
    else:
        report.add(
            WARN,
            "api key",
            "not set - chat requests will answer 503 until it is configured",
        )

    ambient = [
        f"{name}={os.environ[name]}"
        for name in AMBIENT_PROXY_VARS
        if os.environ.get(name)
    ]
    if ambient:
        report.add(
            WARN,
            "env proxies",
            f"{len(ambient)} set ({', '.join(n.split('=')[0] for n in ambient)}) - "
            "direct connections will go through them",
        )
    else:
        report.add(PASS, "env proxies", "none set")

    host = cfg.server.host
    dialable = "127.0.0.1" if host in {"0.0.0.0", "::", "", "*"} else host
    if cfg.server.port and _port_open(dialable, cfg.server.port):
        report.add(
            INFO,
            "router port",
            f"{cfg.server.port} is already listening (a router instance is running)",
        )

    proxy_cfg = cfg.proxy
    report.add(
        INFO,
        "proxy tunnel",
        f"{'enabled' if proxy_cfg.enabled else 'disabled'}, mode={proxy_cfg.mode}",
    )

    # ------------------------------------------------------ direct reachability
    upstream = cfg.upstream.base_url
    upstream_host = urlparse(upstream).hostname or ""
    try:
        infos = socket.getaddrinfo(upstream_host, 443, type=socket.SOCK_STREAM)
        addresses = sorted({info[4][0] for info in infos})
        shown = ", ".join(addresses[:3]) + (" ..." if len(addresses) > 3 else "")
        if any(_looks_filtered(ip) for ip in addresses):
            report.add(WARN, "dns", f"{upstream_host} -> {shown} (answer looks filtered)")
        else:
            report.add(PASS, "dns", f"{upstream_host} -> {shown}")
    except OSError as exc:
        report.add(FAIL, "dns", f"{upstream_host}: {type(exc).__name__}")
        report.hint(
            "DNS cannot resolve the marketplace. Set the system DNS to 1.1.1.1 / 8.8.8.8, "
            "or keep the tunnel enabled (it resolves names remotely)."
        )

    direct_ok, direct_detail = await _direct_probe(upstream, None)
    report.facts["direct_ok"] = direct_ok
    report.add(
        PASS if direct_ok else WARN,
        "direct route",
        direct_detail if direct_ok else f"unreachable ({direct_detail})",
    )

    # ------------------------------------------------------------- the tunnel
    if proxy_cfg.mode == "external":
        await _check_external(report, cfg, proxy_cfg, upstream)
    else:
        await _check_managed(report, cfg, proxy_cfg, upstream)

    # ---------------------------------------------------------------- verdict
    print()
    tunnel_state = report.facts.get("tunnel_state")
    if report.failed:
        print(f"{report.failed} check(s) FAILED.")
    else:
        print("No failing checks.")
    if tunnel_state == "up":
        print("The tunnel works on this machine: Surplus is reachable through it.")
    elif report.facts.get("direct_ok"):
        print("Surplus is reachable directly here; the tunnel is optional.")
    for line in report.hints:
        print(f"  -> {line}")
    return 1 if report.failed else 0


# ------------------------------------------------------------------ external


async def _check_external(
    report: Report, cfg: AppConfig, proxy: ProxyConfig, upstream: str
) -> None:
    url = normalize_proxy_url(proxy.proxy_url)
    if not url:
        report.add(FAIL, "proxy url", "empty or not http/socks5 - set [proxy] proxy_url")
        return
    parsed = urlparse(url)
    host, port = parsed.hostname or "", parsed.port or (1080 if "socks" in url else 80)
    if _port_open(host, port):
        report.add(PASS, "proxy port", f"{host}:{port} accepts connections")
    else:
        report.add(
            FAIL,
            "proxy port",
            f"{host}:{port} refuses connections - is the VPN client running in "
            "proxy-only mode on this port?",
        )
        report.hint(
            "Open your VPN client, enable only its local proxy (no TUN / system proxy) "
            "and copy the exact port from its settings."
        )
        return
    ok, detail = await _direct_probe(upstream, url)
    report.facts["tunnel_state"] = "up" if ok else "down"
    report.add(
        PASS if ok else FAIL,
        "via proxy",
        detail if ok else f"no answer through the proxy ({detail})",
    )
    if not ok:
        report.hint(
            "The local proxy answers but cannot reach Surplus; "
            "check the VPN client's server."
        )


# ------------------------------------------------------------------- managed


async def _check_managed(
    report: Report, cfg: AppConfig, proxy: ProxyConfig, upstream: str
) -> None:
    sub_url = proxy.subscription_url.strip()
    raw_links = proxy.subscription_links.strip()
    if not sub_url and not raw_links:
        report.add(
            FAIL,
            "subscription",
            "none configured - set [proxy] subscription_url or paste raw links",
        )
        return

    text = ""
    if sub_url:
        text = await _fetch_subscription(report, sub_url)
    if not text and raw_links:
        report.add(INFO, "subscription", "using raw links from subscription_links")
        text = raw_links

    if text:
        links = extract_links(text)
        protocols = Counter(link.split("://", 1)[0].lower() for link in links)
        shown = ", ".join(f"{name} x{count}" for name, count in protocols.most_common())
        if links:
            report.add(PASS, "link types", shown)
        else:
            report.add(FAIL, "link types", "no share links found in the subscription")
        servers, skipped = parse_subscription(text)
        unsupported = sorted(
            {reason.split(":", 1)[0] for reason in skipped if "unsupported protocol" in reason}
        )
        report.add(
            PASS if servers else FAIL,
            "usable links",
            f"{len(servers)} of {len(links)} usable"
            + (f"; skipped: {'; '.join(skipped[:3])}" if skipped else ""),
        )
        if not servers:
            report.hint(
                "None of these links can be used here. Xray-core speaks "
                f"{', '.join(SUPPORTED_PROTOCOLS)} - ask the provider for a VLESS link, "
                "or paste one into subscription_links."
            )
        elif unsupported:
            report.hint(f"Ignored unsupported protocol(s): {', '.join(unsupported)}.")

    # ---------------------------------------------------------- xray binary
    holder: dict[str, ProxyConfig] = {"cfg": proxy}
    router_binary = user_config_dir() / "xray" / _xray_binary_name()
    test_cfg = dataclasses.replace(proxy)
    if not test_cfg.xray_binary and router_binary.exists():
        # Reuse the router's binary but never its workdir: the doctor must not
        # touch a running router's config.json, pid file or xray process.
        test_cfg.xray_binary = str(router_binary)
    holder["cfg"] = test_cfg

    def provider() -> ProxyConfig:
        return holder["cfg"]

    probe = Tunnel(provider, upstream, workdir=user_config_dir() / "xray-doctor")
    binary = await probe._ensure_binary(test_cfg)  # diagnostic: same lookup the router uses
    if binary is None:
        report.add(FAIL, "xray binary", probe.status()["last_error"] or "not available")
        if shutil.which("xray") is None and not router_binary.exists():
            report.hint(
                "Xray-core could not be downloaded (github.com is often blocked). "
                "Put xray(.exe) on the PATH, or install it anywhere and set "
                "[proxy] xray_binary to its full path."
            )
        return
    version = probe.status()["xray"]["version"] or "unknown"
    report.add(PASS, "xray binary", f"{version} ({binary})")

    # ------------------------------------------------------- live tunnel test
    print("\nStarting a test tunnel (this can take up to a minute) ...")
    state = "error"
    try:
        state = await asyncio.wait_for(probe.apply(), timeout=180.0)
    except TimeoutError:
        report.add(FAIL, "tunnel test", "timed out after 180 s")
    except Exception as exc:  # noqa: BLE001 - the diagnosis IS the exception
        report.add(FAIL, "tunnel test", f"{type(exc).__name__}: {_short(exc)}")
    finally:
        status = probe.status()
        with contextlib.suppress(Exception):
            await probe.stop()

    report.facts["tunnel_state"] = status.get("state")
    if state == "up":
        latency = (status.get("health") or {}).get("latency_ms")
        route = status.get("route")
        report.add(PASS, "tunnel test", f"route {route} answered in {latency} ms")
        return

    last_error = status.get("last_error") or "no route answered"
    report.add(FAIL, "tunnel test", _short(last_error, 160))
    for line in (status.get("xray") or {}).get("log_tail") or []:
        print(f"      xray> {line}")
    lowered = last_error.lower()
    if "permissionerror" in lowered or "winerror 5" in lowered or "did not listen" in lowered:
        report.hint(
            "xray.exe starts but cannot run: an antivirus / SmartScreen rule is probably "
            "blocking the downloaded binary. Allow it, or set [proxy] xray_binary to a "
            "copy you installed yourself."
        )
    if "probe failed" in lowered or "connecttimeout" in lowered or "proxyerror" in lowered:
        report.hint(
            "Xray runs, but none of the subscribed routes reaches Surplus from this "
            "network. Try another subscription, another network (e.g. mobile hotspot), "
            "and make sure the system clock is correct."
        )


async def _fetch_subscription(report: Report, url: str) -> str:
    host = urlparse(url).netloc
    report.add(INFO, "subscription", f"host {host} ({mask_secret_url(url)})")
    timeout = httpx.Timeout(connect=10.0, read=25.0, write=10.0, pool=10.0)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, trust_env=False
        ) as client:
            response = await client.get(url, headers={"User-Agent": SUBSCRIPTION_USER_AGENT})
    except Exception as exc:  # noqa: BLE001
        report.add(
            FAIL, "subscription", f"{host} unreachable: {type(exc).__name__}: {_short(exc)}"
        )
        report.hint(
            "The subscription address itself is not reachable from this network. "
            "Open it in a browser on the same machine; if that fails too, the panel "
            "is blocked here - paste raw links into subscription_links instead."
        )
        return ""
    report.add(
        PASS if response.status_code == 200 else FAIL,
        "subscription",
        f"HTTP {response.status_code}, {len(response.content)} bytes",
    )
    if response.status_code == 200:
        await _check_clock(report, response)
        return response.text
    if response.status_code in (401, 403, 404, 410):
        report.hint("The panel answered but refused: the subscription link is invalid or expired.")
    return ""


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    from .config import resolve_config_path

    raise SystemExit(asyncio.run(run(resolve_config_path())))
