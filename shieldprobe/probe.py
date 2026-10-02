"""Probe engine: turn a target URL into an anti-bot analysis report.

Two tiers:

* ``probe_http`` — a lightweight pass that never launches a browser. It reads
  status code, Set-Cookie names, and greps the body for the JS/HTML markers
  that a challenge page leaves behind.
* ``probe_browser`` — a deeper pass that drives a real browser (offscreen
  window) to record the request chain (e.g. 412 -> dynamic JS -> 200) and the
  environment fingerprint probes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import requests

from .signatures import Evidence, detect
from .fingerprints import FINGERPRINTS

# A dynamic JS path looks like /AbCdEf0123/xYz.1a2b3c.js — random dir, random
# file, fixed short hash before .js.
_DYNAMIC_SCRIPT = re.compile(r"/[A-Za-z0-9]{10,}/[A-Za-z0-9]+\.[0-9a-f]{5,8}\.js")


@dataclass
class ProbeResult:
    """Structured result of a probe."""

    url: str
    status_code: int = 0
    set_cookie_names: list[str] = field(default_factory=list)
    dynamic_scripts: list[str] = field(default_factory=list)
    html_markers: list[str] = field(default_factory=list)
    js_markers: list[str] = field(default_factory=list)
    detected: list[str] = field(default_factory=list)   # signature ids
    confidence: list[str] = field(default_factory=list) # human-readable conf
    request_chain: list[str] = field(default_factory=list)
    env_probes_seen: list[str] = field(default_factory=list)
    error: Optional[str] = None


_HTML_MARKERS = ("<meta r='m'>", "checking your browser", "cf-challenge")
_JS_MARKERS = ("$_ts", "while(1)", "sensor_data", "window.location", "setTimeout")


def probe_http(url: str, timeout: int = 20, user_agent: Optional[str] = None) -> ProbeResult:
    """Lightweight, browser-less probe of a target URL."""
    res = ProbeResult(url=url)
    headers = {"User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=False)
    except requests.RequestException as e:
        res.error = str(e)
        return res

    res.status_code = resp.status_code
    res.set_cookie_names = [c.name for c in resp.cookies] or _parse_set_cookie(resp)
    body = resp.text

    res.dynamic_scripts = _DYNAMIC_SCRIPT.findall(body)
    res.html_markers = [m for m in _HTML_MARKERS if m in body]
    res.js_markers = [m for m in _JS_MARKERS if m in body]

    evidence = Evidence(
        status_code=res.status_code,
        set_cookie_names=res.set_cookie_names,
        html=body,
        js=body,
        dynamic_scripts=res.dynamic_scripts,
    )
    for sig, conf in detect(evidence, threshold=0.5):
        res.detected.append(sig.id)
        res.confidence.append(f"{sig.name} ({conf:.0%})")
    return res


def probe_browser(url: str, user_agent: Optional[str] = None) -> ProbeResult:
    """Deep probe that drives a real browser and records the request chain."""
    res = ProbeResult(url=url)
    try:
        from .stealth import ShieldSession
    except Exception as e:  # playwright not installed
        res.error = f"browser probe unavailable: {e}"
        return res

    chain: list[str] = []
    with ShieldSession(offscreen=True) as sess:
        page = sess.page
        page.on("response", lambda r: chain.append(f"{r.status} {r.url}"))
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            res.error = str(e)
            return res
        # Wait for a challenge to resolve, if one is running.
        try:
            page.wait_for_function(
                "() => !document.querySelector(\"meta[r='m']\")", timeout=15000
            )
        except Exception:
            pass

        res.request_chain = [c for c in chain if url.split("/")[2] in c]
        res.status_code = 200  # we reached the real page
        # Record which env fingerprint probes the challenge performed.
        seen = []
        for fp in FINGERPRINTS:
            probe_id = fp.id.split(".")[0]
            for c in chain:
                if probe_id.lower() in c.lower():
                    seen.append(fp.id)
                    break
        res.env_probes_seen = seen
    return res


def _parse_set_cookie(resp: requests.Response) -> list[str]:
    """Fallback: pull cookie names from raw Set-Cookie headers."""
    names: list[str] = []
    for raw in resp.headers.get_all("Set-Cookie", []) if hasattr(resp.headers, "get_all") else []:
        names.append(raw.split("=", 1)[0].strip())
    if not names:
        for h in resp.headers.get("Set-Cookie", "").split(","):
            names.append(h.split("=", 1)[0].strip().lstrip(" "))
    return [n for n in names if n]


def format_report(res: ProbeResult) -> str:
    """Render a ProbeResult as a terminal-friendly report."""
    lines: list[str] = []
    lines.append("=" * 62)
    lines.append(f"ShieldProbe report — {res.url}")
    lines.append("=" * 62)
    if res.error:
        lines.append(f"[!] probe failed: {res.error}")
        return "\n".join(lines)

    lines.append(f"HTTP status     : {res.status_code}")
    lines.append(f"Set-Cookie      : {', '.join(res.set_cookie_names) or '(none)'}")
    if res.dynamic_scripts:
        lines.append(f"Dynamic scripts : {len(res.dynamic_scripts)} found")
        for s in res.dynamic_scripts[:3]:
            lines.append(f"    {s}")
    if res.html_markers:
        lines.append(f"HTML markers    : {', '.join(res.html_markers)}")
    if res.js_markers:
        lines.append(f"JS markers      : {', '.join(res.js_markers)}")
    if res.request_chain:
        lines.append("Request chain   :")
        for c in res.request_chain:
            lines.append(f"    {c}")

    lines.append("")
    if res.detected:
        lines.append("Detected protection:")
        for d in res.detected:
            lines.append(f"  [*] {d}")
        for c in res.confidence:
            lines.append(f"      {c}")
    else:
        lines.append("Detected protection: none (no known signature matched)")

    if res.env_probes_seen:
        lines.append(f"Env probes seen : {', '.join(res.env_probes_seen)}")
    return "\n".join(lines)
