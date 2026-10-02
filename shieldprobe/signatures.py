"""Anti-bot type signature library.

Each signature describes a *family* of dynamic anti-bot protection and the
observable indicators that let us recognize it. Recognition is purely
fingerprint-based (status codes, cookie shapes, JS markers, env probes) —
this module *identifies* a protection, it does not defeat one.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Signature:
    """A recognizable family of dynamic anti-bot protection."""

    id: str
    name: str
    description: str
    # Observable indicators.
    status_codes: tuple[int, ...] = ()
    cookie_name_patterns: tuple[str, ...] = ()      # exact or prefix match
    random_cookie_name: bool = False                 # random-looking cookie name
    html_markers: tuple[str, ...] = ()               # e.g. meta[r='m']
    js_markers: tuple[str, ...] = ()                 # e.g. $_ts, while(1)
    dynamic_script_regex: Optional[str] = None       # random-path dynamic JS
    env_probes: tuple[str, ...] = ()                 # expected env fingerprint probes
    meta_refresh: bool = False                       # JS/meta reload challenge

    def score(self, evidence: "Evidence") -> tuple[int, int]:
        """Return (matched, total) indicator score for the given evidence."""
        matched, total = 0, 0
        checks: list[Callable[[], bool]] = []

        if self.status_codes:
            checks.append(lambda: evidence.status_code in self.status_codes)
        if self.cookie_name_patterns:
            checks.append(
                lambda: any(
                    n.startswith(self.cookie_name_patterns)
                    or n in self.cookie_name_patterns
                    for n in evidence.set_cookie_names
                )
            )
        if self.random_cookie_name:
            checks.append(lambda: evidence.has_random_cookie_name)
        if self.html_markers:
            checks.append(
                lambda: any(m in evidence.html for m in self.html_markers)
            )
        if self.js_markers:
            checks.append(
                lambda: any(m in evidence.js for m in self.js_markers)
            )
        if self.dynamic_script_regex:
            checks.append(lambda: evidence.has_dynamic_script)
        if self.meta_refresh:
            checks.append(lambda: evidence.has_meta_refresh)

        for check in checks:
            total += 1
            if check():
                matched += 1
        return matched, total


@dataclass
class Evidence:
    """Collected observations about a single target request."""

    status_code: int = 0
    set_cookie_names: list[str] = field(default_factory=list)
    html: str = ""
    js: str = ""
    dynamic_scripts: list[str] = field(default_factory=list)
    env_probes: list[str] = field(default_factory=list)

    @property
    def has_random_cookie_name(self) -> bool:
        # Random-looking cookie name: pure alphanumeric (no `_`/`-`), 10–24 chars,
        # mixed case AND at least one digit — e.g. "4hP44ZykCTt5O".
        import re

        return any(
            re.fullmatch(r"[A-Za-z0-9]{10,24}", n)
            and re.search(r"[A-Z]", n)
            and re.search(r"[a-z]", n)
            and re.search(r"[0-9]", n)
            for n in self.set_cookie_names
        )

    @property
    def has_dynamic_script(self) -> bool:
        return bool(self.dynamic_scripts)

    @property
    def has_meta_refresh(self) -> bool:
        return ("http-equiv=\"refresh\"" in self.html.lower()
                or "window.location" in self.js)


SIGNATURES: list[Signature] = [
    Signature(
        id="vm-js-challenge",
        name="VM-based JS challenge (RiverSecurity-family)",
        description=(
            "First request is rejected with 412, the body is a self-decrypting "
            "JS that runs a custom bytecode VM (while(1) dispatch), collects "
            "environment fingerprints, writes a cookie via document.cookie, "
            "then reloads the page to a 200."
        ),
        status_codes=(412,),
        random_cookie_name=True,
        html_markers=("<meta r='m'>",),
        js_markers=("$_ts", "while(1)", "_$"),
        dynamic_script_regex=r"/[A-Za-z0-9]{10,}/[A-Za-z0-9]+\.[0-9a-f]+\.js",
        env_probes=("webdriver", "canvas", "Function", "Proxy", "queueMicrotask"),
    ),
    Signature(
        id="cloudflare-js-challenge",
        name="Cloudflare JS challenge",
        description=(
            "503 response with a 'checking your browser' interstitial and a "
            "cf_clearance cookie issued after a 5-second JS challenge."
        ),
        status_codes=(503,),
        cookie_name_patterns=("__cf_bm", "cf_clearance", "__cfduid"),
        html_markers=("checking your browser", "cf-challenge"),
        js_markers=("setTimeout", "cf-chl"),
    ),
    Signature(
        id="akamai-bot-manager",
        name="Akamai Bot Manager sensor",
        description=(
            "Page sets _abck / bm_sz cookies and submits a sensor_data payload "
            "that encodes browser behaviour and environment telemetry."
        ),
        cookie_name_patterns=("_abck", "bm_sz", "bm_sv"),
        js_markers=("sensor_data", "_abck"),
        env_probes=("webdriver", "plugins", "screen", "navigator"),
    ),
    Signature(
        id="generic-meta-refresh",
        name="Generic meta-refresh / JS redirect challenge",
        description=(
            "A Set-Cookie + meta refresh (or window.location) redirect that "
            "re-issues the request with the cookie attached. The simplest "
            "cookie-gate pattern."
        ),
        meta_refresh=True,
        random_cookie_name=True,
    ),
]


def detect(evidence: Evidence, threshold: float = 0.6) -> list[tuple[Signature, float]]:
    """Return signatures that match the evidence above a confidence threshold."""
    hits: list[tuple[Signature, float]] = []
    for sig in SIGNATURES:
        matched, total = sig.score(evidence)
        if total == 0:
            continue
        confidence = matched / total
        if confidence >= threshold:
            hits.append((sig, round(confidence, 2)))
    hits.sort(key=lambda x: -x[1])
    return hits


def list_signatures() -> list[Signature]:
    """All known signatures (for the CLI ``list`` command)."""
    return list(SIGNATURES)
