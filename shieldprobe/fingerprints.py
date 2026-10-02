"""Environment fingerprint checkpoints observed in the wild.

Dynamic anti-bot JS does not only compute a cookie — first it probes the
browser environment to decide whether the visitor is a real user. This module
catalogues the checkpoints we have actually observed (from trace data) together
with *why* each one is checked and how it is usually probed.

This is analysis knowledge: it tells you what a protection looks at, so you
know what a headless/browserless environment must reproduce.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Fingerprint:
    """One environment checkpoint that anti-bot JS inspects."""

    id: str
    category: str
    purpose: str
    probe_method: str
    # What a faithful reproduction must provide.
    reproduce_hint: str


FINGERPRINTS: list[Fingerprint] = [
    Fingerprint(
        id="navigator.webdriver",
        category="automation-detection",
        purpose="Detect Selenium/Playwright/puppeteer automation flag.",
        probe_method="Object.getOwnPropertyDescriptor on both the instance and "
                     "the prototype, checking the descriptor kind (accessor vs value).",
        reproduce_hint="Must be absent on the instance and present as a native "
                       "getter on Navigator.prototype — a plain value fails.",
    ),
    Fingerprint(
        id="canvas",
        category="device-fingerprint",
        purpose="Render text/shapes and hash the pixels; differs across GPU/driver.",
        probe_method="canvas.getContext('2d') + fillText + toDataURL.",
        reproduce_hint="Requires a real 2D rasterizer; stubbed canvas produces a "
                       "detectably uniform hash.",
    ),
    Fingerprint(
        id="webgl",
        category="device-fingerprint",
        purpose="Read renderer/vendor via WebGL, another hardware fingerprint.",
        probe_method="canvas.getContext('webgl').getParameter(...).",
        reproduce_hint="Real WebGL context or a faithful vendor string table.",
    ),
    Fingerprint(
        id="function-constructor",
        category="environment-integrity",
        purpose="Check Function.name / Function.prototype.toString / constructor "
                "identity for signs of an environment-patched (headless) runtime.",
        probe_method="Repeated touches of the Function constructor and its prototype.",
        reproduce_hint="Function must be the pristine native constructor; any proxy "
                       "or renamed wrapper is a red flag.",
    ),
    Fingerprint(
        id="proxy-queueMicrotask",
        category="environment-integrity",
        purpose="Detect whether Proxy / queueMicrotask have been monkey-patched "
                "by a stealth or environment-patching layer.",
        probe_method="getOwnPropertyDescriptor over Proxy and queueMicrotask.",
        reproduce_hint="Native, unmodified built-ins.",
    ),
    Fingerprint(
        id="screen",
        category="display-fingerprint",
        purpose="Read screen resolution / color depth; headless defaults differ.",
        probe_method="screen.width/height/colorDepth reads.",
        reproduce_hint="Report a plausible physical display, not the headless "
                       "default (800x600 or 0).",
    ),
    Fingerprint(
        id="timer-behaviour",
        category="behavioural",
        purpose="Infer headless runtime from setInterval/setTimeout throttling "
                "and timing jitter.",
        probe_method="setInterval/setTimeout scheduling and time deltas.",
        reproduce_hint="Timers must tick at normal cadence; background-tab "
                       "throttling of headless browsers is detectable.",
    ),
]

_CATEGORY_LABELS = {
    "automation-detection": "Automation detection",
    "device-fingerprint": "Device fingerprint",
    "environment-integrity": "Environment integrity",
    "display-fingerprint": "Display fingerprint",
    "behavioural": "Behavioural",
}


def by_category() -> dict[str, list[Fingerprint]]:
    """Group fingerprints by category for reporting."""
    out: dict[str, list[Fingerprint]] = {}
    for fp in FINGERPRINTS:
        out.setdefault(fp.category, []).append(fp)
    return out


def category_label(cat: str) -> str:
    return _CATEGORY_LABELS.get(cat, cat)


def ids() -> list[str]:
    return [fp.id for fp in FINGERPRINTS]
