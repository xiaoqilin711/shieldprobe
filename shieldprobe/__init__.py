"""ShieldProbe — fingerprint, identify, and bypass dynamic anti-bot protections.

A toolkit for analysing dynamic anti-bot (JS-challenge) protections: recognize
the protection family, catalogue the environment fingerprints it checks, and
borrow a real browser session to pass the challenge and crawl the data.
"""
from __future__ import annotations

from .signatures import Evidence, Signature, SIGNATURES, detect, list_signatures
from .fingerprints import FINGERPRINTS, Fingerprint, by_category
from .probe import ProbeResult, probe_http, probe_browser, format_report
from .stealth import ShieldSession

__version__ = "0.1.0"

__all__ = [
    "Evidence",
    "Signature",
    "SIGNATURES",
    "detect",
    "list_signatures",
    "FINGERPRINTS",
    "Fingerprint",
    "by_category",
    "ProbeResult",
    "probe_http",
    "probe_browser",
    "format_report",
    "ShieldSession",
    "__version__",
]
