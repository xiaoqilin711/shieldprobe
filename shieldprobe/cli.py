"""Command-line interface for ShieldProbe."""
from __future__ import annotations

import argparse
import json

from . import __version__
from .probe import probe_http, probe_browser, format_report
from .signatures import list_signatures
from .fingerprints import FINGERPRINTS, category_label


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shieldprobe",
        description="Fingerprint, identify, and bypass dynamic anti-bot protections.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # probe
    pr = sub.add_parser("probe", help="Analyze a target URL")
    pr.add_argument("url", help="target URL to probe")
    pr.add_argument("--deep", action="store_true", help="drive a real browser (slower)")
    pr.add_argument("--json", action="store_true", help="emit JSON instead of text")
    pr.add_argument("--timeout", type=int, default=20)
    pr.add_argument("--user-agent", default=None)

    # signatures
    sub.add_parser("signatures", help="List known anti-bot signatures")

    # fingerprints
    sub.add_parser("fingerprints", help="List environment fingerprint checkpoints")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "probe":
        res = probe_browser(args.url) if args.deep else probe_http(
            args.url, timeout=args.timeout, user_agent=args.user_agent
        )
        if args.json:
            print(json.dumps(res.__dict__, ensure_ascii=False, indent=2))
        else:
            print(format_report(res))
        return 0 if not res.error else 1

    if args.command == "signatures":
        for s in list_signatures():
            print(f"[{s.id}] {s.name}")
            print(f"    status={s.status_codes or '-'} cookies={s.cookie_name_patterns or '-'}")
            print(f"    js={s.js_markers or '-'} html={s.html_markers or '-'}")
            print(f"    env-probes={s.env_probes or '-'}")
        return 0

    if args.command == "fingerprints":
        current = None
        for fp in FINGERPRINTS:
            if fp.category != current:
                current = fp.category
                print(f"\n# {category_label(fp.category)}")
            print(f"  - {fp.id}")
            print(f"      purpose: {fp.purpose}")
            print(f"      probe  : {fp.probe_method}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
