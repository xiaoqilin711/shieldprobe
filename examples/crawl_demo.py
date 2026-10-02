"""End-to-end demo: pass a JS challenge and crawl a paginated JSON endpoint.

This mirrors a real workflow:

1. open an offscreen browser session,
2. visit the list page so the challenge JS runs and lands its cookies,
3. reuse the authenticated session to page through the real JSON API,
4. dump the collected rows to a JSON file.

Run::

    python examples/crawl_demo.py --url https://www.example.com/news/list.shtml \
        --api "https://www.example.com/api/list?page={page}&size=20" \
        --results data.results --total data.total
"""
from __future__ import annotations

import argparse

from shieldprobe import ShieldSession, save_json


def main() -> None:
    p = argparse.ArgumentParser(description="Pass a JS challenge and crawl a JSON API.")
    p.add_argument("--url", required=True, help="list page URL that triggers the challenge")
    p.add_argument("--api", required=True, help="JSON API template with a {page} placeholder")
    p.add_argument("--results", default="data.results", help="dotted path to the results array")
    p.add_argument("--total", default="data.total", help="dotted path to the total count")
    p.add_argument("--page-size", type=int, default=20)
    p.add_argument("--out", default="crawled.json", help="output JSON file")
    args = p.parse_args()

    with ShieldSession(offscreen=True) as sess:
        passed = sess.pass_shield(args.url)
        print(f"[*] challenge passed: {passed}")
        print(f"[*] cookies: {len(sess.cookies())}")

        def on_page(page: int, got: int, total_rows: int, total: int) -> None:
            print(f"    page={page}: +{got} rows (cumulative {total_rows}/{total})")

        rows = sess.crawl_json(
            args.api,
            page_size=args.page_size,
            total_field=args.total,
            results_field=args.results,
            on_page=on_page,
        )

    save_json(args.out, {"count": len(rows), "rows": rows})
    print(f"[*] wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
