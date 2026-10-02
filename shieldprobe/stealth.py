"""Shield session: drive a real browser past a JS challenge and reuse the
authenticated session to fetch data.

The trick is not to defeat the challenge algorithm, but to *borrow* a real
browser: let it run the challenge JS, land the cookies, then reuse the whole
cookie jar via Playwright's ``ctx.request`` for subsequent API calls.

Key lessons baked in from real targets:

* **No headless** — headless Chrome fails environment-fingerprint checks; use
  an offscreen window instead (``--window-position=-2000,-2000``).
* **System Chrome** — ``channel="chrome"`` avoids the automation fingerprints
  of the bundled Chromium build.
* **Full cookie jar** — reusing only the "obvious" cookies gets you a 400;
  always send the entire set, which ``ctx.request`` does automatically.
"""
from __future__ import annotations

import json
from typing import Any, Iterator, Optional


class ShieldSession:
    """A browser session that has (or can) pass a JS challenge."""

    def __init__(
        self,
        offscreen: bool = True,
        headless: bool = False,
        viewport: dict[str, int] | None = None,
        locale: str = "zh-CN",
        timezone_id: str = "Asia/Shanghai",
    ) -> None:
        self.offscreen = offscreen
        self.headless = headless
        self.viewport = viewport or {"width": 1920, "height": 1080}
        self.locale = locale
        self.timezone_id = timezone_id
        self._playwright: Any = None
        self._browser: Any = None
        self._ctx: Any = None
        self.page: Any = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "ShieldSession":
        from playwright.sync_api import sync_playwright

        args = ["--disable-blink-features=AutomationControlled", "--no-sandbox"]
        if self.offscreen and not self.headless:
            args += ["--window-position=-2000,-2000", "--window-size=1920,1080"]

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            channel="chrome", headless=self.headless, args=args
        )
        self._ctx = self._browser.new_context(
            viewport=self.viewport,
            locale=self.locale,
            timezone_id=self.timezone_id,
        )
        self.page = self._ctx.new_page()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    # -- challenge ---------------------------------------------------------
    def pass_shield(
        self,
        url: str,
        marker: str = "meta[r='m']",
        settle: int = 5000,
        timeout: int = 30000,
    ) -> bool:
        """Navigate to ``url`` and wait until the challenge page is gone.

        The challenge page carries ``marker`` (e.g. ``<meta r='m'>``); the real
        page does not. ``settle`` is extra time to let business JS finish
        writing any additional cookies.
        """
        self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        try:
            self.page.wait_for_function(
                f"() => !document.querySelector(\"{marker}\")", timeout=timeout
            )
            passed = True
        except Exception:
            passed = False
        self.page.wait_for_timeout(settle)
        return passed

    # -- session reuse -----------------------------------------------------
    def request(self, url: str, **kwargs: Any) -> Any:
        """GET ``url`` with the full session cookie jar attached."""
        return self._ctx.request.get(url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request(url, **kwargs).json()

    def cookies(self) -> dict[str, str]:
        return {c["name"]: c["value"] for c in self._ctx.cookies() if c["name"] != "Path"}

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies().items())

    # -- paginated crawl ---------------------------------------------------
    def crawl_json(
        self,
        url_template: str,
        *,
        start_page: int = 1,
        page_size: int = 20,
        total_field: str = "data.total",
        results_field: str = "data.results",
        headers: Optional[dict[str, str]] = None,
        on_page: Optional[Any] = None,
    ) -> list[dict[str, Any]]:
        """Paginate a JSON endpoint until all rows are collected.

        ``url_template`` is a format string with a ``{page}`` placeholder,
        e.g. ``"https://host/api/list?page={page}&size=20"``.
        """
        headers = headers or {}
        collected: list[dict[str, Any]] = []
        page = start_page
        while True:
            resp = self.request(url_template.format(page=page), headers=headers)
            if resp.status != 200:
                break
            data = resp.json()
            d = _dig(data, total_field)
            total = int(d or 0)
            results = _dig(data, results_field) or []
            if not results:
                break
            collected.extend(results)
            if on_page:
                on_page(page, len(results), len(collected), total)
            if page * page_size >= total:
                break
            page += 1
        return collected


def _dig(data: Any, dotted: str) -> Any:
    """Fetch a dotted path (e.g. 'data.total') from a nested dict."""
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def save_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
