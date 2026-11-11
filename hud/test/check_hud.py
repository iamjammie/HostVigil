#!/usr/bin/env python3
"""Render the standalone HUD headlessly and assert it is healthy.

Checks (fail -> exit 1):
  * no uncaught JS errors and no console.error (the in-page integrity guard
    reports data violations through console.error)
  * all nine views render and the main canvas is non-empty
  * KPI tiles show numbers
  * the host drawer opens and shows seven tabs
  * no horizontal scroll at 400px width
Runs with Playwright; `pip install playwright && playwright install chromium`.
"""
import asyncio, sys, pathlib
from playwright.async_api import async_playwright

HUD = pathlib.Path(__file__).resolve().parents[1] / "standalone" / "hostvigil-hud.html"
VIEWS = ["overview", "map", "hosts", "vulns", "fim", "allowlist", "policy", "forensics", "fleet"]

async def main() -> int:
    html = HUD.read_text(encoding="utf-8")
    doc = "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'></head><body>" + html + "</body></html>"
    problems = []
    async with async_playwright() as p:
        b = await p.chromium.launch()
        pg = await b.new_page(viewport={"width": 1440, "height": 900})
        pg.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
        pg.on("console", lambda m: problems.append(f"console.{m.type}: {m.text}") if m.type == "error" and "Failed to load resource" not in m.text else None)  # font/CDN fetch noise is not a code error
        await pg.set_content(doc, wait_until="networkidle")
        await pg.wait_for_timeout(800)
        kpis = await pg.eval_on_selector_all(".kpi .v", "els => els.map(e => e.textContent.trim())")
        if len(kpis) < 6 or not all(k.replace("%", "").replace("MB", "").replace("m", "").strip().isdigit() for k in kpis):
            problems.append(f"KPI tiles not numeric: {kpis}")
        for v in VIEWS:
            await pg.evaluate(f"go('{v}')")
            await pg.wait_for_timeout(400)
            n = await pg.evaluate("document.querySelectorAll('#main .card').length")
            if n == 0:
                problems.append(f"view {v} rendered no cards")
        await pg.evaluate("openHost(hosts[0].id)")
        await pg.wait_for_timeout(300)
        tabs = await pg.evaluate("document.querySelectorAll('#drawer .tabs button').length")
        if tabs != 7:
            problems.append(f"drawer has {tabs} tabs, expected 7")
        pm = await b.new_page(viewport={"width": 400, "height": 820})
        await pm.set_content(doc, wait_until="networkidle")
        await pm.wait_for_timeout(600)
        sw, cw = await pm.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]")
        if sw > cw:
            problems.append(f"horizontal overflow at 400px: {sw} > {cw}")
        await b.close()
    for pr in problems:
        print("FAIL", pr)
    print("ok" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
