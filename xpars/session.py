from __future__ import annotations

import json
import sys
import time

AUTH_HEADERS = ("authorization", "x-csrf-token", "x-xsrf-token", "x-xsrftoken",
                "x-api-key", "x-auth-token")


def available() -> bool:
    try:
        import playwright.sync_api
        return True
    except Exception:
        return False


def capture(login_url, out_path, timeout=300.0):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {"ok": False, "reason": "playwright-yok"}
    seen = {}
    state = {"cookies": [], "origins": []}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=False, args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(ignore_https_errors=True)

        def _on_request(req):
            try:
                h = req.headers
            except Exception:
                return
            for k in AUTH_HEADERS:
                v = h.get(k)
                if v:
                    seen[k] = v
        ctx.on("request", _on_request)
        closed = {"v": False}
        browser.on("disconnected", lambda: closed.__setitem__("v", True))
        page = ctx.new_page()
        try:
            page.goto(login_url, wait_until="domcontentloaded")
        except Exception:
            pass
        sys.stderr.write(
            "[oturum] tarayici acildi. Hedefe giris yap; bitince pencereyi KAPAT "
            "(ya da %d sn bekle).\n" % int(timeout))
        sys.stderr.flush()
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if closed["v"]:
                break
            try:
                state = ctx.storage_state()
            except Exception:
                pass
            time.sleep(1.0)
        if not closed["v"]:
            try:
                state = ctx.storage_state()
            except Exception:
                pass
        try:
            browser.close()
        except Exception:
            pass
    out = {"cookies": state.get("cookies", []) or [],
           "origins": state.get("origins", []) or [],
           "xpars_headers": seen}
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f)
    except Exception:
        return {"ok": False, "reason": "yazilamadi"}
    return {"ok": True, "cookies": len(out["cookies"]),
            "origins": len(out["origins"]), "headers": list(seen.keys())}


def load(path):
    with open(path, encoding="utf-8") as f:
        state = json.load(f)
    cookies = state.get("cookies", []) or []
    headers = state.get("xpars_headers", {}) or {}
    storage = {"cookies": cookies, "origins": state.get("origins", []) or []}
    return cookies, headers, storage
