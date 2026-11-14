from __future__ import annotations

from urllib.parse import urlencode

from . import refine

_LAUNCH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding"]

_KEEP_TYPES = {"xhr", "fetch", "document", "script"}

_FORMS_JS = """() => Array.from(document.forms).map(f => ({
    action: f.action || location.href,
    method: (f.method || 'get').toLowerCase(),
    fields: Array.from(f.elements).filter(e => e.name).map(e => e.name)
}))"""


def available():
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def _in_scope(url, seed_hosts, seed_rdns, mode, scope):
    if not scope.permitted(url):
        return False
    h = refine.host(url)
    if not h:
        return False
    if mode == "subdomains":
        return any(h == r or h.endswith("." + r) for r in seed_rdns)
    return h in seed_hosts


def _links(page):
    try:
        return page.eval_on_selector_all(
            "a[href], area[href]", "els => els.map(e => e.href)") or []
    except Exception:
        return []


def _forms(page):
    try:
        return page.evaluate(_FORMS_JS) or []
    except Exception:
        return []


def render_crawl(seeds, scope, mode="strict", timeout=12.0, max_pages=30,
                 per_host=8, forms_out=None, on_progress=None):
    if not available():
        return set()
    seeds = [refine.normalize(s) for s in seeds]
    seeds = [s for s in seeds if scope.permitted(s)]
    if not seeds:
        return set()
    seed_hosts = {refine.host(s) for s in seeds}
    seed_rdns = {refine.registered_domain(h) for h in seed_hosts}
    from playwright.sync_api import sync_playwright
    endpoints = set()
    host_count = {}
    try:
        pw = sync_playwright().start()
    except Exception:
        return set()
    try:
        browser = pw.chromium.launch(headless=True, args=_LAUNCH_ARGS)
        ctx = browser.new_context(ignore_https_errors=True)
        ctx.set_default_navigation_timeout(int(timeout * 1000))
        ctx.set_default_timeout(int(timeout * 1000))
        visited = set()
        frontier = list(seeds)
        while frontier and len(visited) < max_pages:
            url = frontier.pop(0)
            if url in visited:
                continue
            h = refine.host(url)
            if host_count.get(h, 0) >= per_host:
                continue
            visited.add(url)
            host_count[h] = host_count.get(h, 0) + 1
            captured = set()
            page = ctx.new_page()
            page.on("request", lambda req, c=captured: c.add((req.resource_type, req.url)))
            links, forms = [], []
            try:
                page.goto(url, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=int(timeout * 1000))
                except Exception:
                    pass
                page.wait_for_timeout(400)
                links = _links(page)
                forms = _forms(page)
            except Exception:
                pass
            finally:
                try:
                    page.close()
                except Exception:
                    pass
            for rtype, ru in captured:
                if rtype not in _KEEP_TYPES:
                    continue
                cand = (ru or "").split("#")[0]
                if cand.startswith(("http://", "https://")) \
                        and _in_scope(cand, seed_hosts, seed_rdns, mode, scope):
                    endpoints.add(cand)
            for href in links:
                absu = (href or "").split("#")[0]
                if not absu.startswith(("http://", "https://")):
                    continue
                if not _in_scope(absu, seed_hosts, seed_rdns, mode, scope):
                    continue
                endpoints.add(absu)
                if absu not in visited and len(frontier) < max_pages * 4:
                    frontier.append(absu)
            for form in forms:
                action = (form.get("action") or url).split("#")[0]
                fields = form.get("fields") or []
                if not fields or not _in_scope(action, seed_hosts, seed_rdns, mode, scope):
                    continue
                if form.get("method") == "post":
                    if forms_out is not None:
                        forms_out.append({"action": action, "fields": fields, "values": {}})
                else:
                    q = urlencode([(f, "1") for f in fields])
                    endpoints.add(action + ("&" if "?" in action else "?") + q)
            if on_progress is not None:
                try:
                    on_progress(len(visited), max_pages, h)
                except Exception:
                    pass
        try:
            ctx.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            pw.stop()
        except Exception:
            pass
    return endpoints
