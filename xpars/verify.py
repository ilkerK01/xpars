from __future__ import annotations

import json as _json

from . import jsontpl, params

HASH_SOURCES = ("location.hash",)
HREF_SOURCES = ("location.href", "document.url", "document.documenturi")
SEARCH_SOURCES = ("location.search", "url.searchparams", "new urlsearchparams")
NAME_SOURCES = ("window.name",)
MSG_SOURCES = ("postmessage", "onmessage")
JS_SINKS = ("eval(", "settimeout(", "setinterval(", "new function", ".src", ".href")

MARKUP_PAYLOADS = ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
JS_PAYLOADS = ['alert(1)', ';alert(1)//', 'alert(document.domain)']

VERIFY_METHODS = ("GET", "POST", "POST-JSON", "GRAPHQL", "HEADER", "COOKIE",
                  "STORED", "PATH")

_EXEC_CONTEXTS = ("html", "attribute", "attribute_unquoted", "uri", "script")

_BROWSER_CONTROLLED = ("referer", "origin")


def available():
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def _candidates(finding):
    out = []
    for p in finding.get("working_payloads") or []:
        if p not in out:
            out.append(p)
    cp = finding.get("payload")
    if cp and cp not in out:
        out.append(cp)
    return out[:12]


def _safe_dismiss(dialog):
    try:
        dialog.dismiss()
    except Exception:
        pass


def _on_dialog(state):
    def handler(dialog):
        state["hit"] = True
        _safe_dismiss(dialog)
    return handler


def _nav(page, url, timeout, referer=None):
    try:
        if referer is not None:
            page.goto(url, timeout=int(timeout * 1000), wait_until="load", referer=referer)
        else:
            page.goto(url, timeout=int(timeout * 1000), wait_until="load")
        page.wait_for_timeout(350)
    except Exception:
        pass


def _verify_ua(browser, f, timeout):
    for payload in _candidates(f):
        state = {"hit": False}
        try:
            ctx = browser.new_context(ignore_https_errors=True, user_agent=payload)
            page = ctx.new_page()
            page.on("dialog", _on_dialog(state))
            _nav(page, f["url"], timeout)
            ctx.close()
        except Exception:
            continue
        if state["hit"]:
            return payload
    return None


def _mark(f, how, payload):
    f["verified"] = True
    f["how"] = how
    f["severity"] = "critical"
    f["verified_payload"] = payload


def _inject(page, ctx, f, payload, timeout):
    method = f.get("method")
    url = f.get("url")
    name = f.get("param")
    if method == "GET":
        _nav(page, params.set_param(url, name, payload), timeout)
    elif method == "PATH":
        from urllib.parse import quote
        idx = f.get("path_index")
        try:
            _nav(page, params.set_path_segment(url, idx, quote(payload, safe="")), timeout)
        except Exception:
            pass
    elif method == "HEADER":
        try:
            ctx.set_extra_http_headers({name: payload})
        except Exception:
            pass
        _nav(page, url, timeout)
        try:
            ctx.set_extra_http_headers({})
        except Exception:
            pass
    elif method == "COOKIE":
        try:
            ctx.clear_cookies()
            ctx.add_cookies([{"name": "xpars", "value": payload, "url": url}])
        except Exception:
            pass
        _nav(page, url, timeout)
        try:
            ctx.clear_cookies()
        except Exception:
            pass
    elif method == "POST":
        try:
            page.goto("about:blank", timeout=int(timeout * 1000))
            page.evaluate(
                "([a,n,v])=>{const f=document.createElement('form');f.method='POST';"
                "f.action=a;const i=document.createElement('input');i.name=n;i.value=v;"
                "f.appendChild(i);document.body.appendChild(f);f.submit();}",
                [url, name, payload])
            page.wait_for_timeout(500)
        except Exception:
            pass
    elif method in ("POST-JSON", "GRAPHQL"):
        tpl = f.get("json_template")
        path = f.get("json_path")
        if tpl is not None and path is not None:
            body = _json.dumps(jsontpl.set_at(tpl, tuple(path), payload))
        else:
            body = _json.dumps({name: payload})
        try:
            page.goto(url.split("#")[0], timeout=int(timeout * 1000))
            page.evaluate(
                "async ([u,b])=>{try{const r=await fetch(u,{method:'POST',"
                "headers:{'Content-Type':'application/json'},body:b});const t=await r.text();"
                "document.open();document.write(t);document.close();}catch(e){}}",
                [url, body])
            page.wait_for_timeout(500)
        except Exception:
            pass


def _baseline_hit(page, ctx, f, state, timeout):
    method = f.get("method")
    state["hit"] = False
    if method == "GET":
        _nav(page, params.set_param(f["url"], f["param"], "xparsbaseline0"), timeout)
    elif method in ("HEADER", "COOKIE", "POST", "POST-JSON", "GRAPHQL", "PATH"):
        _nav(page, f["url"].split("#")[0], timeout)
    else:
        return False
    return state["hit"]


def verify_findings(findings, timeout=8.0, headless=True):
    targets = [f for f in findings if f.get("method") in VERIFY_METHODS
               and (f.get("method") == "STORED" or _candidates(f))]
    if not available():
        return {"supported": False, "verified": 0, "candidates": len(targets)}
    if not targets:
        return {"supported": True, "verified": 0, "candidates": 0}
    from playwright.sync_api import sync_playwright
    state = {"hit": False}
    verified = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("dialog", _on_dialog(state))
        for f in targets:
            if f.get("method") == "STORED":
                state["hit"] = False
                _nav(page, f["url"], timeout)
                if state["hit"]:
                    _mark(f, "stored-execution", f.get("payload"))
                    verified += 1
                else:
                    f["verified"] = False
                continue
            if _baseline_hit(page, ctx, f, state, timeout):
                f["verify_note"] = "baseline-dialog"
                f["verified"] = False
                continue
            if f.get("method") == "HEADER":
                low = (f.get("param") or "").lower()
                if low == "user-agent":
                    pay = _verify_ua(browser, f, timeout)
                    if pay is not None:
                        _mark(f, "execution", pay)
                        verified += 1
                    else:
                        f["verified"] = False
                    continue
                if low in _BROWSER_CONTROLLED:
                    f["verified"] = False
                    f["verify_note"] = "browser-controlled-header"
                    continue
            if f.get("method") == "GRAPHQL" and f.get("context") not in _EXEC_CONTEXTS:
                f["verified"] = False
                f["verify_note"] = "json-context-skip"
                continue
            done = False
            for payload in _candidates(f):
                state["hit"] = False
                _inject(page, ctx, f, payload, timeout)
                if state["hit"]:
                    _mark(f, "execution", payload)
                    verified += 1
                    done = True
                    break
            if not done:
                f["verified"] = False
        ctx.close()
        browser.close()
    return {"supported": True, "verified": verified, "candidates": len(targets)}


def _dom_kinds(d):
    s = set(d.get("sources", []))
    out = []
    if s.intersection(HASH_SOURCES + HREF_SOURCES):
        out.append("hash")
    if s.intersection(SEARCH_SOURCES + HREF_SOURCES):
        out.append("search")
    if s.intersection(NAME_SOURCES):
        out.append("name")
    if s.intersection(MSG_SOURCES):
        out.append("message")
    return out


def _dom_payloads(d):
    if set(d.get("sinks", [])).intersection(JS_SINKS):
        return JS_PAYLOADS + MARKUP_PAYLOADS
    return MARKUP_PAYLOADS + JS_PAYLOADS


def _dom_inject(page, base, kind, payload, timeout):
    try:
        if kind == "hash":
            try:
                page.goto("about:blank", timeout=int(timeout * 1000))
            except Exception:
                pass
            _nav(page, base + "#" + payload, timeout)
        elif kind == "search":
            sep = "&" if "?" in base else "?"
            _nav(page, base + sep + "xpars=" + payload, timeout)
        elif kind == "name":
            page.goto("about:blank", timeout=int(timeout * 1000))
            page.evaluate("(v)=>{window.name=v;}", payload)
            _nav(page, base, timeout)
        elif kind == "message":
            _nav(page, base, timeout)
            page.evaluate("(v)=>{window.postMessage(v,'*');}", payload)
            page.wait_for_timeout(350)
    except Exception:
        pass


def verify_dom(dom, timeout=8.0, headless=True):
    targets = [d for d in dom if d.get("url") and _dom_kinds(d)]
    if not available():
        return {"supported": False, "verified": 0, "candidates": len(targets)}
    if not targets:
        return {"supported": True, "verified": 0, "candidates": 0}
    from playwright.sync_api import sync_playwright
    state = {"hit": False}
    verified = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("dialog", _on_dialog(state))
        for d in targets:
            base = d["url"].split("#")[0]
            state["hit"] = False
            _nav(page, base, timeout)
            if state["hit"]:
                d["verify_note"] = "baseline-dialog"
                continue
            hit = False
            for kind in _dom_kinds(d):
                for payload in _dom_payloads(d):
                    state["hit"] = False
                    _dom_inject(page, base, kind, payload, timeout)
                    if state["hit"]:
                        d["verified"] = True
                        d["how"] = "dom-execution"
                        d["severity"] = "critical"
                        d["verified_payload"] = payload
                        d["verified_via"] = kind
                        verified += 1
                        hit = True
                        break
                if hit:
                    break
        ctx.close()
        browser.close()
    return {"supported": True, "verified": verified, "candidates": len(targets)}
