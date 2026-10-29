from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

SECRETS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Temp Key ID", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b")),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Twilio Account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9a-fA-F]{32}\b")),
    ("Telegram Bot Token", re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{35}\b")),
    ("Google OAuth Token", re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Bearer Token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}", re.I)),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Basic Auth in URL", re.compile(r"\bhttps?://[^/\s'\"]+:[^/\s'\"]+@[^/\s'\"]+", re.I)),
    ("Redis URI", re.compile(r"\bredis(?:\+tls|s)?://[^\s\"'<>`]+", re.I)),
    ("Postgres URI", re.compile(r"\bpostgres(?:ql)?://[^\s\"'<>`]+", re.I)),
    ("MySQL URI", re.compile(r"\b(?:mysql|mariadb)://[^\s\"'<>`]+", re.I)),
    ("MongoDB URI", re.compile(r"\bmongodb(?:\+srv)?://[^\s\"'<>`]+", re.I)),
    ("Azure Storage Key", re.compile(r"AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}")),
    ("apiKey assignment", re.compile(
        r"\b(?:api[_-]?key|apikey)\b\s*[:=]\s*['\"][^'\"\r\n]{16,}['\"]", re.I)),
    ("secret assignment", re.compile(
        r"\b(?:secret|client[_-]?secret|app[_-]?secret|private[_-]?key)\b\s*[:=]\s*"
        r"['\"][^'\"\r\n]{16,}['\"]", re.I)),
    ("password in JSON", re.compile(r"\"password\"\s*:\s*\"[^\"\r\n]{6,200}\"", re.I)),
    ("token in query", re.compile(
        r"[?&](?:access_token|auth_token|token|id_token|refresh_token|apikey|api_key|key)"
        r"=[A-Za-z0-9._\-]{16,}", re.I)),
]

URL_RE = re.compile(r"""['"`]((?:https?:)?/[A-Za-z0-9_\-./]{1,200}(?:\?[^'"`\s]{0,300})?)['"`]""")
FETCH_RE = re.compile(r"""(?:fetch|axios\.\w+|\.open)\s*\(\s*['"`]([^'"`]{1,300})['"`]""", re.I)

LFI_PARAMS = ("file", "path", "dir", "folder", "include", "template", "doc",
              "document", "page", "load", "download", "read", "filename")
RCE_PARAMS = ("cmd", "exec", "command", "run", "ping", "system", "shell", "code")
SQLI_PARAMS = ("id", "select", "where", "order", "sort", "query", "filter",
               "category", "cat", "user", "uid", "pid")
XSS_PARAMS = ("q", "s", "search", "name", "message", "msg", "redirect", "url",
              "return", "callback", "lang", "ref", "title", "text", "keyword")


def _secrets(text):
    out = []
    seen = set()
    for name, rx in SECRETS:
        for m in rx.findall(text):
            val = m if isinstance(m, str) else m[0]
            v = str(val)[:120]
            key = (name, v)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": name, "value": v})
            if len(out) >= 200:
                return out
    return out


def _endpoints(text):
    eps = set()
    for rx in (URL_RE, FETCH_RE):
        for m in rx.findall(text):
            u = m if isinstance(m, str) else m[0]
            if u and len(u) <= 300:
                eps.add(u)
    return sorted(eps)[:400]


def _classify(endpoints):
    cands = {"lfi": [], "rce": [], "sqli": [], "xss": []}
    for u in endpoints:
        q = urlsplit(u).query
        if not q:
            continue
        names = [k.lower() for k, _ in parse_qsl(q, keep_blank_values=True)]
        if any(n in LFI_PARAMS for n in names):
            cands["lfi"].append(u)
        if any(n in RCE_PARAMS for n in names):
            cands["rce"].append(u)
        if any(n in SQLI_PARAMS for n in names):
            cands["sqli"].append(u)
        if any(n in XSS_PARAMS for n in names):
            cands["xss"].append(u)
    return cands


def scan(text):
    text = text or ""
    endpoints = _endpoints(text)
    return {"secrets": _secrets(text), "endpoints": endpoints,
            "candidates": _classify(endpoints)}


def merge(dst, src):
    ds = {(x["type"], x["value"]) for x in dst.get("secrets", [])}
    for s in src.get("secrets", []):
        if (s["type"], s["value"]) not in ds:
            ds.add((s["type"], s["value"]))
            dst.setdefault("secrets", []).append(s)
    eset = set(dst.get("endpoints", []))
    for e in src.get("endpoints", []):
        if e not in eset:
            eset.add(e)
            dst.setdefault("endpoints", []).append(e)
    for k in ("lfi", "rce", "sqli", "xss"):
        cur = dst.setdefault("candidates", {}).setdefault(k, [])
        curset = set(cur)
        for u in src.get("candidates", {}).get(k, []):
            if u not in curset:
                curset.add(u)
                cur.append(u)
    return dst
