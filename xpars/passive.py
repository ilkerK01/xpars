from __future__ import annotations

import requests

from . import refine

CDX = "http://web.archive.org/cdx/search/cdx"
URLSCAN = "https://urlscan.io/api/v1/search/"
OTX = "https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list"
CRTSH = "https://crt.sh/"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/"

KEYLESS = ("wayback", "urlscan", "otx")


def parse_cdx(text):
    return [line.strip() for line in text.splitlines() if line.strip().startswith("http")]


def parse_urlscan(data):
    out = []
    for res in (data or {}).get("results", []):
        u = (res.get("page") or {}).get("url")
        if u:
            out.append(u)
    return out


def parse_otx(data):
    return [i.get("url") for i in (data or {}).get("url_list", []) if i.get("url")]


def parse_crtsh(data, domain):
    subs = set()
    for row in data or []:
        nv = row.get("name_value", "") or ""
        for line in nv.splitlines():
            h = line.strip().lstrip("*.").lower()
            if h and h.endswith(domain) and "@" not in h:
                subs.add("https://" + h + "/")
    return sorted(subs)


def parse_hackertarget(text, domain):
    out = []
    low = (text or "").lower()
    if "error" in low or "api count" in low or "too many" in low:
        return out
    for line in (text or "").splitlines():
        h = line.split(",")[0].strip().lower()
        if h and h.endswith(domain):
            out.append("https://" + h + "/")
    return out


def belongs(url, domain, subdomains=False):
    h = refine.host(url)
    if not h:
        return False
    if h == domain:
        return True
    return bool(subdomains) and h.endswith("." + domain)


def _get(url, params=None, timeout=25):
    try:
        resp = requests.get(url, params=params, timeout=timeout,
                            headers={"User-Agent": "xpars"})
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    return resp


def _json(resp):
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def wayback(domain, subdomains=False, limit=5000, timeout=25):
    pattern = ("*.%s/*" % domain) if subdomains else ("%s/*" % domain)
    params = {"url": pattern, "output": "text", "fl": "original",
              "collapse": "urlkey", "limit": str(limit)}
    resp = _get(CDX, params=params, timeout=timeout)
    if resp is None:
        return []
    return parse_cdx(resp.text)


def urlscan(domain, timeout=25):
    return parse_urlscan(_json(_get(URLSCAN, {"q": "domain:%s" % domain, "size": "1000"}, timeout)))


def otx(domain, timeout=25):
    return parse_otx(_json(_get(OTX % domain, {"limit": "500"}, timeout)))


def crtsh(domain, timeout=30):
    return parse_crtsh(_json(_get(CRTSH, {"q": "%." + domain, "output": "json"}, timeout)), domain)


def hackertarget(domain, timeout=25):
    resp = _get(HACKERTARGET, {"q": domain}, timeout)
    return parse_hackertarget(resp.text if resp is not None else "", domain)


def gather(domain, subdomains=False, limit=5000, timeout=25, sources=None):
    use = tuple(sources) if sources else ("wayback",)
    urls = set()
    if "wayback" in use:
        urls |= set(wayback(domain, subdomains=False, limit=limit, timeout=timeout))
        if subdomains:
            urls |= set(wayback(domain, subdomains=True, limit=limit, timeout=timeout))
    if "urlscan" in use:
        urls |= set(urlscan(domain, timeout=timeout))
    if "otx" in use:
        urls |= set(otx(domain, timeout=timeout))
    if "crtsh" in use:
        urls |= set(crtsh(domain, timeout=timeout))
    if "hackertarget" in use:
        urls |= set(hackertarget(domain, timeout=timeout))
    return sorted(u for u in urls if belongs(u, domain, subdomains))
