from __future__ import annotations

SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "cf-request-id"],
     ["cloudflare"], ["__cfduid", "__cf_bm", "cf_clearance"]),
    ("Akamai", ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"],
     ["akamaighost"], ["bm_sv", "bm_sz", "_abck", "ak_bmsc", "bm_mi"]),
    ("Imperva Incapsula", ["x-iinfo", "x-cdn"],
     ["incapsula"], ["visid_incap", "incap_ses", "nlbi_"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], ["sucuri"], []),
    ("PerimeterX", ["x-px"], [], ["_px3", "_pxhd", "_pxvid", "_px2"]),
    ("F5 BIG-IP", [], ["big-ip", "bigip"], ["bigipserver", "ts01", "f5_cspm"]),
    ("Barracuda", [], ["barracuda"], ["barra_counter_session"]),
    ("AWS CloudFront", ["x-amz-cf-id", "x-amz-cf-pop"], ["cloudfront"], []),
    ("ModSecurity", ["x-mod-security"], ["mod_security", "modsecurity"], []),
    ("DataDome", ["x-datadome", "x-dd-b"], [], ["datadome"]),
    ("Wordfence", [], [], ["wfvt_", "wordfence_verifiedhuman"]),
    ("Fortiweb", [], ["fortiweb"], ["cookiesession1"]),
]

BLOCK_MARKERS = [
    "access denied", "request blocked", "attention required", "captcha",
    "are you a human", "security challenge", "/cdn-cgi/", "incident id",
    "blocked by", "reference #",
]


def fingerprint(resp):
    found = []
    hdr = {}
    try:
        for k, v in resp.headers.items():
            hdr[k.lower()] = str(v).lower()
    except Exception:
        pass
    server = hdr.get("server", "")
    via = hdr.get("via", "")
    cookie_blob = hdr.get("set-cookie", "")
    try:
        for c in resp.cookies:
            cookie_blob += " " + c.name
    except Exception:
        pass
    cookie_blob = cookie_blob.lower()
    for name, headers, servers, cookies in SIGNATURES:
        hit = None
        for h in headers:
            if h in hdr:
                hit = "header:" + h
                break
        if not hit:
            for s in servers:
                if s in server or s in via:
                    hit = "server:" + s
                    break
        if not hit:
            for ck in cookies:
                if ck in cookie_blob:
                    hit = "cookie:" + ck
                    break
        if hit:
            found.append({"waf": name, "signal": hit})
    return found


def blocked(resp):
    try:
        code = resp.status_code
    except Exception:
        return False
    if code in (403, 406, 429):
        return True
    if code == 503:
        try:
            body = (resp.text or "").lower()
        except Exception:
            body = ""
        return any(m in body for m in BLOCK_MARKERS)
    return False


def csp_summary(resp):
    try:
        csp = resp.headers.get("Content-Security-Policy", "") or ""
    except Exception:
        return {"present": False, "blocks_inline": False, "policy": ""}
    low = csp.lower()
    present = bool(csp.strip())
    has_script = "script-src" in low or "default-src" in low
    unsafe_inline = "'unsafe-inline'" in low
    blocks_inline = present and has_script and not unsafe_inline
    return {"present": present, "blocks_inline": blocks_inline, "policy": csp[:300]}


def fingerprint_host(client, url):
    try:
        resp = client.get(url)
    except Exception:
        return {"wafs": [], "blocked": False, "csp": {"present": False,
                "blocks_inline": False, "policy": ""}}
    return {"wafs": fingerprint(resp), "blocked": blocked(resp),
            "csp": csp_summary(resp)}
