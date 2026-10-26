from __future__ import annotations

import re

PROBE_TAIL = "<>'\"`();/{}=\\"

SINKS = ("innerhtml", "outerhtml", "document.write", "insertadjacenthtml",
         "eval(", "settimeout(", "setinterval(", ".html(", "document.writeln",
         "setattribute", ".src", ".href", "location.assign", "location.replace",
         "location.href", "window.open", "range.createcontextualfragment",
         "jquery", "$(", ".after(", ".before(", ".append(", ".prepend(",
         "domparser", "srcdoc", "new function", "dangerouslysetinnerhtml",
         "bypasssecuritytrust", "v-html", "ng-bind-html", "trustashtml")
SOURCES = ("location.hash", "location.search", "location.href", "document.url",
           "document.documenturi", "window.name", "document.referrer",
           "location.pathname", "location)", "document.location",
           "url.searchparams", "new urlsearchparams", "postmessage", "onmessage",
           "localstorage", "sessionstorage")

SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
ATTR_UNQUOTED = re.compile(r"=\s*[^\s\"'<>]*$")
TAG_RE = re.compile(r"<\s*[A-Za-z][A-Za-z0-9]*")
PAYLOAD_TAG_RE = re.compile(r"<\s*([A-Za-z][A-Za-z0-9]*)")
PAYLOAD_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
PAYLOAD_SCHEME_RE = re.compile(r"javascript:", re.IGNORECASE)

CONTEXT_SCORE = {
    ("html", True): 100,
    ("script", True): 96,
    ("attribute", True): 92,
    ("attribute_unquoted", True): 88,
    ("uri", True): 84,
    ("rcdata", False): 70,
    ("style", False): 64,
    ("comment", False): 58,
    ("script", False): 52,
    ("uri", False): 48,
    ("json_reflection", False): 44,
    ("attribute", False): 40,
    ("encoded", False): 12,
    ("none", False): 0,
}


def probe_value(marker):
    return marker + PROBE_TAIL


SPECIAL = (
    ("<!--", "-->", "comment"),
    ("<script", "</script", "script"),
    ("<style", "</style", "style"),
    ("<textarea", "</textarea", "rcdata"),
    ("<title", "</title", "rcdata"),
)


def _enclosing_special(low, idx):
    best = None
    best_pos = -1
    for opener, closer, kind in SPECIAL:
        start = low.rfind(opener, 0, idx)
        if start < 0:
            continue
        close = low.find(closer, start + len(opener))
        if close != -1 and close < idx:
            continue
        if start > best_pos:
            best_pos = start
            best = kind
    return best


URI_ATTRS = ("href", "src", "action", "formaction", "data", "poster",
             "background", "cite", "longdesc", "xlink:href")

JS_SCRIPT_TYPES = ("", "text/javascript", "application/javascript", "module",
                   "text/ecmascript", "application/ecmascript", "text/jscript",
                   "text/babel", "text/jsx")

SCRIPT_TYPE_RE = re.compile(r'type\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE)


def _script_executable(low, idx):
    tstart = low.rfind("<script", 0, idx)
    if tstart < 0:
        return True
    tend = low.find(">", tstart)
    if tend < 0 or tend >= idx:
        return True
    m = SCRIPT_TYPE_RE.search(low[tstart:tend])
    if not m:
        return True
    return m.group(1).strip() in JS_SCRIPT_TYPES


def _context_at(body, low, idx, marker, is_json):
    tail = body[idx + len(marker):idx + len(marker) + 12]
    raw_lt = "<" in tail
    raw_gt = ">" in tail
    raw_dq = '"' in tail
    raw_sq = "'" in tail
    special = _enclosing_special(low, idx)
    if special == "comment":
        return ("comment", False)
    if special == "rcdata":
        return ("rcdata", False)
    if special == "style":
        return ("style", False)
    if special == "script":
        if not _script_executable(low, idx):
            return ("rcdata", False)
        if raw_dq or raw_sq:
            return ("script", True)
        return ("script", False)
    pre = body[max(0, idx - 200):idx]
    in_tag = pre.rfind("<") > pre.rfind(">")
    tag_seg = pre[pre.rfind("<"):] if in_tag else ""
    inside_dq = tag_seg.count('"') % 2 == 1
    inside_sq = tag_seg.count("'") % 2 == 1
    attr_name = ""
    m = re.findall(r"([A-Za-z:-]+)\s*=\s*[\"']?[^\"'=<>]*$", tag_seg)
    if m:
        attr_name = m[-1].lower()
    in_uri_attr = attr_name in URI_ATTRS
    if raw_lt and raw_gt and not is_json:
        return ("html", True)
    if (inside_dq and raw_dq) or (inside_sq and raw_sq):
        return ("attribute", True)
    if in_uri_attr and (inside_dq or inside_sq or in_tag):
        low_pre = (tag_seg + body[idx:idx + len(marker) + 2]).lower()
        return ("uri", not (raw_lt or raw_gt))
    if in_tag and not inside_dq and not inside_sq and ATTR_UNQUOTED.search(pre) \
            and not (raw_lt and raw_gt):
        return ("attribute_unquoted", True)
    if raw_lt and raw_gt and is_json:
        return ("json_reflection", False)
    return ("encoded", False)


def _all_indices(body, marker):
    out = []
    start = 0
    while True:
        i = body.find(marker, start)
        if i < 0:
            break
        out.append(i)
        start = i + len(marker)
        if len(out) >= 50:
            break
    return out


def reflections(body, marker, content_type=""):
    out = []
    low = body.lower()
    ct = (content_type or "").lower()
    is_json = "json" in ct and "html" not in ct
    for idx in _all_indices(body, marker):
        context, confirmed = _context_at(body, low, idx, marker, is_json)
        score = CONTEXT_SCORE.get((context, confirmed), 20 if confirmed else 8)
        out.append({"context": context, "confirmed": confirmed,
                    "index": idx, "score": score})
    out.sort(key=lambda r: r["score"], reverse=True)
    return out


def reflection(body, marker, content_type=""):
    refs = reflections(body, marker, content_type)
    if not refs:
        return (False, "none", False)
    best = refs[0]
    return (True, best["context"], best["confirmed"])


_ENTITY = {
    "<": ("&lt;", "&#x3c;", "&#60;"),
    ">": ("&gt;", "&#x3e;", "&#62;"),
    '"': ("&quot;", "&#x22;", "&#34;"),
    "'": ("&#x27;", "&#39;", "&apos;"),
    "&": ("&amp;",),
}


def char_survival(body, marker):
    survived = {}
    for ch in PROBE_TAIL:
        survived[ch] = False
    for idx in _all_indices(body, marker):
        seg = body[idx + len(marker):idx + len(marker) + 2 * len(PROBE_TAIL) + 8]
        low = seg.lower()
        for ch in PROBE_TAIL:
            if survived[ch]:
                continue
            ents = _ENTITY.get(ch)
            if ents:
                escaped = any(e in low for e in ents)
                if ch in seg and not escaped:
                    survived[ch] = True
            elif ch in seg:
                survived[ch] = True
    return survived


def _payload_signature(payload):
    tag = PAYLOAD_TAG_RE.search(payload)
    tag_name = tag.group(1).lower() if tag else ""
    handler = PAYLOAD_HANDLER_RE.search(payload)
    handler_txt = handler.group(0).lower().rstrip("= ") if handler else ""
    scheme = bool(PAYLOAD_SCHEME_RE.search(payload))
    return tag_name, handler_txt, scheme


NEEDS_BREAKOUT = ("rcdata", "comment", "style")


def payload_lands(body, payload, context=None):
    p = payload.strip()
    if len(p) < 4:
        return False
    has_tag = bool(TAG_RE.search(p))
    has_scheme = bool(PAYLOAD_SCHEME_RE.search(p))
    breaks = any(c in p for c in "<>\"'")
    strict = context in NEEDS_BREAKOUT
    if p in body and (has_tag or (breaks and not strict)):
        return True
    tag_name, handler_txt, scheme = _payload_signature(p)
    if tag_name and handler_txt:
        rx = re.compile("<" + re.escape(tag_name) + r"[^<>\"'&]*" + re.escape(handler_txt)
                        + r"\s*=", re.IGNORECASE)
        if rx.search(body):
            return True
    if tag_name and scheme:
        rx = re.compile("<" + re.escape(tag_name) + r"[^<>\"'&]*javascript:", re.IGNORECASE)
        if rx.search(body):
            return True
    if scheme and not tag_name:
        uri = "|".join(re.escape(a) for a in URI_ATTRS)
        if re.search(r"(?:" + uri + r")\s*=\s*[\"']?\s*javascript:", body, re.IGNORECASE):
            return True
    return False


def evidence(body, marker, span=50):
    idx = body.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - 20)
    return body[start:idx + len(marker) + span].replace("\n", " ")


def dom_findings(body):
    hits = []
    for block in SCRIPT_RE.findall(body):
        low = block.lower()
        srcs = [s for s in SOURCES if s in low]
        snks = [s for s in SINKS if s in low]
        if srcs and snks:
            hits.append({"sources": sorted(set(srcs)), "sinks": sorted(set(snks))})
    return hits


def dom_findings_js(text):
    low = text.lower()
    srcs = [s for s in SOURCES if s in low]
    snks = [s for s in SINKS if s in low]
    if srcs and snks:
        return [{"sources": sorted(set(srcs)), "sinks": sorted(set(snks))}]
    return []


SCRIPT_SRC_RE = re.compile(r"<script[^>]+src\s*=\s*[\"']?([^\"'> ]+)", re.IGNORECASE)


def script_srcs(body):
    return SCRIPT_SRC_RE.findall(body)
