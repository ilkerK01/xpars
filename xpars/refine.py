from __future__ import annotations

import re
from urllib.parse import (SplitResult, parse_qsl, urlencode, urljoin, urlsplit,
                          urlunsplit)

STATIC_EXT = {"css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
              "ttf", "eot", "pdf", "zip", "rar", "gz", "mp4", "webm", "webp",
              "map", "bmp", "mp3", "avi", "mov", "otf"}
NUM_RE = re.compile(r"^\d+$")
_EMPTY_SPLIT = SplitResult("", "", "", "", "")


def safe_split(url):
    try:
        return urlsplit(url)
    except Exception:
        return _EMPTY_SPLIT


def safe_join(base, ref):
    try:
        return urljoin(base, ref)
    except Exception:
        return None


def safe_port(parts):
    try:
        return parts.port
    except Exception:
        return None


def host(url):
    return (safe_split(url).hostname or "").lower()


def registered_domain(h):
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _ext(path):
    last = path.rsplit("/", 1)[-1]
    return last.rsplit(".", 1)[-1].lower() if "." in last else ""


def normalize(url):
    parts = safe_split(url)
    scheme = (parts.scheme or "http").lower()
    h = (parts.hostname or "").lower()
    port = safe_port(parts)
    netloc = h
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = "%s:%d" % (h, port)
    pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((scheme, netloc, parts.path or "/", urlencode(pairs), ""))


def _pattern_key(url, collapse_numbers=True):
    parts = urlsplit(url)
    path = parts.path
    if collapse_numbers:
        path = "/".join("N" if NUM_RE.match(s) else s for s in path.split("/"))
    names = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
    return (parts.scheme, parts.netloc, path, names)


def refine(urls, params_only=False, drop_static=True, dedup=True, collapse_numbers=False):
    out = []
    seen_exact = set()
    seen_pattern = set()
    for raw in urls:
        try:
            n = normalize(raw)
        except Exception:
            continue
        parts = urlsplit(n)
        if drop_static and _ext(parts.path) in STATIC_EXT:
            continue
        if params_only and not parts.query:
            continue
        if n in seen_exact:
            continue
        seen_exact.add(n)
        if dedup:
            key = _pattern_key(n, collapse_numbers)
            if key in seen_pattern:
                continue
            seen_pattern.add(key)
        out.append(n)
    return out
