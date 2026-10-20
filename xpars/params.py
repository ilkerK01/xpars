from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

COMMON_PARAMS = [
    "q", "s", "search", "id", "page", "p", "url", "redirect", "redir", "next",
    "return", "returnurl", "r", "u", "query", "keyword", "lang", "ref", "callback",
    "name", "file", "path", "dir", "category", "cat", "item", "view", "type", "sort",
    "filter", "year", "month", "day", "debug", "test", "msg", "message", "error", "data",
    "title", "content", "html", "text", "value", "input", "email", "token", "key",
]


def injectable(url):
    parts = urlsplit(url)
    return [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]


def set_param(url, name, value):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    query = urlencode(new_pairs, safe="")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def add_param(url, name, value):
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs.append((name, value))
    query = urlencode(pairs, safe="")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def path_segments(url):
    parts = urlsplit(url)
    segs = parts.path.split("/")
    return [(i, s) for i, s in enumerate(segs) if s and "." not in s]


def set_path_segment(url, idx, value):
    parts = urlsplit(url)
    segs = parts.path.split("/")
    if idx < 0 or idx >= len(segs):
        return url
    segs = list(segs)
    segs[idx] = value
    newpath = "/".join(segs)
    return urlunsplit((parts.scheme, parts.netloc, newpath, parts.query, parts.fragment))


def brute_candidates(url, names=None):
    out = []
    for name in (names or COMMON_PARAMS):
        out.append(add_param(url, name, "1"))
    return out
