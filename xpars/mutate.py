from __future__ import annotations

import re

TAG_RE = re.compile(r"<\s*([A-Za-z][A-Za-z0-9]*)")


def _case_mix(s):
    out = []
    upper = True
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if upper else ch.lower())
            upper = not upper
        else:
            out.append(ch)
    return "".join(out)


def _spaces_to_slash(s):
    return re.sub(r"<([A-Za-z][A-Za-z0-9]*)\s+", lambda m: "<" + m.group(1) + "/", s, count=1)


def _space_variants(s):
    out = []
    for sep in ("\t", "\x0c", "\n", "/"):
        if " " in s:
            out.append(s.replace(" ", sep, 1))
    return out


def _backtick_call(s):
    return re.sub(r"alert\((\d+)\)", r"alert`\1`", s)


def _comment_split_tag(s):
    m = TAG_RE.search(s)
    if not m:
        return None
    name = m.group(1)
    if len(name) < 2:
        return None
    split = "<" + name[0] + "<" + name + ">" + name[1:]
    return s.replace("<" + name, split, 1)


def _entity_scheme(s):
    if "javascript:" not in s.lower():
        return None
    return re.sub(r"javascript:", "javascript&colon;", s, flags=re.IGNORECASE)


def variants(payload, char_map=None):
    out = []
    seen = set()

    def add(v):
        if v and v != payload and v not in seen:
            seen.add(v)
            out.append(v)

    add(_case_mix(payload))
    add(_spaces_to_slash(payload))
    for v in _space_variants(payload):
        add(v)
    add(_backtick_call(payload))
    add(_comment_split_tag(payload))
    add(_entity_scheme(payload))

    blocked_paren = char_map is not None and not char_map.get("(", True)
    if blocked_paren:
        prioritized = [v for v in out if "`" in v]
        rest = [v for v in out if "`" not in v]
        out = prioritized + rest
    return out
