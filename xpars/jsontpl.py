from __future__ import annotations

import copy
import json


def parse(text):
    return json.loads(text)


def leaves(obj, prefix=()):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += leaves(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += leaves(v, prefix + (i,))
    elif isinstance(obj, str):
        out.append(prefix)
    return out


def set_at(obj, path, value):
    if not path:
        return value
    clone = copy.deepcopy(obj)
    cur = clone
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return clone
