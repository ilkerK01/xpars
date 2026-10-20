from __future__ import annotations

from urllib.parse import urlsplit

DENY_DEFAULT = ("europa.eu", "unesco.org")


def host_of(url):
    return (urlsplit(url).hostname or "").lower()


def _match(host, patterns):
    for p in patterns:
        p = p.lower()
        if host == p or host.endswith("." + p):
            return True
    return False


class Scope:
    def __init__(self, allow=None, deny=None):
        self.allow = [h.lower() for h in (allow or [])]
        self.deny = [h.lower() for h in (deny or [])]

    def permitted(self, url):
        host = host_of(url)
        if not host:
            return False
        if _match(host, self.deny) or _match(host, DENY_DEFAULT):
            return False
        if self.allow and not _match(host, self.allow):
            return False
        return True

    def reason(self, url):
        host = host_of(url)
        if not host:
            return "gecersiz host"
        if _match(host, self.deny) or _match(host, DENY_DEFAULT):
            return "denylist (yasak kapsam)"
        if self.allow and not _match(host, self.allow):
            return "allowlist disinda"
        return "izinli"
