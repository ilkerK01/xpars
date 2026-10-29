from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

WORDS = (
    "admin", "login", "api", "config", "backup", "test", "dev",
    "robots.txt", "sitemap.xml", ".git/config", ".env", "wp-admin",
    "wp-login.php", "phpinfo.php", "server-status", "status", "debug",
    "console", "actuator", "actuator/health", "swagger", "swagger-ui.html",
    "api-docs", "graphql", "metrics", "uploads", "backup.zip", "db.sql",
    "old", "staging", "dashboard", "user", "account", "register",
    "search", "readme.md", "info.php", "test.php", ".htaccess",
)

INTERESTING = (200, 204, 301, 302, 307, 401, 403)


def root(url):
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def candidates(base, words=None):
    base = base.rstrip("/") + "/"
    return [base + w for w in (words or WORDS)]


def classify(status):
    return status in INTERESTING


def scan(client, base, words=None):
    out = []
    r = root(base)
    if not r:
        return out
    catch_all = False
    try:
        rnd = client.get(r + "xpars-zzz-nope404probe")
        catch_all = getattr(rnd, "status_code", 0) == 200
    except Exception:
        catch_all = False
    for u in candidates(r, words):
        try:
            resp = client.get(u)
        except Exception:
            continue
        st = getattr(resp, "status_code", 0)
        if st == 200 and catch_all:
            continue
        if classify(st):
            out.append({"url": u, "status": st})
    return out
