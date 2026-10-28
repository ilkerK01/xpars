from __future__ import annotations

import sys
import threading
import time
from urllib.parse import urlsplit

import requests

MAX_BYTES = 8_000_000


def _retry_after(resp, attempt):
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return min(10.0, float(ra))
        except Exception:
            pass
    return min(8.0, 1.0 * (2 ** attempt))


class Client:
    def __init__(self, timeout=10.0, delay=0.0, headers=None, cookie=None,
                 user_agent=None, retries=1, proxy=None, verify=True,
                 max_bytes=MAX_BYTES, rps=0.0, verbose=False, logpath=None):
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.max_bytes = max_bytes
        self.verbose = verbose
        self._logfh = None
        if logpath:
            try:
                self._logfh = open(logpath, "a", encoding="utf-8")
                self._logfh.write("\n# xpars %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
                self._logfh.flush()
            except Exception:
                self._logfh = None
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._host_last = {}
        self._rlock = threading.Lock()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent or "xpars/0.1"
        self.session.verify = verify
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        if cookie:
            self.session.headers["Cookie"] = cookie
        for raw in headers or []:
            key, _, value = raw.partition(":")
            if key.strip():
                self.session.headers[key.strip()] = value.strip()

    def _read_capped(self, resp):
        try:
            raw = resp.raw.read(self.max_bytes + 1, decode_content=True)
        except Exception:
            return
        if raw is not None:
            resp._content = raw[:self.max_bytes]
            resp._content_consumed = True

    def _log(self, method, url, status):
        if not self.verbose and self._logfh is None:
            return
        try:
            u = url if len(url) <= 180 else url[:177] + "..."
            line = "[req] %-4s %s -> %s\n" % (method, u, status)
            if self.verbose:
                try:
                    sys.stderr.write(line)
                except UnicodeEncodeError:
                    sys.stderr.write(line.encode("ascii", "replace").decode("ascii"))
                sys.stderr.flush()
            if self._logfh is not None:
                try:
                    self._logfh.write(line)
                    self._logfh.flush()
                except Exception:
                    pass
        except Exception:
            pass

    def _throttle(self, url):
        if self.min_interval <= 0:
            return
        try:
            host = urlsplit(url).hostname or ""
        except Exception:
            host = ""
        while True:
            with self._rlock:
                now = time.monotonic()
                wait = self.min_interval - (now - self._host_last.get(host, 0.0))
                if wait <= 0:
                    self._host_last[host] = now
                    return
            time.sleep(wait)

    def request(self, method, url, data=None, json=None, headers=None, files=None):
        self._throttle(url)
        last = None
        for attempt in range(self.retries + 1):
            try:
                resp = self.session.request(method, url, data=data, json=json,
                                            files=files, headers=headers,
                                            timeout=self.timeout,
                                            allow_redirects=True, stream=True)
            except Exception as exc:
                last = exc
                self._log(method, url, "err: " + type(exc).__name__)
                continue
            if resp.status_code in (429, 502, 503, 504) and attempt < self.retries:
                wait = _retry_after(resp, attempt)
                self._log(method, url, "%d retry" % resp.status_code)
                try:
                    resp.close()
                except Exception:
                    pass
                last = resp
                time.sleep(wait)
                continue
            self._read_capped(resp)
            self._log(method, url, resp.status_code)
            if self.delay:
                time.sleep(self.delay)
            return resp
        if isinstance(last, Exception):
            raise last
        return last

    def get(self, url, headers=None):
        return self.request("GET", url, headers=headers)

    def post(self, url, data, multipart=False):
        if multipart:
            files = {k: (None, "" if v is None else str(v)) for k, v in data.items()}
            return self.request("POST", url, files=files)
        return self.request("POST", url, data=data)

    def post_json(self, url, obj):
        return self.request("POST", url, json=obj)
