from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import requests

MAX_BYTES = 3_000_000


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
                 max_bytes=MAX_BYTES, rps=0.0):
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.max_bytes = max_bytes
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

    def _throttle(self, url):
        if self.min_interval <= 0:
            return
        host = urlsplit(url).hostname or ""
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
                continue
            if resp.status_code in (429, 502, 503, 504) and attempt < self.retries:
                wait = _retry_after(resp, attempt)
                try:
                    resp.close()
                except Exception:
                    pass
                last = resp
                time.sleep(wait)
                continue
            self._read_capped(resp)
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
