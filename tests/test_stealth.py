from xpars import http, scanner


def test_stealth_profile_levels():
    assert http.stealth_profile("high")["rps"] == 0.5
    assert http.stealth_profile("high")["jitter"] > http.stealth_profile("low")["jitter"]
    assert http.stealth_profile("medium")["delay"] > 0
    assert http.stealth_profile(None)["jitter"] == 0.0
    assert http.stealth_profile("yok")["rps"] == 0.0


def test_client_accepts_jitter():
    c = http.Client(jitter=0.5)
    assert c.jitter == 0.5


def test_spray_round_robin():
    urls = ["http://a/1", "http://a/2", "http://b/1", "http://a/3", "http://b/2"]
    out = scanner.spray_order(urls)
    assert len(out) == 5
    assert out[0].split("/")[2] != out[1].split("/")[2]


def test_spray_single_host():
    urls = ["http://a/1", "http://a/2", "http://a/3"]
    assert scanner.spray_order(urls) == urls
