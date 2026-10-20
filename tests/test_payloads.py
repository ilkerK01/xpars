from __future__ import annotations

from xpars import payloads


def test_default_has_core_vectors():
    assert '"><svg onload=alert(1)>' in payloads.DEFAULT
    assert '<img src=x onerror=alert(1)>' in payloads.DEFAULT


def test_for_context_prioritizes_context():
    out = payloads.for_context("script")
    assert out[0] in payloads.CONTEXT_PAYLOADS["script"]
    assert '"><svg onload=alert(1)>' in out


def test_load_full_is_large_and_clean():
    pl = payloads.load_full()
    assert len(pl) > 4000
    assert all("xss0r" not in p.lower() for p in pl)
    assert any("svg onload=alert(1)" in p.lower() for p in pl)


def test_load_full_no_oob_to_vendor():
    pl = payloads.load_full()
    assert not any("xss0r.com" in p.lower() for p in pl)
