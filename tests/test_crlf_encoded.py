from xpars import crlf, params


def test_set_param_raw_keeps_encoding():
    url = params.set_param_raw("http://ex.com/a?x=1", "x", "%0d%0aSet-Cookie:z=1")
    assert "x=%0d%0aSet-Cookie:z=1" in url
    assert "%250d" not in url


def test_set_param_raw_other_params_encoded():
    url = params.set_param_raw("http://ex.com/a?x=1&y=a b", "x", "%0a")
    assert "y=a%20b" in url


def test_encoded_vectors_present():
    vs = crlf.encoded_vectors("abc")
    assert vs
    assert all(v[0] == "crlf-encoded" for v in vs)
    assert any("%E5%98%8A" in v[1] for v in vs)
    assert any(v[1].startswith("%0d%0a") for v in vs)


def test_encoded_severity_high():
    assert crlf.SEVERITY["crlf-encoded"] == "high"
    assert crlf.HOW["crlf-encoded"] == "crlf-encoded-bypass"
