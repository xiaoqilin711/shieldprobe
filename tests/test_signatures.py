"""Tests for the signature-matching logic."""
from shieldprobe.signatures import Evidence, detect, SIGNATURES


def _sig(sid: str):
    return next(s for s in SIGNATURES if s.id == sid)


def test_vm_challenge_detected():
    ev = Evidence(
        status_code=412,
        set_cookie_names=["4hP44ZykCTt5O"],
        html="<meta r='m'>",
        js="if($_ts.cd){ while(1){ } }",
        dynamic_scripts=["/tQrlMwxgEtCS/xsWaJeZftrRw.294cc83.js"],
    )
    hits = detect(ev)
    ids = [s.id for s, _ in hits]
    assert "vm-js-challenge" in ids


def test_cloudflare_challenge_detected():
    ev = Evidence(
        status_code=503,
        set_cookie_names=["__cf_bm"],
        html="checking your browser",
        js="setTimeout",
    )
    ids = [s.id for s, _ in detect(ev)]
    assert "cloudflare-js-challenge" in ids


def test_akamai_detected():
    ev = Evidence(
        status_code=200,
        set_cookie_names=["_abck", "bm_sz"],
        js="sensor_data",
    )
    ids = [s.id for s, _ in detect(ev)]
    assert "akamai-bot-manager" in ids


def test_random_cookie_name_heuristic():
    ev = Evidence(set_cookie_names=["4hP44ZykCTt5O"])
    assert ev.has_random_cookie_name is True
    ev2 = Evidence(set_cookie_names=["sessionid"])
    assert ev2.has_random_cookie_name is False


def test_no_false_positive_on_plain_page():
    ev = Evidence(status_code=200, html="<html>ok</html>", js="")
    hits = detect(ev)
    assert hits == []
