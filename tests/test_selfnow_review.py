"""Tests for the findings of the independent security review of selfnow (docs: the review seats' reports sit in the
owner's plan folder, not in this repository). Each test names the defect it pins."""
import http.client
import json
import socket
import threading
import time

import pytest

from mockreview import selfnow
from test_selfnow import (CLIENT, HOST, PROXY, SITE, app, clock, cookie_of, insert, make_tar, owner, public,  # noqa: F401
                          publish, unlock)


def get(app, path, cookie=None, method="GET"):
    return public(app, method, path, headers={"cookie": cookie} if cookie else None)


# ---- round sandbox cannot be skipped with empty path segments ------------------------------------

@pytest.mark.parametrize("path", ["/alpha-1/rounds/1/A/index.html", "/alpha-1//rounds/1/A/index.html",
                                  "/alpha-1///rounds/1/A/index.html", "/alpha-1/rounds//1//A/index.html"])
def test_round_files_always_get_the_sandbox_csp(app, path):
    publish(app)
    c = cookie_of(unlock(app))
    r = get(app, path, c)
    assert r.status == 200 and r.headers["content-security-policy"] == selfnow.VARIANT_CSP


def test_board_files_keep_the_board_csp(app):
    publish(app)
    r = get(app, "/alpha-1//index.html", cookie_of(unlock(app)))
    assert r.status == 200 and r.headers["content-security-policy"] == selfnow.BOARD_CSP


# ---- the cookie key ------------------------------------------------------------------------------

@pytest.mark.parametrize("content", [b"", b"short", b"x" * 33])
def test_a_cookie_key_of_the_wrong_length_is_replaced_and_stored(tmp_path, clock, content):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "cookie.key").write_bytes(content)
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock)
    assert len(a._secret) == 32 and (tmp_path / "d" / "cookie.key").read_bytes() == a._secret
    assert sorted(p.name for p in (tmp_path / "d").iterdir() if p.name != "sites") == ["cookie.key"]


def test_a_valid_cookie_key_survives_a_restart(tmp_path, clock):
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,))
    publish(a)
    c = cookie_of(unlock(a))
    b = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,))
    assert b._secret == a._secret and get(b, "/alpha-1/", c).status == 200


# ---- the gate cookie is bound to one site lifetime and expires ----------------------------------

def test_a_cookie_from_a_deleted_board_does_not_open_a_recreated_one(app):
    publish(app)
    old = cookie_of(unlock(app))
    assert owner(app, "DELETE", "/publish/alpha-1").status == 200
    publish(app)
    assert get(app, "/alpha-1/", old).status == 401
    assert get(app, "/alpha-1/", cookie_of(unlock(app))).status == 200


def test_two_site_lifetimes_have_different_salts(app):
    publish(app)
    first = app._meta("alpha-1")["gate_salt"]
    owner(app, "DELETE", "/publish/alpha-1")
    publish(app)
    assert app._meta("alpha-1")["gate_salt"] != first and len(first) >= 32


def test_a_republish_keeps_the_salt_so_reviewers_stay_unlocked(app):
    publish(app)
    c = cookie_of(unlock(app))
    assert owner(app, "PUT", "/publish/alpha-1", make_tar(SITE)).status == 200
    assert get(app, "/alpha-1/", c).status == 200


def test_the_cookie_expires(app, clock):
    publish(app)
    c = cookie_of(unlock(app))
    clock.t += selfnow.COOKIE_TTL_S - 1
    assert get(app, "/alpha-1/", c).status == 200
    clock.t += 2
    assert get(app, "/alpha-1/", c).status == 401


def test_a_tampered_cookie_expiry_is_refused(app, clock):
    publish(app)
    value = cookie_of(unlock(app)).split("=", 1)[1]
    issued, _, mac = value.partition(".")
    assert mac, "cookie value must be <issued>.<mac>"
    clock.t += selfnow.COOKIE_TTL_S + 5
    assert get(app, "/alpha-1/", "gate=" + value).status == 401          # expired as issued
    forged = "gate=%d.%s" % (int(clock.t) - 10, mac)                       # same signature, fresh-looking stamp
    assert get(app, "/alpha-1/", forged).status == 401


@pytest.mark.parametrize("value", ["gate=", "gate=abc", "gate=.", "gate=1.", "gate=x.y", "gate=-5.abcd", "gate=1.2.3"])
def test_malformed_cookies_are_refused_not_crashed(app, value):
    publish(app)
    assert get(app, "/alpha-1/", value).status == 401


# ---- feedback inserts are serialised --------------------------------------------------------------

def _burst(n, fn):
    barrier = threading.Barrier(n)
    out = [None] * n

    def run(i):
        barrier.wait()
        out[i] = fn(i)
    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    return out


def test_concurrent_inserts_are_all_stored_with_unique_ids(tmp_path, clock):
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,),
                    max_records_per_slug=1000)
    publish(a)
    c = cookie_of(unlock(a))
    res = _burst(40, lambda i: insert(a, c, idem=f"k{i}", client=f"203.0.113.{i + 10}"))
    assert [r.status for r in res].count(200) == 40
    ids = {json.loads(r.body)["id"] for r in res}
    stored = json.loads(owner(a, "GET", "/publishes/alpha-1/data/feedback").body)["records"]
    assert len(ids) == 40 and len(stored) == 40 and {r["id"] for r in stored} == ids


def test_concurrent_inserts_with_one_idempotency_key_store_one_record(tmp_path, clock):
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,),
                    max_records_per_slug=1000)
    publish(a)
    c = cookie_of(unlock(a))
    res = _burst(20, lambda i: insert(a, c, idem="same", client=f"203.0.113.{i + 10}"))
    assert [r.status for r in res].count(200) == 20 and len({json.loads(r.body)["id"] for r in res}) == 1
    assert len(json.loads(owner(a, "GET", "/publishes/alpha-1/data/feedback").body)["records"]) == 1


def test_an_insert_respects_the_total_store_cap(app):
    publish(app)
    c = cookie_of(unlock(app))
    app.max_total_bytes = app._total_bytes() + 50
    assert insert(app, c).status == 507


# ---- request framing on the real listener ---------------------------------------------------------

def _raw(port, payload, wait=1.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(payload)
    s.settimeout(wait)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data


@pytest.fixture
def pub(app):
    publish(app)
    srv = selfnow.make_server(app, "public", "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


GET = ("GET /alpha-1/ HTTP/1.1\r\nHost: %s\r\n" % HOST).encode()


@pytest.mark.parametrize("method", ["GET", "HEAD", "DELETE", "OPTIONS"])
def test_a_body_on_a_bodyless_method_closes_the_connection_instead_of_desyncing(pub, method):
    smuggled = GET + b"\r\n"
    req = ("%s /alpha-1/ HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n" % (method, HOST, len(smuggled))).encode() + smuggled
    out = _raw(pub, req)
    assert out.count(b"HTTP/1.1 ") == 1 and b"connection: close" in out.lower()


def test_transfer_encoding_is_refused(pub):
    req = ("POST /alpha-1/unlock HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % HOST).encode()
    out = _raw(pub, req)
    assert out.startswith(b"HTTP/1.1 400") and b"connection: close" in out.lower()


def test_a_normal_keepalive_request_still_answers_twice_on_one_connection(pub):
    c = http.client.HTTPConnection("127.0.0.1", pub, timeout=5)
    for _ in range(2):
        c.request("GET", "/alpha-1/", headers={"Host": HOST})
        r = c.getresponse()
        r.read()
        assert r.status == 401


# ---- path without the trailing slash ---------------------------------------------------------------

@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_a_board_url_without_the_slash_redirects_so_relative_links_work(app, method):
    publish(app)
    r = get(app, "/alpha-1", method=method)
    assert r.status == 308 and r.headers["location"] == "/alpha-1/"
    assert get(app, "/alpha-1/").status == 401


# ---- password hashing cannot exhaust memory --------------------------------------------------------

def test_at_most_two_password_hashes_run_at_once(app, monkeypatch):
    publish(app)
    gate, inside, peak, lock = threading.Event(), [0], [0], threading.Lock()

    def slow(cls_or_pw, *a):
        with lock:
            inside[0] += 1
            peak[0] = max(peak[0], inside[0])
        gate.wait(10)
        with lock:
            inside[0] -= 1
        return False
    monkeypatch.setattr(selfnow.App, "_check_password", classmethod(lambda cls, pw, stored: slow(pw)))
    monkeypatch.setattr(selfnow, "SCRYPT_WAIT_S", 20)
    out = []
    ts = [threading.Thread(target=lambda i=i: out.append(public(app, "POST", "/alpha-1/unlock", b"password=wrong%d" % i,
                           {"content-type": "application/x-www-form-urlencoded"}, client=f"203.0.113.{i + 10}"))) for i in range(6)]
    for t in ts:
        t.start()
    time.sleep(0.5)
    assert peak[0] == 2
    gate.set()
    for t in ts:
        t.join(20)
    assert [r.status for r in out] == [401] * 6


def test_a_busy_hasher_answers_503_not_a_hang(app, monkeypatch):
    publish(app)
    gate = threading.Event()
    monkeypatch.setattr(selfnow.App, "_check_password", classmethod(lambda cls, pw, stored: gate.wait(10) and False))
    monkeypatch.setattr(selfnow, "SCRYPT_WAIT_S", 0.05)
    ts = [threading.Thread(target=lambda i=i: public(app, "POST", "/alpha-1/unlock", b"password=x",
                           {"content-type": "application/x-www-form-urlencoded"}, client=f"203.0.113.{i + 10}")) for i in range(2)]
    for t in ts:
        t.start()
    time.sleep(0.3)
    r = public(app, "POST", "/alpha-1/unlock", b"password=x", {"content-type": "application/x-www-form-urlencoded"}, client="203.0.113.99")
    gate.set()
    for t in ts:
        t.join(10)
    assert r.status == 503


def test_a_failed_guess_counts_before_the_hash_finishes(app, monkeypatch):
    publish(app)
    gate = threading.Event()
    monkeypatch.setattr(selfnow.App, "_check_password", classmethod(lambda cls, pw, stored: gate.wait(10) and False))
    monkeypatch.setattr(selfnow, "SCRYPT_WAIT_S", 20)
    out = []
    ts = [threading.Thread(target=lambda: out.append(public(app, "POST", "/alpha-1/unlock", b"password=x",
                           {"content-type": "application/x-www-form-urlencoded"}))) for _ in range(selfnow.UNLOCK_FAILS + 5)]
    for t in ts:
        t.start()
    time.sleep(0.6)
    refused = [r.status for r in out]            # finished while the hashes are still blocked
    gate.set()
    for t in ts:
        t.join(20)
    assert refused == [429] * 5


def test_a_correct_password_leaves_no_failure_behind(app):
    publish(app)
    assert unlock(app).status == 303
    assert sum(len(v) for v in app._fails.values()) == 0


# ---- counters do not grow without bound ------------------------------------------------------------

def test_expired_failure_and_hit_keys_are_dropped(app, clock, monkeypatch):
    publish(app)
    monkeypatch.setattr(selfnow.App, "_check_password", classmethod(lambda cls, pw, stored: False))
    for i in range(selfnow.GC_ABOVE + 200):
        public(app, "POST", "/alpha-1/unlock", b"password=x", {"content-type": "application/x-www-form-urlencoded"},
               client="2001:db8:%x::1" % i)
    clock.t += selfnow.UNLOCK_WINDOW + 1
    public(app, "POST", "/alpha-1/unlock", b"password=x", {"content-type": "application/x-www-form-urlencoded"}, client="203.0.113.5")
    assert len(app._fails) < 100


def test_expired_insert_keys_are_dropped(tmp_path, clock):
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,), max_records_per_slug=100000)
    publish(a)
    c = cookie_of(unlock(a))
    for i in range(selfnow.GC_ABOVE + 50):
        a._hits[("alpha-1", "198.51.%d.%d" % (i // 250, i % 250))] = [clock.t - selfnow.RATE_WINDOW - 1]
    clock.t += 1
    assert insert(a, c, idem="gc").status == 200
    assert len(a._hits) < 100


# ---- upload robustness ------------------------------------------------------------------------------

def test_conflicting_names_are_a_400_and_leave_nothing_behind(app):
    assert owner(app, "PUT", "/publish/alpha-1", make_tar({"a": b"x", "a/b": b"y"})).status == 400
    assert list(app.sites.iterdir()) == []


def test_a_failed_republish_leaves_the_old_site_and_no_staging(app):
    publish(app)
    assert owner(app, "PUT", "/publish/alpha-1", make_tar({"a": b"x", "a/b": b"y"})).status == 400
    assert not list((app.sites / "alpha-1" / "v").glob("*.staging"))
    assert get(app, "/alpha-1/", cookie_of(unlock(app))).status == 200


def test_the_slug_cap_refuses_a_new_site_but_not_an_update(tmp_path, clock):
    a = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, max_slugs=2)
    assert owner(a, "PUT", "/publish/aa-1", make_tar(SITE)).status == 200
    assert owner(a, "PUT", "/publish/bb-2", make_tar(SITE)).status == 200
    assert owner(a, "PUT", "/publish/cc-3", make_tar(SITE)).status == 409
    assert owner(a, "PUT", "/publish/aa-1", make_tar(SITE)).status == 200
    assert sorted(p.name for p in a.sites.iterdir()) == ["aa-1", "bb-2"]


def test_a_compressed_archive_is_refused(app):
    import gzip
    r = owner(app, "PUT", "/publish/alpha-1", gzip.compress(make_tar(SITE)))
    assert r.status == 400 and b"not a tar" in r.body


def test_one_file_over_the_per_file_cap_is_refused(app):
    big = b"x" * (selfnow.MAX_FILE_BYTES + 1)
    r = owner(app, "PUT", "/publish/alpha-1", make_tar({"index.html": b"x", "big.bin": big}))
    assert r.status == 400 and b"too large" in r.body


def test_the_sweeper_survives_a_meta_file_with_a_bad_timestamp(app, clock):
    publish(app)
    publish(app, slug="beta-2")
    m = app._meta("alpha-1")
    m["updated"] = "yesterday"
    app._save_meta("alpha-1", m)
    clock.t += (app.retention_days + 1) * 86400
    assert app.sweep() == 1 and (app.sites / "alpha-1").exists() and not (app.sites / "beta-2").exists()


# ---- in-flight cap on the public listener -----------------------------------------------------------

def test_the_public_listener_caps_requests_in_flight(app, monkeypatch):
    publish(app)
    monkeypatch.setattr(selfnow, "INFLIGHT", 1)
    monkeypatch.setattr(selfnow, "INFLIGHT_WAIT_S", 0.05)
    gate = threading.Event()
    real = app.public
    monkeypatch.setattr(app, "public", lambda *a, **k: (gate.wait(10), real(*a, **k))[1])
    srv = selfnow.make_server(app, "public", "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        first = threading.Thread(target=lambda: _raw(srv.server_address[1], GET + b"\r\n", wait=3))
        first.start()
        time.sleep(0.3)
        second = _raw(srv.server_address[1], GET + b"\r\n", wait=2)
        assert second.startswith(b"HTTP/1.1 503")
        gate.set()
        first.join(10)
        assert _raw(srv.server_address[1], GET + b"Connection: close\r\n\r\n").startswith(b"HTTP/1.1 401")
    finally:
        gate.set()
        srv.shutdown()


# ---- deploy files ------------------------------------------------------------------------------------

def test_the_image_is_pinned_by_digest_and_the_container_has_an_init_and_no_swap():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "deploy" / "selfnow"
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    assert any(l.startswith("FROM ") and "@sha256:" in l for l in dockerfile.splitlines())
    assert "init: true" in compose and "memswap_limit: 256m" in compose
