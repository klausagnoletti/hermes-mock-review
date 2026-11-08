"""Tests for mockreview.selfnow, the self-hosted publish server (here.now-shaped API, owner listener split from the public one).

The app is a plain object with an injectable clock, so every guard is tested without sockets:
    app.public(method, path, headers, body, peer) -> Response   (reached through the reverse proxy)
    app.owner(method, path, headers, body, peer)  -> Response   (loopback-only listener)
"""
import io
import json
import tarfile

import pytest

from mockreview import selfnow

HOST = "board.example.test"
PROXY = "10.9.0.2"        # the reverse proxy's address on the service network
CLIENT = "203.0.113.7"


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def make_tar(files, extra=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for ti in extra or []:
            tf.addfile(ti)
    return buf.getvalue()


SITE = {"index.html": b"<html><body>board</body></html>", "state.json": b"{}",
        "rounds/1/A/index.html": b"<script>1</script>"}


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(tmp_path, clock):
    return selfnow.App(data_dir=tmp_path / "data", public_host=HOST, clock=clock,
                       trusted_proxies=(PROXY,), max_records_per_slug=5, max_total_bytes=10_000_000)


def owner(app, method, path, body=b"", headers=None, peer="127.0.0.1"):
    return app.owner(method, path, headers or {}, body, peer)


def public(app, method, path, body=b"", headers=None, peer=PROXY, client=CLIENT):
    h = {"host": HOST, "x-forwarded-for": client}
    h.update(headers or {})
    return app.public(method, path, h, body, peer)


def publish(app, slug="alpha-1", password="pw-correct-horse", files=None):
    r = owner(app, "PUT", f"/publish/{slug}", make_tar(files or SITE))
    assert r.status == 200, r.body
    r = owner(app, "PATCH", f"/publish/{slug}/metadata", json.dumps({"password": password}).encode())
    assert r.status == 200, r.body


def unlock(app, slug="alpha-1", password="pw-correct-horse"):
    r = public(app, "POST", f"/{slug}/unlock", f"password={password}".encode(),
               {"content-type": "application/x-www-form-urlencoded"})
    return r


def cookie_of(resp):
    raw = resp.headers["set-cookie"]
    return raw.split(";", 1)[0]


def insert(app, cookie, body=None, slug="alpha-1", client=CLIENT, idem="k1"):
    body = body or {"token": "t" * 8, "round": 1, "amend": False, "payload": "{}"}
    return public(app, "POST", f"/{slug}/.herenow/data/feedback", json.dumps(body).encode(),
                  {"cookie": cookie, "content-type": "application/json", "idempotency-key": idem}, client=client)


# ---- gate -------------------------------------------------------------------------------------

def test_gate_serves_password_form_without_cookie(app):
    publish(app)
    r = public(app, "GET", "/alpha-1/")
    assert r.status == 401
    assert b'type="password"' in r.body          # browsercheck looks for input[type=password]


def test_unlock_sets_scoped_lax_cookie_and_opens_the_board(app):
    publish(app)
    r = unlock(app)
    assert r.status in (200, 303)
    sc = r.headers["set-cookie"]
    assert "Path=/alpha-1/" in sc and "SameSite=Lax" in sc and "HttpOnly" in sc and "Secure" in sc
    ok = public(app, "GET", "/alpha-1/", headers={"cookie": cookie_of(r)})
    assert ok.status == 200 and b"board" in ok.body


def test_wrong_password_is_refused_and_sets_no_cookie(app):
    publish(app)
    r = unlock(app, password="nope")
    assert r.status == 401 and "set-cookie" not in r.headers


def test_cookie_of_one_slug_does_not_open_another(app):
    publish(app, "alpha-1")
    publish(app, "beta-2")
    c = cookie_of(unlock(app, "alpha-1"))
    assert public(app, "GET", "/beta-2/", headers={"cookie": c}).status == 401


# ---- insert ------------------------------------------------------------------------------------

def test_insert_without_cookie_is_401(app):
    publish(app)
    assert insert(app, "").status == 401


def test_insert_with_cookie_is_stored_and_listed_by_owner(app):
    publish(app)
    c = cookie_of(unlock(app))
    assert insert(app, c).status in (200, 201)
    res = owner(app, "GET", "/publishes/alpha-1/data/feedback?limit=100")
    body = json.loads(res.body)
    assert res.status == 200 and len(body["records"]) == 1
    rec = body["records"][0]
    assert rec["data"]["token"] == "t" * 8 and rec["data"]["round"] == 1 and "id" in rec and "createdAt" in rec
    assert body.get("nextCursor") in (None, "")


def test_same_idempotency_key_gives_one_record_even_after_restart(app, tmp_path, clock):
    publish(app)
    c = cookie_of(unlock(app))
    insert(app, c, idem="same")
    insert(app, c, idem="same")
    app2 = selfnow.App(data_dir=tmp_path / "data", public_host=HOST, clock=clock, trusted_proxies=(PROXY,),
                       max_records_per_slug=5, max_total_bytes=10_000_000)
    insert(app2, c, idem="same")
    assert len(json.loads(owner(app2, "GET", "/publishes/alpha-1/data/feedback").body)["records"]) == 1


def test_payload_over_15000_chars_is_refused(app):
    publish(app)
    c = cookie_of(unlock(app))
    r = insert(app, c, {"token": "t", "round": 1, "amend": False, "payload": "x" * 15001})
    assert r.status in (400, 413)


def test_record_cap_per_slug(app):
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(5):
        assert insert(app, c, idem=f"k{i}", client=f"203.0.113.{i + 10}").status in (200, 201)
    assert insert(app, c, idem="k-over", client="203.0.113.99").status == 409


def test_rate_limit_30_per_hour_per_client_ip(app):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(30):
        assert insert(app, c, idem=f"r{i}").status in (200, 201)
    assert insert(app, c, idem="r30").status == 429


def test_spoofed_forwarded_header_from_a_direct_peer_does_not_reset_the_limit(app):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(30):
        insert(app, c, idem=f"s{i}", client=CLIENT)
    # a peer that is not the proxy sends its own X-Forwarded-For: the header is ignored, the peer is the key
    h = {"host": HOST, "x-forwarded-for": "198.51.100.1", "cookie": c, "content-type": "application/json",
         "idempotency-key": "spoof"}
    body = json.dumps({"token": "t", "round": 1, "amend": False, "payload": "{}"}).encode()
    first = app.public("POST", "/alpha-1/.herenow/data/feedback", h, body, "192.0.2.50")
    assert first.status in (200, 201)         # counted against 192.0.2.50, not 198.51.100.1
    again = app.public("POST", "/alpha-1/.herenow/data/feedback", dict(h, **{"x-forwarded-for": "198.51.100.2",
                                                                              "idempotency-key": "spoof2"}), body, "192.0.2.50")
    assert again.status in (200, 201)
    # the proxied client that already hit the limit is still limited
    assert insert(app, c, idem="s-final", client=CLIENT).status == 429


def test_rate_limit_window_expires(app, clock):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(30):
        insert(app, c, idem=f"w{i}")
    assert insert(app, c, idem="w-over").status == 429
    clock.t += 3601
    assert insert(app, c, idem="w-later").status in (200, 201)


def test_total_bytes_cap_refuses_a_big_upload(tmp_path, clock):
    app = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,),
                      max_total_bytes=1000)
    r = owner(app, "PUT", "/publish/alpha-1", make_tar({"index.html": b"x" * 5000}))
    assert r.status == 413


# ---- host, origin, size ------------------------------------------------------------------------

def test_wrong_host_is_421(app):
    publish(app)
    r = app.public("GET", "/alpha-1/", {"host": "evil.example.test"}, b"", PROXY)
    assert r.status == 421


def test_cross_origin_post_is_403(app):
    publish(app)
    c = cookie_of(unlock(app))
    r = public(app, "POST", "/alpha-1/.herenow/data/feedback", b"{}",
               {"cookie": c, "origin": "https://evil.example.test", "content-type": "application/json"})
    assert r.status == 403


def test_body_over_16kb_is_413_on_the_public_listener(app):
    publish(app)
    c = cookie_of(unlock(app))
    r = public(app, "POST", "/alpha-1/.herenow/data/feedback", b"x" * (16 * 1024 + 1),
               {"cookie": c, "content-type": "application/json"})
    assert r.status == 413


# ---- slugs -------------------------------------------------------------------------------------

@pytest.mark.parametrize("slug", ["alpha-1\n", "../etc", "a/b", "A_B", "x", "-lead", "a" * 82])
def test_bad_slugs_are_refused(app, slug):
    r = owner(app, "PUT", f"/publish/{slug}", make_tar(SITE))
    assert r.status in (400, 404)


# ---- status semantics the poller depends on ---------------------------------------------------

def test_missing_slug_is_404_not_401(app):
    assert owner(app, "GET", "/publishes/ghost-1/data/feedback").status == 404
    assert public(app, "GET", "/ghost-1/").status == 404


def test_owner_listener_refuses_a_non_loopback_peer(app):
    publish(app)
    r = app.owner("GET", "/publishes/alpha-1/data/feedback", {}, b"", "172.18.0.5")
    assert r.status == 403


def test_public_listener_has_no_owner_routes(app):
    publish(app)
    assert public(app, "DELETE", "/publish/alpha-1").status in (404, 405)
    assert public(app, "GET", "/publishes/alpha-1/data/feedback").status in (404, 401)


# ---- tar ---------------------------------------------------------------------------------------

def _info(name, typ=tarfile.REGTYPE, link=""):
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = link
    return ti


@pytest.mark.parametrize("bad", [
    {"../escape.html": b"x"},
    {"/abs.html": b"x"},
    {"a/../../b.html": b"x"},
])
def test_hostile_tar_names_are_refused_and_leave_the_live_site(app, bad):
    publish(app)
    before = public(app, "GET", "/alpha-1/", headers={"cookie": cookie_of(unlock(app))}).body
    r = owner(app, "PUT", "/publish/alpha-1", make_tar(bad))
    assert r.status == 400
    after = public(app, "GET", "/alpha-1/", headers={"cookie": cookie_of(unlock(app))}).body
    assert before == after


def test_symlink_and_hardlink_entries_are_refused(app):
    publish(app)
    for typ in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        data = make_tar({"index.html": b"x"}, extra=[_info("link", typ, "/etc/passwd")])
        assert owner(app, "PUT", "/publish/alpha-1", data).status == 400


def test_a_good_upload_replaces_the_site_atomically(app):
    publish(app)
    r = owner(app, "PUT", "/publish/alpha-1", make_tar({"index.html": b"<html>v2</html>", "state.json": b"{}"}))
    assert r.status == 200
    c = cookie_of(unlock(app))
    assert b"v2" in public(app, "GET", "/alpha-1/", headers={"cookie": c}).body


# ---- prototype isolation -----------------------------------------------------------------------

def test_round_files_carry_the_sandbox_csp(app):
    publish(app)
    c = cookie_of(unlock(app))
    r = public(app, "GET", "/alpha-1/rounds/1/A/index.html", headers={"cookie": c})
    assert r.status == 200
    assert "sandbox" in r.headers["content-security-policy"]
    assert "allow-same-origin" not in r.headers["content-security-policy"]


def test_every_response_has_the_security_headers(app):
    publish(app)
    for r in (public(app, "GET", "/alpha-1/"), public(app, "GET", "/ghost-1/"),
              app.public("GET", "/alpha-1/", {"host": "evil.example.test"}, b"", PROXY)):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "content-security-policy" in r.headers
        assert r.headers["cache-control"] == "no-store"


# ---- delete and retention ----------------------------------------------------------------------

def test_delete_removes_site_and_records(app):
    publish(app)
    c = cookie_of(unlock(app))
    insert(app, c)
    assert owner(app, "DELETE", "/publish/alpha-1").status == 200
    assert owner(app, "GET", "/publishes/alpha-1/data/feedback").status == 404
    assert public(app, "GET", "/alpha-1/").status == 404
    assert owner(app, "DELETE", "/publish/alpha-1").status == 404      # the poller treats 404 as "already gone"


def test_retention_deletes_old_sites_and_their_records(tmp_path, clock):
    app = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=(PROXY,),
                      retention_days=7)
    publish(app)
    c = cookie_of(unlock(app))
    insert(app, c)
    clock.t += 8 * 86400
    assert app.sweep() == 1
    assert owner(app, "GET", "/publishes/alpha-1/data/feedback").status == 404
