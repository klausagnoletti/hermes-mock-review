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
    body = json.dumps({"token": "t", "round": 1, "amend": False, "payload": "{}"}).encode()
    base = {"host": HOST, "cookie": c, "content-type": "application/json"}
    # a peer that is not the proxy rotates its own X-Forwarded-For: the header is ignored, the peer is the key
    for i in range(30):
        h = dict(base, **{"x-forwarded-for": f"198.51.100.{i}", "idempotency-key": f"d{i}"})
        assert app.public("POST", "/alpha-1/.herenow/data/feedback", h, body, "192.0.2.50").status in (200, 201)
    h = dict(base, **{"x-forwarded-for": "198.51.100.250", "idempotency-key": "d-over"})
    assert app.public("POST", "/alpha-1/.herenow/data/feedback", h, body, "192.0.2.50").status == 429
    # a different direct peer is counted on its own
    h = dict(base, **{"x-forwarded-for": "198.51.100.1", "idempotency-key": "d-other"})
    assert app.public("POST", "/alpha-1/.herenow/data/feedback", h, body, "192.0.2.51").status in (200, 201)


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


# ---- guards added after the first implementation pass -----------------------------------------

def test_ten_wrong_passwords_lock_the_client_out_for_the_window(app, clock):
    publish(app)
    for _ in range(10):
        assert unlock(app, password="nope").status == 401
    assert unlock(app, password="pw-correct-horse").status == 429       # even the right one, while locked out
    clock.t += 601
    assert unlock(app, password="pw-correct-horse").status in (200, 303)


@pytest.mark.parametrize("path", ["/alpha-1\n/", "/alpha-1/ ", "/alpha-1/%0a", "/alpha-1/..\\x"])
def test_control_characters_in_a_public_path_are_refused(app, path):
    publish(app)
    r = public(app, "GET", path)
    assert r.status in (400, 404)
    assert b"board" not in r.body


def test_a_new_site_is_locked_until_the_owner_sets_a_password(app):
    owner(app, "PUT", "/publish/alpha-1", make_tar(SITE))
    r = public(app, "GET", "/alpha-1/")
    assert r.status == 401
    assert unlock(app, password="anything-at-all").status == 401


def test_changing_the_password_invalidates_old_cookies(app):
    publish(app)
    c = cookie_of(unlock(app))
    assert public(app, "GET", "/alpha-1/", headers={"cookie": c}).status == 200
    owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": "another-pass-9"}).encode())
    assert public(app, "GET", "/alpha-1/", headers={"cookie": c}).status == 401


def test_null_password_opens_the_board_and_short_password_is_refused(app):
    publish(app)
    r = owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": "short"}).encode())
    assert r.status == 400
    owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": None}).encode())
    assert public(app, "GET", "/alpha-1/").status == 200


def test_list_pagination_returns_a_stable_cursor(app):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(3):
        insert(app, c, idem=f"p{i}", client=f"203.0.113.{i + 20}")
    first = json.loads(owner(app, "GET", "/publishes/alpha-1/data/feedback?limit=2").body)
    assert len(first["records"]) == 2 and first["nextCursor"]
    second = json.loads(owner(app, "GET", f"/publishes/alpha-1/data/feedback?limit=2&cursor={first['nextCursor']}").body)
    assert len(second["records"]) == 1 and second["nextCursor"] in (None, "")
    ids = [r["id"] for r in first["records"] + second["records"]]
    assert ids == sorted(ids) and len(set(ids)) == 3


# ---- real listeners ---------------------------------------------------------------------------

def _serve(app, kind):
    import threading
    srv = selfnow.make_server(app, kind, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_real_listener_refuses_an_oversize_body_before_reading_it(app):
    import http.client
    publish(app)
    srv = _serve(app, "public")
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        c.putrequest("POST", "/alpha-1/.herenow/data/feedback")
        c.putheader("Host", HOST)
        c.putheader("Content-Type", "application/json")
        c.putheader("Content-Length", str(10 * 1024 * 1024))      # promised, never sent
        c.endheaders()
        r = c.getresponse()
        assert r.status == 413 and r.getheader("connection", "").lower() == "close"
    finally:
        srv.shutdown()


def test_real_listener_round_trip_and_headers(tmp_path, clock):
    import http.client
    # peer is 127.0.0.1 for both listeners here; trust it as the proxy so X-Forwarded-For is honoured
    app = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=("127.0.0.1",))
    pub, own = _serve(app, "public"), _serve(app, "owner")
    try:
        oc = http.client.HTTPConnection("127.0.0.1", own.server_address[1], timeout=5)
        oc.request("PUT", "/publish/alpha-1", body=make_tar(SITE))
        assert oc.getresponse().read() and True
        oc = http.client.HTTPConnection("127.0.0.1", own.server_address[1], timeout=5)
        oc.request("PATCH", "/publish/alpha-1/metadata", body=json.dumps({"password": "pw-correct-horse"}))
        assert oc.getresponse().status == 200
        pc = http.client.HTTPConnection("127.0.0.1", pub.server_address[1], timeout=5)
        pc.request("GET", "/alpha-1/", headers={"Host": HOST})
        r = pc.getresponse()
        assert r.status == 401 and r.getheader("x-content-type-options") == "nosniff" and b"password" in r.read()
        pc = http.client.HTTPConnection("127.0.0.1", pub.server_address[1], timeout=5)
        pc.request("DELETE", "/publish/alpha-1", headers={"Host": HOST})
        assert pc.getresponse().status in (404, 405)               # owner routes do not exist publicly
    finally:
        pub.shutdown()
        own.shutdown()


def test_ipv6_clients_in_one_64_share_a_rate_counter(app):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(15):
        assert insert(app, c, idem=f"a{i}", client="2001:db8:1:2::1").status in (200, 201)
        assert insert(app, c, idem=f"b{i}", client="2001:db8:1:2::ffff").status in (200, 201)
    assert insert(app, c, idem="a-over", client="2001:db8:1:2::abcd").status == 429
    assert insert(app, c, idem="other-64", client="2001:db8:1:3::1").status in (200, 201)


def test_hidden_files_in_an_archive_are_refused(app):
    publish(app)
    assert owner(app, "PUT", "/publish/alpha-1", make_tar({"index.html": b"x", ".env": b"secret"})).status == 400


def test_the_client_is_the_rightmost_forwarded_entry_not_a_value_the_client_supplied(app):
    app.max_records_per_slug = 1000
    publish(app)
    c = cookie_of(unlock(app))
    for i in range(30):    # the visitor invents a new leftmost entry each time; the proxy appends the real one
        assert insert(app, c, idem=f"x{i}", client=f"198.51.100.{i}, {CLIENT}").status in (200, 201)
    assert insert(app, c, idem="x-over", client="198.51.100.200, " + CLIENT).status == 429


# ---- secrets never echoed -------------------------------------------------------------------

PLANTED = "Planted-Secret-pw-7731"


def _everything(resp):
    return (resp.body.decode("utf-8", "replace") + " " +
            " ".join(f"{k}: {v}" for k, v in resp.headers.items() if k != "set-cookie"))


def test_a_planted_password_never_reaches_a_response_or_a_log(app, caplog, capsys, monkeypatch):
    import logging
    caplog.set_level(logging.DEBUG)
    seen = []
    seen.append(owner(app, "PUT", "/publish/alpha-1", make_tar(SITE)))
    seen.append(owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": PLANTED}).encode()))
    seen.append(owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": PLANTED[:5]}).encode()))
    seen.append(unlock(app, password=PLANTED + "x"))                       # wrong password carrying the planted text
    seen.append(unlock(app, password=PLANTED))                              # right one: only Set-Cookie may differ
    cookie = cookie_of(seen[-1])
    seen.append(public(app, "GET", "/alpha-1/", headers={"cookie": cookie}))
    seen.append(public(app, "POST", "/alpha-1/.herenow/data/feedback", PLANTED.encode(),
                       {"cookie": cookie, "content-type": "application/json"}))
    seen.append(public(app, "POST", "/alpha-1/unlock", (PLANTED * 2000).encode(),
                       {"content-type": "application/x-www-form-urlencoded"}))        # oversize
    seen.append(owner(app, "GET", "/publishes/alpha-1/data/feedback"))

    def boom(*a, **k):
        raise RuntimeError("explode with " + PLANTED)
    monkeypatch.setattr(app, "_insert", boom)
    seen.append(public(app, "POST", "/alpha-1/.herenow/data/feedback", b"{}",
                       {"cookie": cookie, "content-type": "application/json"}))          # the generic 500 path
    assert seen[-1].status == 500
    for r in seen:
        assert PLANTED not in _everything(r)
    out = capsys.readouterr()
    assert PLANTED not in out.out + out.err + caplog.text
    sc = seen[4].headers["set-cookie"]
    assert PLANTED not in sc and "gate=" in sc


def test_the_password_and_cookie_key_are_not_stored_in_clear(app, tmp_path):
    owner(app, "PUT", "/publish/alpha-1", make_tar(SITE))
    owner(app, "PATCH", "/publish/alpha-1/metadata", json.dumps({"password": PLANTED}).encode())
    for f in (tmp_path / "data").rglob("*"):
        if f.is_file() and f.name != "cookie.key":
            assert PLANTED.encode() not in f.read_bytes()
    assert (tmp_path / "data" / "cookie.key").stat().st_mode & 0o077 == 0     # key file is private


# ---- CIDR peers (container networks hand out dynamic addresses) ----------------------------------

def test_proxy_and_owner_peers_accept_cidr_ranges(tmp_path, clock):
    app = selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock,
                      trusted_proxies=("10.9.0.0/24",), owner_peers=("127.0.0.1", "172.19.0.1/32", "fd00:1::/64"))
    assert app._client({"x-forwarded-for": "203.0.113.9"}, "10.9.0.77") == "203.0.113.9"      # inside the range
    assert app._client({"x-forwarded-for": "203.0.113.9"}, "10.9.1.77") == "10.9.1.77"        # just outside
    assert owner(app, "GET", "/publishes/x1/data/feedback", peer="172.19.0.1").status == 404   # allowed, no such slug
    assert owner(app, "GET", "/publishes/x1/data/feedback", peer="172.19.0.5").status == 403
    assert owner(app, "GET", "/publishes/x1/data/feedback", peer="fd00:1::5").status == 404
    assert owner(app, "GET", "/publishes/x1/data/feedback", peer="not-an-address").status == 403
    assert owner(app, "GET", "/publishes/x1/data/feedback", peer="10.9.0.77").status == 403    # the proxy is not the owner


def test_a_bad_network_in_settings_fails_at_start(tmp_path, clock):
    with pytest.raises(ValueError):
        selfnow.App(data_dir=tmp_path / "d", public_host=HOST, clock=clock, trusted_proxies=("not-a-network",))
