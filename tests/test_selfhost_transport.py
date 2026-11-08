"""The selfhost owner transport: herenow._api and publish() go through ssh to a forced-command wrapper that runs a fixed
curl against the loopback-published owner listener of mockreview.selfnow. No test here opens a network connection to
anything except a loopback listener started by the test."""
import io
import json
import os
import subprocess
import tarfile
import threading
from pathlib import Path

import pytest

from mockreview import config, herenow, selfnow, store
from mockreview.store import ReviewError

ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "deploy" / "selfnow" / "owner-ssh.sh"
BASE = "https://boards.example.test"


@pytest.fixture
def selfhost(monkeypatch):
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_SSH", "ownerbox")
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_BASE", BASE)


class FakeSsh:
    """Replaces subprocess.run inside herenow; records every call, answers from a queue of (returncode, stdout)."""

    def __init__(self, *answers):
        self.answers = list(answers) or [(0, b'{"ok": true}\nSTATUS 200\n')]
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append({"argv": list(argv), "input": kw.get("input"), "kw": kw})
        rc, out = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr=b"permission denied SECRET-STDERR-TEXT")


def use_ssh(monkeypatch, *answers):
    fake = FakeSsh(*answers)
    monkeypatch.setattr(herenow.subprocess, "run", fake)
    return fake


# ---- _api over ssh -----------------------------------------------------------------------------

def test_api_runs_one_fixed_ssh_command_and_parses_the_body(selfhost, monkeypatch):
    fake = use_ssh(monkeypatch, (0, b'{"records": []}\nSTATUS 200\n'))
    assert herenow._api("GET", "/publishes/alpha-1/data/feedback?limit=100") == {"records": []}
    argv = fake.calls[0]["argv"]
    assert argv[0] == "ssh" and "BatchMode=yes" in argv and "ConnectTimeout=10" in argv
    assert "-T" in argv and "ClearAllForwardings=yes" in argv and argv.index("-T") < argv.index("--")
    assert argv[-3:] == ["--", "ownerbox", "GET /publishes/alpha-1/data/feedback?limit=100"]
    assert fake.calls[0]["kw"].get("shell") is not True


def test_api_never_touches_http_or_the_here_now_key_when_selfhost_is_set(selfhost, monkeypatch):
    use_ssh(monkeypatch)
    monkeypatch.setattr(herenow.urllib.request, "urlopen", lambda *a, **k: pytest.fail("http used"))
    monkeypatch.setattr(herenow.secrets, "get_secret", lambda *a, **k: pytest.fail("secret read"))
    assert herenow._api("DELETE", "/publish/alpha-1") == {"ok": True}


def test_http_status_from_the_wrapper_becomes_the_error_status(selfhost, monkeypatch):
    use_ssh(monkeypatch, (0, b'{"ok": false, "error": "not found"}\nSTATUS 404\n'))
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 404


def test_delete_site_treats_a_404_as_already_gone(selfhost, monkeypatch):
    use_ssh(monkeypatch, (0, b'{"ok": false}\nSTATUS 404\n'))
    assert herenow.delete_site("alpha-1") is False


def test_ssh_failure_is_a_502_and_never_echoes_stderr(selfhost, monkeypatch):
    use_ssh(monkeypatch, (255, b""))
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 502 and "SECRET-STDERR-TEXT" not in str(e.value)


def test_ssh_timeout_is_a_504(selfhost, monkeypatch):
    def boom(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)
    monkeypatch.setattr(herenow.subprocess, "run", boom)
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 504


def test_garbled_wrapper_output_is_a_502(selfhost, monkeypatch):
    use_ssh(monkeypatch, (0, b"no status line here"))
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 502


def test_a_nonzero_ssh_exit_is_an_error_even_when_the_output_looks_fine(selfhost, monkeypatch):
    use_ssh(monkeypatch, (1, b'{"ok": true}\nSTATUS 200\n'))
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 502


def test_a_success_status_with_a_body_that_is_not_json_is_a_502(selfhost, monkeypatch):
    use_ssh(monkeypatch, (0, b"<html>not json</html>\nSTATUS 200\n"))
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 502


@pytest.mark.parametrize("method", ["POST", "OPTIONS", "put", "HEAD", "PUT ", ""])
def test_a_method_outside_the_four_is_refused_before_ssh(selfhost, monkeypatch, method):
    fake = use_ssh(monkeypatch)
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api(method, "/publish/alpha-1")
    assert e.value.status == 400 and fake.calls == []


def test_the_uploaded_tar_holds_only_plain_visible_files_with_normalised_owner_and_mode(tmp_path):
    site = tmp_path / "site"
    (site / "sub").mkdir(parents=True)
    (site / ".hidden-dir").mkdir()
    (site / "a.txt").write_text("a", encoding="utf-8")
    (site / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (site / "a.txt").chmod(0o600)
    (site / ".manifest").write_text("m", encoding="utf-8")
    (site / ".hidden-dir" / "c.txt").write_text("c", encoding="utf-8")
    (site / "sub" / ".x").write_text("x", encoding="utf-8")
    (site / "link.txt").symlink_to(site / "a.txt")
    with tarfile.open(fileobj=io.BytesIO(herenow._tar_site(site))) as tf:
        members = tf.getmembers()
    assert sorted(m.name for m in members) == ["a.txt", "sub/b.txt"]
    assert all(m.isreg() and m.uid == 0 and m.gid == 0 and m.uname == "" and m.gname == "" and m.mode == 0o644
               for m in members)


@pytest.mark.parametrize("path", ["/publish/alpha-1\n", "/publish/alpha-1 x", "/publish/../x", "publish/alpha-1",
                                  "/publish/alpha-1;id", "/publish/ALPHA", "/publishes/a/data/feedback?limit=1&x=$(id)"])
def test_a_path_that_could_inject_into_the_remote_command_is_refused_before_ssh(selfhost, monkeypatch, path):
    fake = use_ssh(monkeypatch)
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", path)
    assert e.value.status == 400 and fake.calls == []


@pytest.mark.parametrize("alias", ["-oProxyCommand=touch x", "a b", "a;b", "", "x" * 80, "host\nname"])
def test_a_bad_ssh_alias_is_refused_before_ssh(monkeypatch, alias):
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_SSH", alias)
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_BASE", BASE)
    fake = use_ssh(monkeypatch)
    if alias == "":
        monkeypatch.setattr(herenow.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        monkeypatch.setattr(herenow.secrets, "get_secret", lambda *a, **k: None)   # unset: the plain here.now path
        with pytest.raises(herenow.HereNowError):
            herenow._api("GET", "/publishes/alpha-1/data/feedback")
        assert fake.calls == []
        return
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 409 and fake.calls == []


@pytest.mark.parametrize("base", ["", "http://boards.example.test", "boards.example.test", "https://", "ftp://x.test"])
def test_a_selfhost_alias_needs_an_https_base(monkeypatch, base):
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_SSH", "ownerbox")
    monkeypatch.setenv("MOCKREVIEW_SELFHOST_BASE", base)
    fake = use_ssh(monkeypatch)
    with pytest.raises(herenow.HereNowError) as e:
        herenow._api("GET", "/publishes/alpha-1/data/feedback")
    assert e.value.status == 409 and fake.calls == []


# ---- publish over ssh --------------------------------------------------------------------------

@pytest.fixture
def hn_review(env, variants, selfhost):
    specs = [store.parse_variant_spec(v) for v in variants]
    return store.create_review("Public review", "", {"platform": "discord", "chat_id": "1490000000000000002",
                                                     "thread_id": "1490000000000000002"}, "herenow", specs)


def test_publish_uploads_a_tar_without_the_here_now_manifest_and_stores_the_selfhost_url(hn_review, monkeypatch):
    fake = use_ssh(monkeypatch)
    monkeypatch.setattr(config, "herenow_publish_script", lambda: pytest.fail("here-now helper looked up"))
    monkeypatch.setattr(herenow.secrets, "get_secret", lambda *a, **k: pytest.fail("secret read"))
    data = herenow.publish(hn_review["id"], verify=False)
    put = [c for c in fake.calls if c["argv"][-1].startswith("PUT /publish/")]
    assert len(put) == 1
    slug = put[0]["argv"][-1].split("/")[-1]
    assert selfnow.SLUG_RE.fullmatch(slug)
    with tarfile.open(fileobj=io.BytesIO(put[0]["input"])) as tf:
        names = tf.getnames()
        assert all(m.isreg() or m.isdir() for m in tf.getmembers())
    assert "index.html" in names and "board.js" in names and "state.json" in names
    assert not any(n.split("/")[0].startswith(".") for n in names)
    assert data["herenow"]["slug"] == slug and data["herenow"]["site_url"] == f"{BASE}/{slug}/"


def test_a_republish_reuses_the_slug(hn_review, monkeypatch):
    fake = use_ssh(monkeypatch)
    first = herenow.publish(hn_review["id"], verify=False)["herenow"]["slug"]
    herenow.publish(hn_review["id"], verify=False)
    puts = [c["argv"][-1] for c in fake.calls if c["argv"][-1].startswith("PUT /publish/")]
    assert puts == [f"PUT /publish/{first}", f"PUT /publish/{first}"]


def test_a_failed_upload_is_reported_and_stores_no_url(hn_review, monkeypatch):
    use_ssh(monkeypatch, (0, b'{"ok": false, "error": "store is full"}\nSTATUS 413\n'))
    with pytest.raises(herenow.HereNowError) as e:
        herenow.publish(hn_review["id"], verify=False)
    assert e.value.status == 413
    assert not (store.load(hn_review["id"]).get("herenow", {}).get("site_url") or "").startswith(BASE)


# ---- the forced-command wrapper ----------------------------------------------------------------

@pytest.fixture
def owner_listener(tmp_path):
    app = selfnow.App(data_dir=tmp_path / "d", public_host="boards.example.test")
    srv = selfnow.make_server(app, "owner", "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield app, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def run_wrapper(url, command, stdin=b""):
    env = {"PATH": os.environ["PATH"], "SELFNOW_OWNER_URL": url}
    if command is not None:
        env["SSH_ORIGINAL_COMMAND"] = command
    return subprocess.run(["sh", str(WRAPPER)], input=stdin, capture_output=True, env=env, timeout=60)


def tar_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def status_of(proc):
    return int(proc.stdout.decode().rstrip("\n").rsplit("STATUS ", 1)[1])


def test_wrapper_allows_exactly_the_four_owner_operations(owner_listener):
    app, url = owner_listener
    r = run_wrapper(url, "PUT /publish/alpha-1", tar_bytes({"index.html": b"<html>x</html>"}))
    assert r.returncode == 0 and status_of(r) == 200
    r = run_wrapper(url, "PATCH /publish/alpha-1/metadata", b'{"password": "pw-correct-horse"}')
    assert status_of(r) == 200
    r = run_wrapper(url, "GET /publishes/alpha-1/data/feedback?limit=100")
    assert status_of(r) == 200 and json.loads(r.stdout.decode().rsplit("\nSTATUS", 1)[0])["records"] == []
    r = run_wrapper(url, "GET /publishes/alpha-1/data/feedback?limit=100&cursor=00000002")
    assert status_of(r) == 200
    r = run_wrapper(url, "DELETE /publish/alpha-1")
    assert status_of(r) == 200
    assert run_wrapper(url, "DELETE /publish/alpha-1").stdout.decode().rstrip().endswith("STATUS 404")


@pytest.mark.parametrize("command", [
    None, "", "id", "ls /", "PUT", "PUT /publish/", "PUT /publish/../x", "PUT /publish/a", "PUT /publish/ALPHA",
    "PUT /publish/alpha-1;id", "PUT /publish/alpha-1 && id", "PUT /publish/alpha-1\nDELETE /publish/beta-2",
    "PUT /publish/alpha-1\rid", "put /publish/alpha-1", "POST /publish/alpha-1", "GET /publish/alpha-1",
    "PUT /publishes/alpha-1/data/feedback", "PATCH /publish/alpha-1", "DELETE /publish/alpha-1/metadata",
    "GET /etc/passwd", "GET /publishes/alpha-1/data/feedback?limit=1;id", "GET /publishes/alpha-1/data/feedback?x=$(id)",
    "GET /publishes/alpha-1/data/feedback?limit=1 -o /tmp/x", "GET http://evil.test/", "GET //evil.test/publishes/a",
    "PUT /publish/alpha-1 --data x", "PUT /publish/\u00e5lpha",
    "PUT http://evil.test/publish/alpha-1", "PUT /x/publish/alpha-1", "GET /etc/../publishes/alpha-1/data/feedback",
    "GET /x/publishes/alpha-1/data/feedback", "DELETE /a/publish/alpha-1", "PATCH /a/publish/alpha-1/metadata",
])
def test_wrapper_refuses_everything_else_without_reaching_the_server(owner_listener, command):
    app, url = owner_listener
    r = run_wrapper(url, command, tar_bytes({"index.html": b"x"}))
    assert r.returncode != 0 and b"STATUS" not in r.stdout
    assert list(app.sites.iterdir()) == []          # nothing reached the server


def test_wrapper_does_not_pass_a_request_body_to_get_or_delete(owner_listener):
    app, url = owner_listener
    run_wrapper(url, "PUT /publish/alpha-1", tar_bytes({"index.html": b"x"}))
    # a GET with stdin must not turn into a body-carrying request or change anything
    r = run_wrapper(url, "GET /publishes/alpha-1/data/feedback", b"ignored body")
    assert status_of(r) == 200 and (app.sites / "alpha-1" / "meta.json").exists()


@pytest.fixture
def recorder():
    """A stand-in owner listener that records exactly what the wrapper put on the wire."""
    import http.server
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def _any(self):
            n = int(self.headers.get("content-length") or 0)
            seen.append({"method": self.command, "path": self.path, "body": self.rfile.read(n) if n else b"",
                         "ctype": self.headers.get("content-type")})
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')
        do_GET = do_PUT = do_PATCH = do_DELETE = _any

        def log_message(self, format, *args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield seen, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_wrapper_uses_its_own_pinned_path_not_the_callers(tmp_path, owner_listener):
    app, url = owner_listener
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "curl").write_text(f"#!/bin/sh\necho hijacked > {tmp_path}/marker\nexit 0\n", encoding="utf-8")
    (fake / "curl").chmod(0o755)
    env = {"PATH": f"{fake}:{os.environ['PATH']}", "SELFNOW_OWNER_URL": url,
           "SSH_ORIGINAL_COMMAND": "GET /publishes/alpha-1/data/feedback"}
    r = subprocess.run(["sh", str(WRAPPER)], capture_output=True, env=env, timeout=60)
    assert not (tmp_path / "marker").exists() and b"STATUS" in r.stdout


def test_wrapper_only_speaks_http(tmp_path):
    (tmp_path / "publishes" / "alpha-1" / "data").mkdir(parents=True)
    (tmp_path / "publishes" / "alpha-1" / "data" / "feedback").write_text("LEAK", encoding="utf-8")
    r = run_wrapper("file://" + str(tmp_path), "GET /publishes/alpha-1/data/feedback")
    assert b"LEAK" not in r.stdout and r.returncode != 0


def test_wrapper_only_speaks_http_for_uploads_too(tmp_path):
    (tmp_path / "publish").mkdir()
    (tmp_path / "publish" / "alpha-1").write_text("LEAK", encoding="utf-8")
    r = run_wrapper("file://" + str(tmp_path), "PUT /publish/alpha-1", b"UPLOADED")
    assert b"LEAK" not in r.stdout and r.returncode != 0
    assert (tmp_path / "publish" / "alpha-1").read_text(encoding="utf-8") == "LEAK"


def test_wrapper_sends_the_body_only_with_put_and_patch_and_with_the_right_content_type(recorder):
    seen, url = recorder
    run_wrapper(url, "PUT /publish/alpha-1", b"TARBYTES")
    run_wrapper(url, "PATCH /publish/alpha-1/metadata", b'{"password": null}')
    run_wrapper(url, "GET /publishes/alpha-1/data/feedback?limit=100", b"smuggled")
    run_wrapper(url, "DELETE /publish/alpha-1", b"smuggled")
    assert seen == [
        {"method": "PUT", "path": "/publish/alpha-1", "body": b"TARBYTES", "ctype": "application/octet-stream"},
        {"method": "PATCH", "path": "/publish/alpha-1/metadata", "body": b'{"password": null}', "ctype": "application/json"},
        {"method": "GET", "path": "/publishes/alpha-1/data/feedback?limit=100", "body": b"", "ctype": None},
        {"method": "DELETE", "path": "/publish/alpha-1", "body": b"", "ctype": None},
    ]
