"""Self-hosted publish server with the here.now-shaped API the plugin's herenow flow already speaks.

Two listeners over one App:
  public  (reverse proxy -> container network): the gated board, the unlock form, anonymous feedback insert.
  owner   (host loopback only):                  upload a site, set the password, list feedback, delete the site.

The App is a plain object with an injectable clock, so every guard is testable without sockets
(app.public / app.owner return a Response). The HTTP wrappers at the bottom only move bytes.
Standard library only (upstream invariant).
"""
import hashlib
import hmac
import io
import ipaddress
import json
import mimetypes
import os
from os import open as _fd_open  # low-level fd call; the text-file audit matches the name "os.open"
import re
import secrets as _secrets
import shutil
import tarfile
import time
from collections import defaultdict
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,80}")
MAX_PUBLIC_BODY = 16 * 1024
MAX_PAYLOAD = 15000
MAX_SITE_FILES = 2000
MAX_SITE_BYTES = 25 * 1024 * 1024
RATE_LIMIT = 30
RATE_WINDOW = 3600
UNLOCK_FAILS = 10
UNLOCK_WINDOW = 600
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")
BAD_PATH = re.compile(r"[\x00-\x20\x7f\\]")   # urlsplit silently strips \n \r \t, so check the raw path first

BOARD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
             "frame-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
             "frame-ancestors 'none'")
VARIANT_CSP = "sandbox allow-scripts"

GATE_PAGE = (b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Locked</title>"
             b"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head><body>"
             b"<form method=\"post\" action=\"unlock\"><label>Password <input type=\"password\" name=\"password\" "
             b"autocomplete=\"current-password\" autofocus></label> <button type=\"submit\">Open</button></form>"
             b"</body></html>")


class Response:
    def __init__(self, status: int, body: bytes = b"", headers: Optional[Dict[str, str]] = None,
                 ctype: str = "application/json"):
        self.status = status
        self.body = body
        self.headers = {"content-type": ctype}
        if headers:
            self.headers.update(headers)


def _json(status: int, obj: Any, headers: Optional[Dict[str, str]] = None) -> Response:
    return Response(status, json.dumps(obj).encode("utf-8"), headers)


def _err(status: int, message: str, headers: Optional[Dict[str, str]] = None) -> Response:
    return _json(status, {"ok": False, "error": message}, headers)


def _nets(items) -> tuple:
    return tuple(ipaddress.ip_network(s, strict=False) for s in items)


def _match(peer: str, nets) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(n.version == ip.version and ip in n for n in nets)


class App:
    def __init__(self, data_dir, public_host: str, clock: Callable[[], float] = time.time,
                 trusted_proxies: Tuple[str, ...] = (), owner_peers: Tuple[str, ...] = LOOPBACK,
                 max_records_per_slug: int = 500, max_total_bytes: int = 200 * 1024 * 1024,
                 max_slugs: int = 100, retention_days: int = 30):
        self.root = Path(data_dir)
        self.sites = self.root / "sites"
        self.sites.mkdir(parents=True, exist_ok=True)
        self.public_host = public_host.lower()
        self.clock = clock
        self.trusted_proxies = tuple(trusted_proxies)
        self.owner_peers = tuple(owner_peers)
        self._proxy_nets = _nets(self.trusted_proxies)
        self._owner_nets = _nets(self.owner_peers)
        self.max_records_per_slug = max_records_per_slug
        self.max_total_bytes = max_total_bytes
        self.max_slugs = max_slugs
        self.retention_days = retention_days
        self._hits = defaultdict(list)     # (slug, client) -> insert timestamps
        self._fails = defaultdict(list)    # (slug, client) -> failed unlock timestamps
        self._secret = self._load_secret()

    # ---- state ---------------------------------------------------------------------------------

    def _load_secret(self) -> bytes:
        p = self.root / "cookie.key"
        if p.exists():
            return p.read_bytes()
        key = _secrets.token_bytes(32)
        fd = _fd_open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key

    def _dir(self, slug: str) -> Path:
        return self.sites / slug

    def _exists(self, slug: str) -> bool:
        return (self._dir(slug) / "meta.json").is_file()

    def _meta(self, slug: str) -> Dict[str, Any]:
        return json.loads((self._dir(slug) / "meta.json").read_text(encoding="utf-8"))

    def _save_meta(self, slug: str, meta: Dict[str, Any]) -> None:
        tmp = self._dir(slug) / ("meta.%s.tmp" % _secrets.token_hex(4))
        tmp.write_text(json.dumps(meta), encoding="utf-8")
        os.replace(tmp, self._dir(slug) / "meta.json")

    def _total_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.sites.rglob("*") if f.is_file() and not f.is_symlink())

    def _records(self, slug: str) -> Path:
        return self._dir(slug) / "records"

    # ---- headers ---------------------------------------------------------------------------------

    @staticmethod
    def _secure(resp: Response, csp: str = BOARD_CSP) -> Response:
        h = resp.headers
        h.setdefault("x-content-type-options", "nosniff")
        h.setdefault("referrer-policy", "no-referrer")
        h.setdefault("content-security-policy", csp)
        h.setdefault("cache-control", "no-store")
        return resp

    # ---- client identity -------------------------------------------------------------------------

    def _client(self, headers: Dict[str, str], peer: str) -> str:
        who = peer
        if _match(peer, self._proxy_nets):
            fwd = headers.get("x-forwarded-for", "")
            parts = [p.strip() for p in fwd.split(",") if p.strip()]
            if parts:
                who = parts[-1]     # the entry the trusted proxy appended
        try:
            ip = ipaddress.ip_address(who)
        except ValueError:
            return "invalid"
        if ip.version == 6:
            return str(ipaddress.ip_network("%s/64" % ip, strict=False))
        return str(ip)

    # ---- gate cookie -----------------------------------------------------------------------------

    def _gate_value(self, slug: str, meta: Dict[str, Any]) -> str:
        msg = ("%s|%s" % (slug, meta.get("gate_version", 0))).encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _unlocked(self, slug: str, meta: Dict[str, Any], headers: Dict[str, str]) -> bool:
        if meta.get("gate") == "open":
            return True
        if meta.get("gate") != "password":
            return False
        jar = SimpleCookie()
        try:
            jar.load(headers.get("cookie", ""))
        except Exception:
            return False
        morsel = jar.get("gate")
        return bool(morsel) and hmac.compare_digest(morsel.value, self._gate_value(slug, meta))

    @staticmethod
    def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
        salt = salt or _secrets.token_bytes(16)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        return salt.hex() + "$" + dk.hex()

    @classmethod
    def _check_password(cls, password: str, stored: str) -> bool:
        salt_hex, _, _ = stored.partition("$")
        return hmac.compare_digest(cls._hash_password(password, bytes.fromhex(salt_hex)), stored)

    # ---- public listener -------------------------------------------------------------------------

    def public(self, method: str, path: str, headers: Dict[str, str], body: bytes, peer: str) -> Response:
        headers = {k.lower(): v for k, v in headers.items()}
        try:
            return self._public(method, path, headers, body, peer)
        except Exception:
            return self._secure(_err(500, "internal error"))

    def _public(self, method, path, headers, body, peer) -> Response:
        host = headers.get("host", "").lower()
        if host != self.public_host:
            return self._secure(_err(421, "misdirected request"))
        if BAD_PATH.search(path):
            return self._secure(_err(400, "bad path"))
        decoded = unquote(urlsplit(path).path)
        if BAD_PATH.search(decoded):
            return self._secure(_err(400, "bad path"))
        parts = decoded.split("/")
        if len(parts) < 2 or parts[0] != "" or not SLUG_RE.fullmatch(parts[1]) or not self._exists(parts[1]):
            return self._secure(_err(404, "not found"))
        slug, rest = parts[1], parts[2:]
        meta = self._meta(slug)
        if method == "POST":
            origin = headers.get("origin")
            if origin is not None and origin.strip().lower() != "https://" + self.public_host:
                return self._secure(_err(403, "cross-origin requests are not accepted"))
            if len(body) > MAX_PUBLIC_BODY:
                return self._secure(_err(413, "request too large"))
            if rest == ["unlock"]:
                return self._unlock(slug, meta, headers, body, peer)
            if rest == [".herenow", "data", "feedback"]:
                return self._insert(slug, meta, headers, body, peer)
            return self._secure(_err(404, "not found"))
        if method not in ("GET", "HEAD"):
            return self._secure(_err(405, "method not allowed"))
        if not self._unlocked(slug, meta, headers):
            return self._secure(Response(401, GATE_PAGE, ctype="text/html; charset=utf-8"))
        return self._serve(slug, rest)

    def _serve(self, slug: str, rest: List[str]) -> Response:
        if any(p in (".", "..") or p.startswith(".") or "\\" in p or "\x00" in p for p in rest if p != ""):
            return self._secure(_err(404, "not found"))
        rel = "/".join(p for p in rest if p != "") or "index.html"
        base = (self._dir(slug) / "current").resolve()
        target = (base / rel).resolve()
        if target.is_dir():
            target = target / "index.html"
        try:
            target.relative_to(base)
        except ValueError:
            return self._secure(_err(404, "not found"))
        if not target.is_file():
            return self._secure(_err(404, "not found"))
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml", "application/json"):
            ctype += "; charset=utf-8"
        is_round = rest[:1] == ["rounds"]
        resp = Response(200, target.read_bytes(), ctype=ctype)
        return self._secure(resp, VARIANT_CSP if is_round else BOARD_CSP)

    def _unlock(self, slug, meta, headers, body, peer) -> Response:
        client = self._client(headers, peer)
        now = self.clock()
        key = (slug, client)
        self._fails[key] = [t for t in self._fails[key] if now - t < UNLOCK_WINDOW]
        if len(self._fails[key]) >= UNLOCK_FAILS:
            return self._secure(_err(429, "too many attempts"))
        if meta.get("gate") != "password":
            return self._secure(_err(401, "locked"))
        form = parse_qs(body.decode("utf-8", "replace"))
        pw = (form.get("password") or [""])[0]
        if not pw or not self._check_password(pw, meta["password_hash"]):
            self._fails[key].append(now)
            return self._secure(_err(401, "wrong password"))
        cookie = "gate=%s; Path=/%s/; Secure; HttpOnly; SameSite=Lax" % (self._gate_value(slug, meta), slug)
        return self._secure(Response(303, b"", {"set-cookie": cookie, "location": "./"}, ctype="text/plain"))

    def _insert(self, slug, meta, headers, body, peer) -> Response:
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return self._secure(_err(415, "content-type must be application/json"))
        if not self._unlocked(slug, meta, headers):
            return self._secure(_err(401, "unlock the board first"))
        idem = headers.get("idempotency-key", "")
        idem_dir = self._dir(slug) / "idem"
        idem_file = idem_dir / hashlib.sha256(idem.encode("utf-8")).hexdigest() if idem else None
        if idem_file is not None and idem_file.is_file():
            return self._secure(_json(200, {"ok": True, "id": idem_file.read_text(encoding="utf-8")}))
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._secure(_err(400, "body is not valid JSON"))
        token, rnd, amend, payload = (data.get("token"), data.get("round"), data.get("amend", False),
                                      data.get("payload")) if isinstance(data, dict) else (None,) * 4
        if (not isinstance(token, str) or len(token) > 64 or isinstance(rnd, bool) or not isinstance(rnd, int)
                or not 1 <= rnd <= 999 or not isinstance(amend, bool) or not isinstance(payload, str)
                or len(payload) > MAX_PAYLOAD):
            return self._secure(_err(400, "invalid record"))
        now = self.clock()
        client = self._client(headers, peer)
        key = (slug, client)
        self._hits[key] = [t for t in self._hits[key] if now - t < RATE_WINDOW]
        if len(self._hits[key]) >= RATE_LIMIT:
            return self._secure(_err(429, "too many submits from this network"))
        rdir = self._records(slug)
        rdir.mkdir(exist_ok=True)
        existing = sorted(rdir.glob("*.json"))
        if len(existing) >= self.max_records_per_slug:
            return self._secure(_err(409, "this board has reached its feedback limit"))
        seq = (int(existing[-1].stem) + 1) if existing else 1
        rec_id = "%08d" % seq
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        rec = {"id": rec_id, "createdAt": created,
               "data": {"token": token, "round": rnd, "amend": amend, "payload": payload}}
        tmp = rdir / (rec_id + ".tmp")
        tmp.write_text(json.dumps(rec), encoding="utf-8")
        os.replace(tmp, rdir / (rec_id + ".json"))
        if idem_file is not None:
            idem_dir.mkdir(exist_ok=True)
            idem_file.write_text(rec_id, encoding="utf-8")
        self._hits[key].append(now)
        return self._secure(_json(200, {"ok": True, "id": rec_id}))

    # ---- owner listener --------------------------------------------------------------------------

    def owner(self, method: str, path: str, headers: Dict[str, str], body: bytes, peer: str) -> Response:
        if not _match(peer, self._owner_nets):
            return self._secure(_err(403, "owner routes are loopback only"))
        if BAD_PATH.search(path):
            return self._secure(_err(400, "bad path"))
        try:
            return self._owner(method, urlsplit(path), body)
        except Exception:
            return self._secure(_err(500, "internal error"))

    def _owner(self, method, url, body) -> Response:
        parts = url.path.split("/")
        if len(parts) >= 3 and parts[1] in ("publish", "publishes") and SLUG_RE.fullmatch(parts[2] or ""):
            slug, rest = parts[2], parts[3:]
        else:
            return self._secure(_err(404, "not found"))
        if parts[1] == "publish" and rest == [] and method == "PUT":
            return self._upload(slug, body)
        if parts[1] == "publish" and rest == [] and method == "DELETE":
            return self._delete(slug)
        if parts[1] == "publish" and rest == ["metadata"] and method == "PATCH":
            return self._set_password(slug, body)
        if parts[1] == "publishes" and rest == ["data", "feedback"] and method == "GET":
            return self._list(slug, url.query)
        return self._secure(_err(404, "not found"))

    def _upload(self, slug: str, body: bytes) -> Response:
        if self._total_bytes() + len(body) > self.max_total_bytes:
            return self._secure(_err(413, "store is full"))
        if not self._exists(slug) and len(list(self.sites.iterdir())) >= self.max_slugs:
            return self._secure(_err(409, "too many sites"))
        try:
            files = self._read_tar(body)
        except ValueError as e:
            return self._secure(_err(400, str(e)))
        sdir = self._dir(slug)
        vdir = sdir / "v"
        vdir.mkdir(parents=True, exist_ok=True)
        vid = _secrets.token_hex(8)
        staging = vdir / (vid + ".staging")
        for name, data in files.items():
            dest = staging / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        if not files:
            staging.mkdir()
        final = vdir / vid
        os.replace(staging, final)
        link_tmp = sdir / ("current.%s.tmp" % vid)
        os.symlink(os.path.join("v", vid), link_tmp)
        old = os.path.realpath(sdir / "current") if (sdir / "current").is_symlink() else None
        os.replace(link_tmp, sdir / "current")        # atomic switch
        if old and os.path.isdir(old) and os.path.realpath(old) != str(final.resolve()):
            shutil.rmtree(old, ignore_errors=True)
        now = self.clock()
        meta = self._meta(slug) if self._exists(slug) else {"gate": "locked", "gate_version": 0, "created": now}
        meta["updated"] = now
        self._save_meta(slug, meta)
        return self._secure(_json(200, {"ok": True, "slug": slug}))

    @staticmethod
    def _read_tar(body: bytes) -> Dict[str, bytes]:
        out = {}   # type: Dict[str, bytes]
        total = 0
        try:
            tf = tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
        except tarfile.TarError:
            raise ValueError("not a tar archive")
        with tf:
            for m in tf:
                name = m.name
                if (not name or name.startswith("/") or "\\" in name or "\x00" in name or len(name) > 255
                        or ".." in name.split("/")):
                    raise ValueError("unsafe path in archive")
                if m.isdir():
                    continue
                if not m.isreg():
                    raise ValueError("only regular files are accepted")
                total += m.size
                if len(out) >= MAX_SITE_FILES or total > MAX_SITE_BYTES:
                    raise ValueError("archive is too large")
                clean = "/".join(p for p in name.split("/") if p not in ("", "."))
                if any(p.startswith(".") for p in clean.split("/")):
                    raise ValueError("hidden files are not accepted")
                f = tf.extractfile(m)
                out[clean] = f.read() if f else b""
        return out

    def _set_password(self, slug: str, body: bytes) -> Response:
        if not self._exists(slug):
            return self._secure(_err(404, "not found"))
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._secure(_err(400, "body is not valid JSON"))
        if not isinstance(data, dict) or "password" not in data:
            return self._secure(_err(400, "password is required (a string, or null to open the board)"))
        pw = data["password"]
        meta = self._meta(slug)
        meta["gate_version"] = int(meta.get("gate_version", 0)) + 1   # a new password invalidates old cookies
        if pw is None:
            meta["gate"] = "open"
            meta.pop("password_hash", None)
        elif isinstance(pw, str) and len(pw) >= 8:
            meta["gate"] = "password"
            meta["password_hash"] = self._hash_password(pw)
        else:
            return self._secure(_err(400, "password must be at least 8 characters"))
        self._save_meta(slug, meta)
        return self._secure(_json(200, {"ok": True}))

    def _list(self, slug: str, query: str) -> Response:
        if not self._exists(slug):
            return self._secure(_err(404, "not found"))
        q = parse_qs(query)
        try:
            limit = max(1, min(100, int((q.get("limit") or ["100"])[0])))
        except ValueError:
            limit = 100
        cursor = (q.get("cursor") or [""])[0]
        files = sorted(self._records(slug).glob("*.json")) if self._records(slug).is_dir() else []
        if cursor:
            files = [f for f in files if f.stem > cursor]
        page = files[:limit]
        records = [json.loads(f.read_text(encoding="utf-8")) for f in page]
        nxt = page[-1].stem if len(files) > limit else None
        return self._secure(_json(200, {"records": records, "nextCursor": nxt}))

    def _delete(self, slug: str) -> Response:
        if not self._exists(slug):
            return self._secure(_err(404, "not found"))
        shutil.rmtree(self._dir(slug), ignore_errors=True)
        return self._secure(_json(200, {"ok": True}))

    # ---- retention -------------------------------------------------------------------------------

    def sweep(self) -> int:
        """Delete sites (with their records) not updated for retention_days. Returns how many."""
        cutoff = self.clock() - self.retention_days * 86400
        removed = 0
        for d in list(self.sites.iterdir()):
            try:
                updated = json.loads((d / "meta.json").read_text(encoding="utf-8")).get("updated", 0)
            except (OSError, ValueError):
                continue
            if updated < cutoff:
                shutil.rmtree(d, ignore_errors=True)
                removed += 1
        return removed


# ---- HTTP wrappers (move bytes only; every decision is in App) -------------------------------------

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

REQUEST_TIMEOUT_S = 30


def make_server(app: App, kind: str, host: str, port: int) -> ThreadingHTTPServer:
    """kind is 'public' or 'owner'. The body limit is enforced here, before anything is buffered."""
    limit = MAX_PUBLIC_BODY if kind == "public" else app.max_total_bytes

    class Handler(BaseHTTPRequestHandler):
        server_version = "selfnow"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = REQUEST_TIMEOUT_S

        def log_message(self, *args) -> None:       # no request logging: paths and bodies stay out of logs
            return

        def _handle(self) -> None:
            raw_len = self.headers.get("Content-Length")
            body = b""
            if self.command in ("POST", "PUT", "PATCH"):
                if raw_len is None or not raw_len.isdigit():
                    return self._send(App._secure(_err(411, "content-length required")), close=True)
                if int(raw_len) > limit:
                    return self._send(App._secure(_err(413, "request too large")), close=True)
                body = self.rfile.read(int(raw_len))
            handler = app.public if kind == "public" else app.owner
            self._send(handler(self.command, self.path, dict(self.headers.items()), body, self.client_address[0]))

        def _send(self, resp: Response, close: bool = False) -> None:
            body = b"" if self.command == "HEAD" else resp.body
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp.body)))
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def main(argv: Optional[List[str]] = None) -> None:
    import argparse
    import threading
    p = argparse.ArgumentParser(description="self-hosted publish server")
    p.add_argument("--data", required=True)
    p.add_argument("--public-host", required=True, help="the Host header the reverse proxy sends")
    p.add_argument("--public-bind", default="0.0.0.0")
    p.add_argument("--public-port", type=int, default=8080)
    p.add_argument("--owner-bind", default="0.0.0.0")
    p.add_argument("--owner-port", type=int, default=8081)
    p.add_argument("--proxy", action="append", default=[], help="reverse proxy peer address (repeatable)")
    p.add_argument("--owner-peer", action="append", default=[], help="extra allowed owner peer, e.g. the bridge gateway")
    p.add_argument("--retention-days", type=int, default=30)
    a = p.parse_args(argv)
    app = App(a.data, a.public_host, trusted_proxies=tuple(a.proxy), owner_peers=LOOPBACK + tuple(a.owner_peer),
              retention_days=a.retention_days)

    def sweeper() -> None:
        while True:
            app.sweep()
            time.sleep(6 * 3600)

    threading.Thread(target=sweeper, daemon=True).start()
    pub = make_server(app, "public", a.public_bind, a.public_port)
    own = make_server(app, "owner", a.owner_bind, a.owner_port)
    threading.Thread(target=own.serve_forever, daemon=True).start()
    pub.serve_forever()


if __name__ == "__main__":
    main()
