"""here.now hosting: build the static board, publish, poll Site Data, delete.

The published site is the same board as the local one plus a Site Data manifest.
The browser inserts one record per submit into the `feedback` collection
(public insert, owner-only read). The local server polls those records with the
account API key, treats every record as untrusted, and runs it through the same
submit path as a local POST.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import browsercheck, config, locks, passwords, service, settings, store
from . import secrets
from .store import ReviewError

log = logging.getLogger("mockreview.herenow")

COLLECTION = "feedback"
MAX_PAYLOAD = 15000  # Site Data caps a record body at 16 KB
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,80}$")
BOARD_FILES = ("index.html", "board.css", "board.js", "favicon.svg")

MANIFEST = {
    "collections": {
        COLLECTION: {
            "fields": {
                "token": {"type": "string", "required": True, "maxLength": 64},
                "round": {"type": "integer", "required": True, "minimum": 1, "maximum": 999},
                "amend": {"type": "boolean", "default": False},
                "payload": {"type": "string", "required": True, "maxLength": MAX_PAYLOAD},
            },
            "access": {"read": "owner", "insert": "public", "update": "owner", "delete": "owner"},
            "rateLimit": "30/hour/ip",
        }
    }
}


class HereNowError(ReviewError):
    pass


# here.now answers API errors with JSON ({"code": "..."}). When its backend Worker crashes instead, the Cloudflare
# edge answers with an HTML error page ("Error 1101 ... Worker threw exception", a Ray ID). Pull out only these short
# tokens, so a log line says which kind of failure it was and the Ray ID can go in a support request.
_CF_ERROR_RE = re.compile(r"Error\s+(1\d{3})\b")
_CF_RAY_RE = re.compile(r"Ray ID:\s*([0-9a-f]{16})\b")
_TAG_RE = re.compile(r"<[^>]{0,2000}>")
_JSON_CODE_RE = re.compile(r'"code"\s*:\s*"([a-z_]{1,48})"')


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        body = e.read(64 * 1024).decode("utf-8", "replace")
    except Exception:
        return ""
    text = _TAG_RE.sub(" ", body)
    parts = []
    cf = _CF_ERROR_RE.search(text)
    if cf:
        parts.append(f"Cloudflare error {cf.group(1)}")
        ray = _CF_RAY_RE.search(text)
        if ray:
            parts.append(f"ray {ray.group(1)}")
    else:
        code = _JSON_CODE_RE.search(body)
        if code:
            parts.append(code.group(1))
    return "".join(", " + p for p in parts)


def api_key() -> str:
    key = secrets.get_secret("HERENOW_API_KEY")
    if not key:
        raise HereNowError("HERENOW_API_KEY is not set (Hermes secret scope or environment)", 409)
    return key


def _api(method: str, path: str, timeout: float = 20.0,
         body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    alias = _selfhost_alias()
    if alias:
        return _api_ssh(alias, method, path, timeout, body=body)
    req = urllib.request.Request(
        config.HERENOW_API + path,
        method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Authorization": f"Bearer {api_key()}", "X-HereNow-Client": config.HERENOW_CLIENT,
                 "Accept": "application/json", "Content-Type": "application/json",
                 "User-Agent": "mock-review/1.1 (hermes)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(4 * 1024 * 1024)
            return json.loads(raw or b"{}")
    except urllib.error.HTTPError as e:
        # Remote responses may echo credentials, including a password PATCH body: never log the body, only the
        # short tokens _error_detail matches.
        detail = _error_detail(e)
        raise HereNowError(f"here.now {method} failed (HTTP {e.code}{detail})", e.code) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise HereNowError(f"here.now {method} failed", 502) from None


def password_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """Only explicit owner operations return the password, after confirmed application."""
    if data.get("mode") != "herenow":
        return {}
    hn = data.get("herenow") or {}
    return {"password": hn.get("password") if hn.get("password_enabled") and
            hn.get("password_status") == "applied" and hn.get("password_applied") is True
            and not store.verify_blocks(data) else None,
            "password_enabled": hn.get("password_enabled", False),
            "password_status": hn.get("password_status", "legacy")}


def _apply_password(review_id: str) -> Dict[str, Any]:
    """Caller holds .publish.lock. Persist intent before the request; reconcile on retry."""
    with store.locked(review_id):
        data = store.load(review_id)
        hn = data["herenow"]
        if not SLUG_RE.fullmatch(hn.get("slug") or ""):
            raise HereNowError("password choice saved; publish the review before sharing it", 409)
        enabled = hn.get("password_enabled", False)
        if enabled and not hn.get("password"):
            hn["password"] = passwords.generate()
        hn.update(password_status="pending", password_applied=None)
        store.save(review_id, data)
        value, slug = hn.get("password") if enabled else None, hn["slug"]
    try:
        _api("PATCH", f"/publish/{slug}/metadata", body={"password": value})
    except Exception:
        with store.locked(review_id):
            data = store.load(review_id)
            data["herenow"].update(password_status="error", password_applied=None)
            store.save(review_id, data)
        raise HereNowError("here.now password update failed; protection is unconfirmed. "
                           "Retry password on|off or publish, or close to delete the site.", 502) from None
    with store.locked(review_id):
        data = store.load(review_id)
        hn = data["herenow"]
        hn.update(password_status="applied", password_applied=enabled)
        if not enabled:
            hn["password"] = None
        store.save(review_id, data)
    return data


gated_prototype = store.gated_prototype


def _verify_site(review_id: str) -> Dict[str, Any]:
    """Caller holds .publish.lock and the password gate is live. Load the real board behind its password in a browser
    (browsercheck): any 4xx/5xx or failed subresource, an unstyled frame or a missing browser fails the publish, and
    the review's URL and password stay withheld (verify_status) until a later publish passes."""
    with store.locked(review_id):
        data = store.load(review_id)
        hn, rnd = data["herenow"], data["rounds"][-1]
        site_url, secret, n, vid = hn.get("site_url"), hn.get("password"), rnd["n"], rnd["variants"][0]["id"]
        hn.update(verify_status="pending", verify_error=None)
        store.save(review_id, data)
    problem: Optional[browsercheck.BrowserCheckError] = None
    if not site_url or not secret:
        problem = browsercheck.BrowserCheckError("the site URL or password is not stored")
    else:
        try:
            browsercheck.verify_board(site_url, secret, n, variant=vid)
        except browsercheck.BrowserCheckError as e:
            problem = e
    with store.locked(review_id):
        data = store.load(review_id)
        hn = data["herenow"]
        if problem is None:
            hn.update(verify_status="verified", verify_error=None, verified_round=n, verified_at=store.now_iso())
        else:
            hn.update(verify_status="failed", verify_error=problem.message[:600])
        store.save(review_id, data)
    if problem is not None:
        unavailable = isinstance(problem, browsercheck.BrowserUnavailable)
        raise HereNowError(
            f"browser check of the password-gated prototype failed: {problem.message}. "
            + ("It could not be verified, so it is treated as failed. " if unavailable else "")
            + "The board's link and password are withheld. Fix the prototype and add a round (a gated prototype "
            f"round is bundled automatically), or retry `mockreview publish {review_id}`.",
            409 if unavailable else 502)
    return data


def set_password(review_id: str, enabled: bool) -> Dict[str, Any]:
    if not isinstance(enabled, bool):
        raise ReviewError("password must be a boolean")
    store.load(review_id)
    rdir = store.review_dir(review_id)
    with locks.exclusive(rdir / ".publish.lock"):
        with store.locked(review_id):
            data = store.load(review_id)
            if data["mode"] != "herenow" or data["status"] != "open":
                raise ReviewError("password changes require an open herenow review", 409)
            hn = data["herenow"]
            hn.update(password_enabled=enabled, password_status="pending", password_applied=None)
            if enabled and not hn.get("password"):
                hn["password"] = passwords.generate()
            store.save(review_id, data)
        data = _apply_password(review_id)
        if enabled and gated_prototype(data):
            data = _verify_site(review_id)     # a prototype round made while the gate was off has no bundle
        return data


def build_site(data: Dict[str, Any], dest: Path) -> Path:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name in BOARD_FILES:
        shutil.copyfile(config.BOARD_DIR / name, dest / name)
    state = store.public_state(data, submit_kind="sitedata")
    (dest / "state.json").write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    src_rounds = store.review_dir(data["id"]) / "rounds"
    shutil.copytree(src_rounds, dest / "rounds", ignore=shutil.ignore_patterns("feedback.*", ".*"))
    (dest / ".herenow").mkdir()
    (dest / ".herenow" / "data.json").write_text(json.dumps(MANIFEST, indent=2), encoding="utf-8")
    return dest


_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_BASE_RE = re.compile(r"https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?")
_SLUG = r"[a-z0-9][a-z0-9-]{1,80}"
# The only requests the owner transport may send; fullmatch, so nothing can ride along in the remote command.
_OWNER_PATH = re.compile(r"/publish/%s(/metadata)?|/publishes/%s/data/feedback(\?[A-Za-z0-9=&]{0,200})?" % (_SLUG, _SLUG))


def _selfhost_alias() -> str:
    """The ssh host alias of the self-hosted publish server's owner endpoint, or "" for here.now."""
    alias = settings.get("selfhost_ssh")
    if not alias:
        return ""
    if not _ALIAS_RE.fullmatch(alias):
        raise HereNowError("selfhost_ssh must be an ssh host alias (letters, digits, dot, dash, underscore)", 409)
    if not _BASE_RE.fullmatch(settings.get("selfhost_base") or ""):
        raise HereNowError("selfhost_base must be an https URL when selfhost_ssh is set", 409)
    return alias


def _api_ssh(alias: str, method: str, path: str, timeout: float, body: Optional[Dict[str, Any]] = None,
             raw: Optional[bytes] = None) -> Dict[str, Any]:
    """One owner request through ssh. The host forces a wrapper that runs a fixed curl against the loopback owner
    listener, so the only thing sent is "<METHOD> <path>" plus the body on stdin. The wrapper prints the response body,
    then a final line "STATUS <http code>". Nothing from stderr is ever put in an error."""
    if method not in ("PUT", "PATCH", "GET", "DELETE") or not _OWNER_PATH.fullmatch(path):
        raise HereNowError("selfhost request refused", 400)
    stdin = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else b"")
    argv = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            "-o", "ClearAllForwardings=yes", "--", alias, f"{method} {path}"]
    try:
        proc = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise HereNowError("selfhost ssh timed out", 504) from None
    except OSError:
        raise HereNowError("selfhost ssh could not run", 502) from None
    if proc.returncode != 0:
        raise HereNowError(f"selfhost ssh failed (exit {proc.returncode})", 502)
    head, _, tail = proc.stdout.rpartition(b"\nSTATUS ")
    try:
        status = int(tail.strip())
    except ValueError:
        raise HereNowError("selfhost ssh returned no status", 502) from None
    if status >= 400:
        raise HereNowError(f"selfhost {method} failed (HTTP {status})", status)
    try:
        return json.loads(head or b"{}")
    except ValueError:
        raise HereNowError("selfhost ssh returned invalid JSON", 502) from None


def _tar_site(site: Path) -> bytes:
    """The built site as a plain tar: regular files only, no links, no hidden entries (the here.now manifest is hidden),
    owner and mode normalised. The server re-validates every entry."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for f in sorted(site.rglob("*")):
            rel = f.relative_to(site)
            if f.is_symlink() or not f.is_file() or any(p.startswith(".") for p in rel.parts):
                continue
            info = tf.gettarinfo(str(f), arcname=rel.as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            with open(f, "rb") as fh:
                tf.addfile(info, fh)
    return buf.getvalue()


def _publish_selfhost(site: Path, slug: Optional[str], alias: str):
    """Upload the built site to the self-hosted server. Returns (slug, site_url, auth_mode)."""
    slug = slug or "mr-" + os.urandom(6).hex()
    _api_ssh(alias, "PUT", f"/publish/{slug}", 300.0, raw=_tar_site(site))
    return slug, settings.get("selfhost_base").rstrip("/") + f"/{slug}/", "authenticated"


def _publish_helper(script, child_env, site: Path, rdir: Path, title: str, existing_slug: Optional[str]):
    """Publish through the here.now publish helper. Returns (slug, site_url, auth_mode)."""
    cmd = ["bash", str(script), str(site), "--client", "hermes", "--title", f"Mock review: {title}"[:80]]
    if existing_slug:
        cmd += ["--slug", existing_slug]
    try:
        proc = subprocess.run(cmd, cwd=str(rdir), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, env=child_env)
    except subprocess.TimeoutExpired:
        raise HereNowError("here.now publish timed out after 300 s", 504)
    results: Dict[str, str] = {}
    for line in (proc.stderr or "").splitlines():
        if line.startswith("publish_result.") and "=" in line:
            k, v = line[len("publish_result."):].split("=", 1)
            results[k] = v.strip()
    slug, url = results.get("slug", ""), results.get("site_url", "")
    if proc.returncode != 0 or not SLUG_RE.match(slug or "") or not url.startswith("https://"):
        raise HereNowError(f"here.now publish failed (exit {proc.returncode}); check the publish helper", 502)
    if results.get("auth_mode") != "authenticated":
        log.warning("here.now publish was not authenticated — Site Data will return 403 account_required")
    return slug, url, results.get("auth_mode")


def publish(review_id: str, verify: bool = True) -> Dict[str, Any]:
    """Build and publish (create or update) the review's site via the here.now publish helper. A gated prototype is
    then loaded in a browser behind its password (see _verify_site); the poller's quiet republish skips that."""
    alias = _selfhost_alias()
    script = child_env = None
    if not alias:
        try:
            script = config.herenow_publish_script()
        except FileNotFoundError as e:
            raise HereNowError(str(e), 409)
        key = api_key()  # Must be nonempty before the helper can run.
        child_env = dict(os.environ, HERENOW_API_KEY=key)
    store.load(review_id)
    rdir = store.review_dir(review_id)
    with locks.exclusive(rdir / ".publish.lock"):
        data = store.load(review_id)
        if data["mode"] != "herenow" or data["status"] != "open":
            raise ReviewError("only open herenow reviews can be published", 409)
        hn = data.get("herenow") or {}
        site = build_site(data, rdir / "site")
        if alias:
            slug, url, auth_mode = _publish_selfhost(site, hn.get("slug"), alias)
        else:
            slug, url, auth_mode = _publish_helper(script, child_env, site, rdir, data["title"], hn.get("slug"))
        with store.locked(review_id):
            data = store.load(review_id)
            data.setdefault("herenow", {}).update(slug=slug, site_url=url, published_at=store.now_iso(),
                                                  auth_mode=auth_mode, site_gone_at=None)
            store.save(review_id, data)
        # Legacy reviews stay public until explicitly toggled. Never remove a gate on a
        # normal unprotected republish; retry an interrupted/failed removal, however.
        hn = data["herenow"]
        if hn.get("password_enabled") or ("password_enabled" in hn and
                                          hn.get("password_status") != "applied"):
            data = _apply_password(review_id)
        if verify and gated_prototype(data):
            data = _verify_site(review_id)
    return data


def republish_quietly(review_id: str) -> None:
    try:
        publish(review_id, verify=False)
    except Exception as e:  # the poller must keep running
        log.error("republish of %s failed: %s", review_id, e)


def fetch_records(slug: str) -> List[Dict[str, Any]]:
    if not SLUG_RE.match(slug or ""):
        raise HereNowError("bad slug", 400)
    out: List[Dict[str, Any]] = []
    cursor = None
    for _ in range(20):
        q = {"limit": "100"}
        if cursor:
            q["cursor"] = cursor
        res = _api("GET", f"/publishes/{slug}/data/{COLLECTION}?" + urllib.parse.urlencode(q), timeout=POLL_TIMEOUT)
        recs = res.get("records") if isinstance(res, dict) else None
        out.extend(r for r in (recs or []) if isinstance(r, dict))
        cursor = res.get("nextCursor") if isinstance(res, dict) else None
        if not cursor:
            break
    return out


def delete_site(slug: str) -> bool:
    """Delete a published site. A DELETE whose response is lost may still have deleted it, so a transport failure is
    retried once: the retried DELETE answers 404 when the first one had already landed, and 200 when it had not."""
    if not SLUG_RE.match(slug or ""):
        raise HereNowError("bad slug", 400)
    attempt = 0
    while True:
        try:
            _api("DELETE", f"/publish/{slug}")
            return True
        except HereNowError as e:
            if e.status == 404:
                return False
            if e.status not in (502, 504) or attempt:
                raise
            attempt += 1


def parse_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Pull only the known fields out of an untrusted Site Data record."""
    d = rec.get("data") if isinstance(rec.get("data"), dict) else {}
    token, rnd, amend, payload = d.get("token"), d.get("round"), d.get("amend", False), d.get("payload")
    if not isinstance(token, str) or len(token) > 64:
        raise ReviewError("record has no valid token", 403)
    if not isinstance(rnd, int) or isinstance(rnd, bool):
        raise ReviewError("record has no valid round")
    if not isinstance(payload, str) or len(payload) > MAX_PAYLOAD:
        raise ReviewError("record payload missing or too large")
    try:
        fb = json.loads(payload)
    except ValueError:
        raise ReviewError("record payload is not JSON")
    return {"token": token, "round": rnd, "amend": amend is True, "feedback": fb}


def poll_review(review_id: str, fetch: Optional[Callable[[str], List[Dict[str, Any]]]] = None,
                republish: bool = True) -> List[Dict[str, Any]]:
    """Ingest new Site Data records for one open here.now review. Returns per-record outcomes."""
    fetch = fetch or fetch_records
    data = store.load(review_id)
    hn = data.get("herenow") or {}
    if data["mode"] != "herenow" or data["status"] != "open" or not hn.get("slug") or hn.get("site_gone_at"):
        return []
    records = fetch(hn["slug"])
    seen = set(hn.get("processed_records") or [])
    fresh = [r for r in records if isinstance(r.get("id"), str) and len(r["id"]) <= 80 and r["id"] not in seen]
    fresh.sort(key=lambda r: str(r.get("createdAt") or ""))
    outcomes = []
    accepted_rounds = []
    for rec in fresh:
        rid = rec["id"]
        try:
            parsed = parse_record(rec)
            res = service.submit(review_id, parsed["round"], parsed["feedback"], parsed["token"],
                                 amend=parsed["amend"], source="herenow", record_id=rid, do_notify=False)
            outcome = {"record": rid, "result": "accepted", "round": res["round"], "amended": res["amended"]}
            accepted_rounds.append(res["round"])
        except ReviewError as e:
            outcome = {"record": rid, "result": "rejected", "reason": e.message}
            log.warning("here.now record %s for %s rejected: %s", rid, review_id, e.message)
        with store.locked(review_id):
            data = store.load(review_id)
            h = data.setdefault("herenow", {})
            h["processed_records"] = (h.get("processed_records") or [])[-4999:] + [rid]
            h["record_log"] = (h.get("record_log") or [])[-49:] + [{**outcome, "at": store.now_iso()}]
            store.save(review_id, data)
        outcomes.append(outcome)
    for n in dict.fromkeys(accepted_rounds):
        service.deliver_submission(review_id, n)
    with store.locked(review_id):
        data = store.load(review_id)
        data.setdefault("herenow", {})["last_poll"] = store.now_iso()
        store.save(review_id, data)
    if accepted_rounds and republish:
        republish_quietly(review_id)
    return outcomes


def open_reviews() -> List[str]:
    out = []
    for rid in store.list_ids():
        try:
            d = store.load(rid)
        except (ReviewError, ValueError, OSError):
            continue
        hn = d.get("herenow") or {}
        if d.get("mode") == "herenow" and d.get("status") == "open" and hn.get("slug") and not hn.get("site_gone_at"):
            out.append(rid)
    return out


# here.now's Site Data routes go down for well under a minute at a time, on a five-minute rhythm: requests hang for up
# to ~30 s, then every Site Data request answers HTTP 500 (Cloudflare error 1101, the backend Worker threw) while the
# rest of the API keeps answering. A poll that lands in that window fails and one TRANSIENT_RETRY_SECONDS later
# succeeds. So a 5xx, a timeout or a dropped connection:
#   - first failure in a row: INFO, and the Worker polls again after TRANSIENT_RETRY_SECONDS instead of poll_seconds;
#   - second in a row (the retry hit it too, so not that blip): WARNING;
#   - TRANSIENT_POLL_ERROR_LIMIT in a row: ERROR.
# Anything else (bad key, bad slug, a 4xx, an unexpected exception) is not transient and logs at ERROR at once.
# POLL_TIMEOUT keeps a hung request from holding the Worker (and the notice retries it runs) for the full 20 s.
POLL_TIMEOUT = 10.0
TRANSIENT_RETRY_SECONDS = 45.0
TRANSIENT_POLL_ERROR_LIMIT = 3
_poll_failures: Dict[str, int] = {}


def retry_delay() -> Optional[float]:
    """Seconds until the Worker should poll again after a transient failure, or None to keep poll_seconds."""
    return TRANSIENT_RETRY_SECONDS if _poll_failures else None


def _is_transient_poll_error(e: Exception) -> bool:
    return isinstance(e, HereNowError) and (e.status >= 500 or e.status in (408, 429))


def poll_all() -> int:
    n = 0
    ids = open_reviews()
    for gone in set(_poll_failures) - set(ids):
        _poll_failures.pop(gone, None)
    for rid in ids:
        try:
            n += sum(1 for o in poll_review(rid) if o["result"] == "accepted")
            _poll_failures.pop(rid, None)
        except Exception as e:
            if isinstance(e, HereNowError) and e.status == 404:
                # The site was deleted (a close whose DELETE response was lost) but the review is still open: stop
                # polling it, once. Closing the review now only needs the local half.
                _poll_failures.pop(rid, None)
                with store.locked(rid):
                    data = store.load(rid)
                    data.setdefault("herenow", {})["site_gone_at"] = store.now_iso()
                    store.save(rid, data)
                log.warning("poll of %s: the here.now site is gone (HTTP 404); stopped polling, close the review to finish", rid)
                continue
            if not _is_transient_poll_error(e):
                _poll_failures.pop(rid, None)
                log.error("poll of %s failed: %s", rid, e)
                continue
            count = _poll_failures[rid] = _poll_failures.get(rid, 0) + 1
            if count >= TRANSIENT_POLL_ERROR_LIMIT:
                log.error("poll of %s failed %d times in a row: %s", rid, count, e)
            elif count == 1:
                log.info("poll of %s hit a here.now blip, retrying in %.0f s: %s", rid, TRANSIENT_RETRY_SECONDS, e)
            else:
                log.warning("poll of %s failed %d times in a row (%d is an error): %s",
                            rid, count, TRANSIENT_POLL_ERROR_LIMIT, e)
    return n
