"""Settings: one table (SPEC), one resolver.

Every value comes from, highest first:
    1. a per-call override (a create/add-round flag or a tool argument; look settings are then stored in the
       review's JSON, so a review never changes under the reviewer)
    2. an environment variable (the declared MOCKREVIEW_* overrides)
    3. Hermes config: plugins.entries.mock-review.settings.<name> in $HERMES_HOME/config.yaml
    4. the built-in default below

config.yaml is read with PyYAML when available; otherwise a strict parser reads only this plugin's settings.
Secrets are resolved separately through Hermes's public secret accessor. HERMES_HOME selects the active home;
MOCKREVIEW_CONFIG overrides the nonsecret config path. HERMES_KANBAN_TASK marks a worker for owner resolution.
notify-test --secret-env selects a scoped secret name; it does not read process environment values directly.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("mockreview.settings")

PLUGIN_ID = "mock-review"
DEVICES = ("desktop", "tablet", "mobile")
_MISSING = object()


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class Setting:
    name: str
    type: str                      # str | int | float | bool | list
    default: Any
    description: str
    group: str
    env: Optional[str] = None      # default: MOCKREVIEW_<NAME>
    choices: Tuple[str, ...] = ()
    lo: Optional[float] = None
    hi: Optional[float] = None
    review: bool = False           # resolved at create time and stored in the review JSON
    aliases: Dict[str, str] = field(default_factory=dict)

    @property
    def env_name(self) -> str:
        return self.env or "MOCKREVIEW_" + self.name.upper()


SPEC: List[Setting] = [
    # look (stored per review)
    Setting("devices", "list", ["desktop", "mobile"], "Device widths the board offers, any of desktop, tablet, mobile. "
            "With one device the switch is hidden.", "look", review=True),
    Setting("default_device", "str", "auto", "Width the board opens at: auto (the viewer's device, clamped to "
            "devices), desktop, tablet or mobile.", "look", choices=("auto",) + DEVICES, review=True),
    Setting("default_theme", "str", "project", "Theme the board opens in: project (the design profile's default), "
            "dark or light.", "look", choices=("project", "dark", "light"), review=True),
    Setting("show_theme_toggle", "bool", True, "Show the light/dark toggle in the header.", "look", review=True),
    Setting("mobile_width", "int", 390, "Mock width in px for Mobile.", "look", lo=280, hi=640, review=True),
    Setting("tablet_width", "int", 820, "Mock width in px for Tablet (capped at a decision's desktop_width).",
            "look", lo=600, hi=1280, review=True),
    Setting("desktop_width", "int", 1280, "Desktop mock width in px for a decision that sets no desktop_width.",
            "look", lo=320, hi=1920),
    # feedback (the first three are stored per review)
    Setting("pins_enabled", "bool", True, "Let the reviewer drop pins on mocks.", "feedback", review=True),
    Setting("require_note_on_change", "bool", False, "Block Send until every Change mark has a note.",
            "feedback", review=True),
    Setting("max_pins", "int", 40, "Most pins per round.", "feedback", lo=1, hi=80, review=True),
    Setting("webhook_url", "str", "http://localhost:8644/webhooks/mock-review", "Hermes webhook base URL; the route suffix is selected by origin platform.",
            "feedback"),
    Setting("webhook_route", "str", "mock-review", "Webhook route prefix; setup creates <prefix>-<platform> for each origin platform.", "feedback"),
    Setting("wake_required", "bool", True, "Refuse to create or extend a review unless the owning service can wake "
            "Hermes on Send (the scoped signing secret is set; setup creates routes). Off: demo/local-only boards that "
            "are viewed but never wake anyone.", "feedback"),
    Setting("retry_seconds", "float", 60.0, "Seconds between retries of an undelivered wake-up.", "feedback",
            lo=0, hi=86400),
    Setting("stale_after_minutes", "float", 15.0, "Minutes after a submitted round with no new round before the "
            "board server pings the origin chat that the agent may have stalled. No ping for a round with nothing to "
            "build (every decision approved or skipped, no pins, no general notes) or one the agent acknowledged "
            "(mockreview ack). 0 = never ping.", "feedback", lo=0, hi=10080),
    Setting("stale_after_read_minutes", "float", 60.0, "Once the agent has read a submission's feedback "
            "(mock_review_feedback or mockreview feedback), minutes after that read with no new round before the "
            "stalled ping. 0 = no ping once the feedback was read.", "feedback", lo=0, hi=10080),
    Setting("wake_toolsets", "list", [], "Hermes toolsets the session woken by Send may use, for example mock-review, "
            "terminal, file (the list replaces Hermes's webhook default). hermes mockreview setup prints the toolsets line to add by hand to the wake "
            "route in webhook_subscriptions.json; add it again after every setup run. Empty: Hermes's safe webhook tools only, and "
            "the build continues in the origin chat's session. Refused for a waking board whose Send is ungated "
            "(a here.now board with its password off, or any board while host listens beyond loopback), because "
            "that board text would reach these tools.", "feedback"),
    Setting("poll_seconds", "float", 60.0, "Seconds between here.now Site Data polls.", "feedback", lo=5, hi=86400),
    # hosting
    Setting("default_host", "str", "local", "Where a review is hosted when the call doesn't say: tailnet "
            "(private, over Tailscale), local (this computer's own address, no Tailscale) or herenow (internet link, password protected by default).",
            "hosting", choices=("tailnet", "local", "herenow"),
            aliases={"tailscale": "tailnet", "here.now": "herenow", "lan": "local"}),
    Setting("herenow_password", "bool", True, "Password protect new here.now reviews. Stored per review; "
            "change an existing review with mockreview password <id> on|off.", "hosting"),
    Setting("ask_host_each_time", "bool", True, "Ask the user tailnet, local or here.now before every review "
            "(read by the skill and tool text, not enforced in code).", "hosting"),
    Setting("public_base", "str", "", "Tailnet URL for review links. Empty: detect MagicDNS with tailscale status --json.", "hosting"),
    Setting("selfhost_ssh", "str", "", "ssh host alias of your own publish server's owner endpoint (key login, forced command). "
            "Empty uses here.now. Needs selfhost_base. Reviews keep the herenow mode; only where the site is stored changes.",
            "hosting"),
    Setting("selfhost_base", "str", "", "https URL your self-hosted boards are served from, for example https://boards.example.org. "
            "Required when selfhost_ssh is set.", "hosting"),
    Setting("host", "str", "127.0.0.1", "Address the board server binds. Loopback (default) keeps it on this "
            "computer (tailnet via tailscale serve); 0.0.0.0 shares it with every device on your network, "
            "unauthenticated, so local links open on other devices.", "hosting",
            choices=("127.0.0.1", "localhost", "::1", "0.0.0.0")),
    Setting("owner", "str", "auto", "Who owns board storage and wake-ups: the running board server. auto = use this "
            "process's own store when the server watches it; inside a Kanban worker whose store is not watched, "
            "create in the server's store instead (reported in the result); anywhere else refuse rather than "
            "publish an orphan board. service = always the server's store. self = this process's store, no server "
            "check (own server, tests).", "hosting", choices=("auto", "service", "self")),
    Setting("port", "int", 8790, "Port the board server binds.", "hosting", lo=1, hi=65535),
    Setting("local_base", "str", "", "URL the CLI uses to reach the server. Empty: http://<host>:<port>.",
            "hosting"),
    Setting("lan_address", "str", "", "Address local-mode links use. Empty: this computer's network address, "
            "detected (127.0.0.1 while the server binds loopback only).", "hosting"),
    # demo
    Setting("offer_live_demo", "bool", False, "Allow a prototype (\"try it live\") round. Off: create/add-round "
            "refuse one unless the call allows it.", "demo"),
    # housekeeping
    Setting("data_dir", "str", "", "Where reviews live. Empty: $HERMES_HOME/workspace/mock-reviews.",
            "housekeeping", env="MOCKREVIEW_HOME"),
    Setting("auto_close_idle_days", "int", 0, "Close an open review after this many days without a new round or "
            "feedback (here.now: its public site is deleted). 0 = never.", "housekeeping", lo=0, hi=3650),
    Setting("keep_closed_days", "int", 0, "Delete a closed review this many days after it closed. "
            "0 = keep forever.", "housekeeping", lo=0, hi=3650),
    Setting("housekeeping_seconds", "int", 3600, "Seconds between the server's auto-close/prune passes.",
            "housekeeping", lo=60, hi=604800),
    # server
    Setting("autostart", "bool", False, "Start the board server inside the Hermes gateway process (a background "
            "thread serving host:port) when the gateway's webhook platform connects. Off (default): nothing runs in "
            "the background; run `hermes mockreview serve` yourself. Restart the gateway after changing it, host or "
            "port.", "server"),
]
BY_NAME: Dict[str, Setting] = {s.name: s for s in SPEC}
REVIEW_KEYS: Tuple[str, ...] = tuple(s.name for s in SPEC if s.review)


# ---------------------------------------------------------------- paths of the config file itself

def default_hermes_home() -> Path:
    """Hermes's own default when HERMES_HOME is unset (the same rule as hermes_constants, not imported from it):
    %LOCALAPPDATA%\\hermes on Windows, else ~/.hermes."""
    suffix = os.environ.get("HERMES_DATA_DIR_SUFFIX", "")
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "").strip()
        return (Path(local) if local else Path.home() / "AppData" / "Local") / ("hermes" + suffix)
    return Path.home() / (".hermes" + suffix)


def hermes_home() -> Path:
    v = os.environ.get("HERMES_HOME")
    return Path(v).expanduser() if v else default_hermes_home()


def config_path() -> Path:
    v = os.environ.get("MOCKREVIEW_CONFIG")
    return Path(v).expanduser() if v else hermes_home() / "config.yaml"


# ---------------------------------------------------------------- the strict mini parser (no PyYAML)

class _Line:
    __slots__ = ("no", "indent", "text")

    def __init__(self, no: int, indent: int, text: str):
        self.no, self.indent, self.text = no, indent, text


_KEY = re.compile(r"""^(?P<key>'[^']*'|"[^"]*"|[^\s'"#\-\[\]{}&*!|>%@`][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s+(?P<rest>.*)|$)""")
_INT = re.compile(r"^[-+]?(0|[1-9][0-9_]*)$")
_FLOAT = re.compile(r"^[-+]?([0-9][0-9_]*)?\.[0-9_]*([eE][-+]?[0-9]+)?$|^[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+$")


def _lines(text: str) -> List[_Line]:
    out = []
    for no, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip()
        st = s.lstrip(" ")
        if not st or st.startswith("#") or st in ("---", "..."):
            continue
        out.append(_Line(no, len(s) - len(st), st))
    return out


def _quoted(tok: str, no: int) -> Tuple[str, str]:
    """A quoted scalar at the start of tok -> (value, the rest after the closing quote)."""
    q = tok[0]
    i = 1
    while i < len(tok):
        c = tok[i]
        if q == "'" and c == "'":
            if tok[i + 1:i + 2] == "'":
                i += 2
                continue
            return tok[1:i].replace("''", "'"), tok[i + 1:]
        if q == '"' and c == "\\":
            i += 2
            continue
        if q == '"' and c == '"':
            try:
                return json.loads(tok[:i + 1]), tok[i + 1:]
            except ValueError:
                raise SettingsError(f"line {no}: unsupported escape in a double-quoted string")
        i += 1
    raise SettingsError(f"line {no}: unterminated quoted string")


def _plain(tok: str) -> str:
    m = re.search(r"\s#", tok)
    return (tok[:m.start()] if m else tok).strip()


def _scalar(tok: str, no: int) -> Any:
    tok = tok.strip()
    if tok[:1] in ("'", '"'):
        val, rest = _quoted(tok, no)
        rest = rest.strip()
        if rest and not rest.startswith("#"):
            raise SettingsError(f"line {no}: unexpected text after a quoted string")
        return val
    tok = _plain(tok)
    if tok[:1] in ("&", "*", "!", "|", ">", "{", "[", "%", "@", "`"):
        raise SettingsError(f"line {no}: unsupported YAML ({tok[:1]!r}) in mock-review settings")
    low = tok.lower()
    if low in ("", "null", "~"):
        return None
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if _INT.match(tok):
        return int(tok.replace("_", ""))
    if _FLOAT.match(tok) and any(ch.isdigit() for ch in tok):
        return float(tok.replace("_", ""))
    return tok


def _flow_list(tok: str, no: int) -> List[Any]:
    """[a, 'b', 3] on one line. Nested lists/maps are refused."""
    tok = tok.strip()
    items: List[Any] = []
    i, cur = 1, ""

    def close(at: int) -> List[Any]:
        rest = tok[at + 1:].strip()
        if rest and not rest.startswith("#"):
            raise SettingsError(f"line {no}: unexpected text after a list")
        return items

    while i < len(tok):
        c = tok[i]
        if c in "'\"" and not cur.strip():
            val, rest = _quoted(tok[i:], no)
            items.append(val)
            i = len(tok) - len(rest)
            while i < len(tok) and tok[i] == " ":
                i += 1
            if i >= len(tok) or tok[i] not in ",]":
                raise SettingsError(f"line {no}: expected , or ] after a quoted list item")
            if tok[i] == "]":
                return close(i)
            i, cur = i + 1, ""
            continue
        if c in "[{":
            raise SettingsError(f"line {no}: nested lists/maps aren't supported in mock-review settings")
        if c in ",]":
            if cur.strip():
                items.append(_scalar(cur, no))
            cur = ""
            if c == "]":
                return close(i)
        else:
            cur += c
        i += 1
    raise SettingsError(f"line {no}: unterminated [list]")


def _key(line: _Line) -> Optional[Tuple[str, str]]:
    m = _KEY.match(line.text)
    if not m:
        return None
    k = m.group("key").strip()
    if k[:1] in ("'", '"'):
        k = _quoted(k, line.no)[0]
    return k, (m.group("rest") or "")


def _find(lines: List[_Line], lo: int, hi: int, key: str) -> Optional[int]:
    """Index of `key:` among the direct children of lines[lo:hi] (the block's first line sets the indent)."""
    if lo >= hi:
        return None
    ci = lines[lo].indent
    for k in range(lo, hi):
        ln = lines[k]
        if ln.indent == ci and not ln.text.startswith("- "):
            kv = _key(ln)
            if kv and kv[0] == key:
                return k
    return None


def _block_end(lines: List[_Line], k: int, hi: int) -> int:
    ind = lines[k].indent
    j = k + 1
    while j < hi and (lines[j].indent > ind):
        j += 1
    return j


def _parse_mapping(lines: List[_Line], lo: int, hi: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if lo >= hi:
        return out
    ci = lines[lo].indent
    k = lo
    while k < hi:
        ln = lines[k]
        kv = _key(ln) if ln.indent == ci and not ln.text.startswith("-") else None
        if not kv:
            raise SettingsError(f"line {ln.no}: expected `name: value` in mock-review settings")
        name, rest = kv
        rest = rest.strip()
        k += 1
        if rest and not rest.startswith("#"):
            if rest.startswith("{"):
                if _plain(rest) != "{}":
                    raise SettingsError(f"line {ln.no}: nested maps aren't supported in mock-review settings")
                out[name] = {}
            elif rest.startswith("["):
                out[name] = _flow_list(rest, ln.no)
            else:
                out[name] = _scalar(rest, ln.no)
            if k < hi and lines[k].indent > ci:
                raise SettingsError(f"line {lines[k].no}: multi-line values aren't supported in mock-review settings")
            continue
        items: List[Any] = []
        while k < hi and (lines[k].indent > ci or (lines[k].indent == ci and lines[k].text[:2] in ("- ", "-"))):
            t = lines[k].text
            if not (t.startswith("- ") or t == "-"):
                raise SettingsError(f"line {lines[k].no}: nested maps aren't supported in mock-review settings")
            item = t[1:].strip()
            if item.startswith(("[", "{")) or (item[:1] not in ("'", '"') and _KEY.match(item)):
                raise SettingsError(f"line {lines[k].no}: nested values aren't supported in mock-review settings")
            items.append(_scalar(item, lines[k].no))
            k += 1
        out[name] = items if items else None
    return out


def parse_plugin_settings(text: str, plugin: str = PLUGIN_ID) -> Dict[str, Any]:
    """plugins.entries.<plugin>.settings out of a config.yaml, without PyYAML. Strict inside that mapping."""
    lines = _lines(text)
    lo, hi = 0, len(lines)
    for key in ("plugins", "entries", plugin, "settings"):
        k = _find(lines, lo, hi, key)
        if k is None:
            return {}
        rest = _plain(_key(lines[k])[1]).strip()
        if rest:
            if rest in ("{}", "null", "~"):
                return {}
            raise SettingsError(f"line {lines[k].no}: `{key}:` must be a block mapping for the no-PyYAML reader")
        end = _block_end(lines, k, hi)
        lo, hi = k + 1, end
    return _parse_mapping(lines, lo, hi)


def _yaml_module():
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        return None


def _from_yaml(text: str, yaml) -> Dict[str, Any]:
    doc = yaml.safe_load(text) or {}
    node: Any = doc
    for key in ("plugins", "entries", PLUGIN_ID, "settings"):
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


_cache: Dict[str, Any] = {"key": None, "values": {}, "error": None, "reader": ""}
FORCE_MINI_PARSER = False   # tests flip this to exercise the no-PyYAML path under a Python that has PyYAML


def file_settings() -> Tuple[Dict[str, Any], Optional[str], str]:
    """(settings mapping, error or None, reader name). Cached on (path, mtime, size)."""
    p = config_path()
    try:
        st = p.stat()
    except FileNotFoundError:
        return {}, None, "none (no config.yaml)"
    except OSError as e:
        return {}, f"cannot stat {p}: {e}", "none"
    yaml = None if FORCE_MINI_PARSER else _yaml_module()
    reader = "PyYAML" if yaml else "built-in parser (no PyYAML)"
    ckey = (str(p), st.st_mtime_ns, st.st_size, reader)
    if _cache["key"] == ckey:
        return _cache["values"], _cache["error"], _cache["reader"]
    values: Dict[str, Any] = {}
    error = None
    try:
        text = p.read_text(encoding="utf-8")
        values = _from_yaml(text, yaml) if yaml else parse_plugin_settings(text)
    except Exception as e:  # unreadable or unsupported: fall back to env/defaults, loudly
        error = f"{p}: {e}"
        log.warning("mock-review settings in config.yaml ignored (%s); using env vars and defaults", error)
    _cache.update(key=ckey, values=values, error=error, reader=reader)
    return values, error, reader


# ---------------------------------------------------------------- coercion + resolution

def coerce(s: Setting, v: Any) -> Any:
    """Validate/convert one value for a setting. Raises SettingsError with a message naming the setting."""
    def bad(why: str) -> SettingsError:
        return SettingsError(f"setting {s.name}: {why} (got {v!r})")
    if s.type == "bool":
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)) and v in (0, 1):
            return bool(v)
        if isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"):
            return True
        if isinstance(v, str) and v.strip().lower() in ("0", "false", "no", "off"):
            return False
        raise bad("must be true or false")
    if s.type in ("int", "float"):
        if isinstance(v, bool):
            raise bad("must be a number")
        try:
            n = float(v) if s.type == "float" else int(str(v).strip()) if isinstance(v, str) else v
            if s.type == "int" and isinstance(n, float):
                if n != int(n):
                    raise ValueError
                n = int(n)
            n = float(n) if s.type == "float" else int(n)
        except (TypeError, ValueError):
            raise bad(f"must be {'an integer' if s.type == 'int' else 'a number'}")
        if (s.lo is not None and n < s.lo) or (s.hi is not None and n > s.hi):
            raise bad(f"must be between {s.lo:g} and {s.hi:g}")
        return n
    if s.type == "list":
        if isinstance(v, str):
            v = [x for x in re.split(r"[,\s]+", v.strip()) if x]
        if not isinstance(v, (list, tuple)):
            raise bad("must be a list")
        items = [str(x).strip().lower() for x in v]
        if s.name == "devices":
            if not items:
                raise bad("needs at least one of desktop, tablet, mobile")
            unknown = [x for x in items if x not in DEVICES]
            if unknown:
                raise bad(f"unknown device {unknown[0]!r}; use desktop, tablet, mobile")
            if len(set(items)) != len(items):
                raise bad("lists a device twice")
            return [d for d in DEVICES if d in items]
        if s.name == "wake_toolsets":
            items = [x for x in items if x]
            bad_names = [x for x in items if not re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,63}", x)]
            if bad_names:
                raise bad(f"toolset name not valid: {bad_names[0]!r} (lowercase letters, digits, _ . : -)")
            return list(dict.fromkeys(items))
        return items
    if v is None:
        v = ""
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        raise bad("must be text")
    v = str(v).strip()
    if s.aliases:
        v = s.aliases.get(v.lower(), v)
    if s.choices:
        v = v.lower() if v.lower() in s.choices else v
        if v not in s.choices:
            raise bad("must be one of " + ", ".join(s.choices))
    return v


ConfigSource = Callable[[str], Any]   # name -> value, or settings.MISSING
MISSING = _MISSING
_config_source: ContextVar[Optional[ConfigSource]] = ContextVar("mockreview_config_source", default=None)


def set_config_source(fn: Optional[ConfigSource]) -> None:
    """Inside Hermes the plugin reads its settings through ctx.get_config; None = read config.yaml directly."""
    _config_source.set(fn)


def _config_value(name: str) -> Tuple[Any, str]:
    source = _config_source.get()
    if source is not None:
        try:
            v = source(name)
        except Exception as e:
            log.warning("plugin get_config(%s) failed: %s", name, e)
            v = MISSING
        return v, f"config.yaml via Hermes get_config (plugins.entries.{PLUGIN_ID}.settings.{name})"
    values, _, _ = file_settings()
    return (values[name] if name in values else MISSING), f"config.yaml (plugins.entries.{PLUGIN_ID}.settings.{name})"


def resolve_one(name: str, override: Any = None) -> Tuple[Any, str, List[str]]:
    """(value, where it came from, warnings). An invalid override raises; an invalid env/config value is skipped."""
    s = BY_NAME[name]
    notes: List[str] = []
    if override is not None:
        try:
            return coerce(s, override), "override", notes
        except SettingsError as e:
            raise SettingsError(str(e) + " — passed for this call")
    ev = os.environ.get(s.env_name)
    if ev is not None and ev != "":
        try:
            return coerce(s, ev), f"env {s.env_name}", notes
        except SettingsError as e:
            notes.append(f"{e} — env {s.env_name} ignored")
    cv, where = _config_value(name)
    if cv is not MISSING and cv is not None:
        try:
            return coerce(s, cv), where, notes
        except SettingsError as e:
            notes.append(f"{e} — config.yaml value ignored")
    for n in notes:
        log.warning("%s", n)
    return (list(s.default) if isinstance(s.default, list) else s.default), "default", notes


def get(name: str, override: Any = None) -> Any:
    return resolve_one(name, override)[0]


def resolve_all(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Every setting with its value and source (for `mockreview settings`)."""
    overrides = overrides or {}
    out = {}
    for s in SPEC:
        v, src, notes = resolve_one(s.name, overrides.get(s.name))
        out[s.name] = {"value": v, "source": src, **({"warnings": notes} if notes else {})}
    return out


def review_settings(overrides: Optional[Dict[str, Any]] = None, base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The look/feedback settings stored in a review. `base` = what the review already has (add-round keeps it)."""
    overrides = {k: v for k, v in (overrides or {}).items() if v is not None and k in REVIEW_KEYS}
    out: Dict[str, Any] = {}
    for name in REVIEW_KEYS:
        if name in overrides:
            out[name] = resolve_one(name, overrides[name])[0]
        elif base and name in base:
            out[name] = base[name]
        else:
            out[name] = get(name)
    dd = out["default_device"]
    if dd != "auto" and dd not in out["devices"]:
        if "default_device" in overrides:
            raise SettingsError(f"setting default_device: {dd!r} isn't one of devices {out['devices']}")
        out["default_device"] = "auto"
    return out


def describe() -> Dict[str, Any]:
    """Where the config.yaml layer comes from and how it was read."""
    if _config_source.get() is not None:
        return {"config": "Hermes ctx.get_config", "reader": "Hermes", "error": None}
    _, err, reader = file_settings()
    return {"config": str(config_path()), "reader": reader, "error": err}


def render_config_schema(indent: str = "  ") -> str:
    """The plugin.yaml `config_schema:` block for SPEC (scripts/gen_plugin_manifest.py writes it; a test checks it)."""
    def scalar(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return repr(v)
        if isinstance(v, list):
            return "[" + ", ".join(v) + "]"
        return json.dumps(v)
    lines = ["config_schema:"]
    for s in SPEC:
        lines.append(f"{indent}{s.name}:")
        lines.append(f"{indent * 2}type: {s.type}")
        lines.append(f"{indent * 2}default: {scalar(s.default)}")
        if s.choices:
            lines.append(f"{indent * 2}enum: [{', '.join(json.dumps(c) for c in s.choices)}]")
        lines.append(f"{indent * 2}description: {json.dumps(s.description + ' Env: ' + s.env_name + '.')}")
    for name, env, description in (
        ("herenow_api_key", "HERENOW_API_KEY", "Optional here.now key; required only for public hosting."),
        ("webhook_secret", "MOCKREVIEW_WEBHOOK_SECRET", "Optional signing secret; required only for wake delivery."),
    ):
        lines.extend((f"{indent}{name}:", f"{indent * 2}type: secret", f"{indent * 2}env: {env}",
                      f"{indent * 2}required: false", f"{indent * 2}description: {json.dumps(description)}"))
    return "\n".join(lines) + "\n"
