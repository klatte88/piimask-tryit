"""
The local app's server: the try-it page and its API, for this computer only.

`LocalApp(home)` binds a `ThreadingHTTPServer` on `("127.0.0.1", 0)` (a free
port, never another interface), makes a fresh secret path
(`secrets.token_urlsafe`) and a fresh API token, starts one `TryItSession` at
the stored counter (`instance.load_counter(home).value`), opens the `SafeLog`
(prunes 30 days, writes `session_start`) and writes `running.json`.
`serve_forever()` blocks; `shutdown()` (from another thread) stops it;
`close()` clears `running.json` and frees the port. Tests and the CLI use
`start_in_thread()` / `stop()` or the context manager.

Every request, in this order:
1. Host must be `127.0.0.1:<port>` or `localhost:<port>`, else 421, no body
   (DNS rebinding).
2. `GET /proof?nonce=<32 lowercase hex>` (the one route outside the secret)
   answers `{"proof": instance.proof_for(secret, nonce)}`, so the running-copy
   probe can tell this copy is the real one without the secret ever being
   sent. Any other query or a bad nonce is 404, no body.
3. The path must start with `/<secret>/` and the rest must be `""` (the page),
   `mode.json`, `api`, `bundle` or one of the packaged web files (an
   allow-list read once at start; names starting with `_` or `.` are never
   served), else 404, no body. A query string is ignored.
4. `OPTIONS` (a CORS preflight) and any method other than GET/POST is 405 with
   no CORS headers; a POST to a file or a GET of `api`/`bundle` is 405 too.
5. POST: `Origin`, when present, must be `http://127.0.0.1:<port>` or
   `http://localhost:<port>`, and `Sec-Fetch-Site`, when present, must be
   `same-origin` (else 403); `X-Piimask-Token` must match
   (`hmac.compare_digest`, else 403); `Content-Type` must be
   `application/json` (else 415); the body must have a `Content-Length` of at
   most 256 KB (else 413, or 400 when missing). All with no body.
   `GET mode.json` (it holds the token) also refuses a `Sec-Fetch-Site` that
   is neither `same-origin` nor `none` (403).

`mode.json` -> `{"transport": "local", "token", "version", "log_ok",
"notices"?}`; `notices` is `["counter_reset"]` only when the stored counter
was damaged at this start. `api` and `bundle` follow the app's HTTP
interface. The reveal field from the page is
`answer`; the session's `call` takes `text`, so the server maps it.

One `threading.Lock` is held around `session.call` + `SafeLog.record` +
`instance.save_counter` (saved after EVERY call, refusals included), and
around flags and bundle work, so a double click cannot corrupt the key.

Every response, errors included, carries `headers.response_headers()` (the
CSP from `web/_headers`, `Referrer-Policy: no-referrer`, `Cache-Control:
no-store`, `nosniff`) and never an `Access-Control-Allow-*` header.
`log_message` prints nothing and `handle_error` prints no traceback, so no
value, secret or token reaches the console.

A flags save that the log could not join to exactly one prompt answers
`{"ok": false, "code": "unknown_prompt" | "flags_mismatch" | "ambiguous_prompt"}`.

The server stops on its own after `idle_limit` seconds (8 h) without a
request under the secret path (a refused request or `/proof` never counts) (`clock` and `idle_poll` are injectable for tests). The key lives in
the session's memory only, so stopping wipes it.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, Self

from piimask.localapp import headers as _headers
from piimask.localapp import instance
from piimask.localapp.log import SafeLog

MAX_BODY = 256 * 1024
IDLE_LIMIT_S = 8 * 60 * 60
IDLE_POLL_S = 30.0
PRUNE_DAYS = 30

_PROOF_QUERY = re.compile(r"nonce=([0-9a-f]{32})")
_ROUTES = ("mode.json", "api", "bundle")
_SESSION_OPS = ("mask", "reveal", "reset")
_FLAG_KEYS = ("misses", "over_masks", "restore_wrong", "checked_all", "useful")
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}


def app_version() -> str:
    """The installed version (standalone package first, then the project), else "0"."""
    from importlib import metadata

    for name in ("piimask-tryit", "pii-masking-saas"):
        try:
            return metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return "0"


def downloads_dir() -> Path:
    """Where a bundle is saved: `PIIMASK_TRYIT_DOWNLOADS`, else `~/Downloads`.

    Only the path is decided here; `save_bundle` creates the folder if it is missing.
    """
    override = os.environ.get("PIIMASK_TRYIT_DOWNLOADS")
    return Path(override) if override else Path.home() / "Downloads"


def bundle_file_name(now: datetime) -> str:
    return f"piimask-feedback-{now:%Y-%m-%d-%H%M}.zip"


def save_bundle(data: bytes, folder: Path, now: datetime) -> Path:
    """Write `data` under `folder` with a fresh name (never overwrites); return the path.

    The folder is created if missing. On POSIX the file is created owner-only
    (`0o600`, at creation, so it is never readable by others even for a
    moment); on Windows it is created normally (the Downloads folder is the
    user's own, and modes are ignored there).
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    base = bundle_file_name(now)
    stem = base[: -len(".zip")]
    for n in range(1, 1000):
        path = folder / (base if n == 1 else f"{stem}-{n}.zip")
        try:
            if os.name == "nt":
                with open(path, "xb") as fh:
                    fh.write(data)
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
        except FileExistsError:
            continue
        return path
    raise FileExistsError("bundle_name_taken")


def _web_files(root: Traversable | Path) -> dict[str, tuple[bytes, str]]:
    """The allow-list: every plain file in the page folder with a known type, read once."""
    out: dict[str, tuple[bytes, str]] = {}
    try:
        entries = list(root.iterdir())
    except (OSError, FileNotFoundError):
        return out
    for entry in entries:
        name = entry.name
        if name.startswith(("_", ".")) or not entry.is_file():
            continue
        ext = name[name.rfind("."):].lower() if "." in name else ""
        ctype = _CONTENT_TYPES.get(ext)
        if ctype is None or name in _ROUTES:
            continue
        out[name] = (entry.read_bytes(), ctype)
    return out


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64  # the stdlib's 5 resets a burst of page requests
    app: LocalApp

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Never print a traceback: it could quote a value."""


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "piimask"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- output ---------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:
        """Silent: a request line holds the secret path."""

    def _send(self, status: int, body: bytes = b"", ctype: str | None = None) -> None:
        self.send_response(status)
        for name, value in self.server.app.response_headers:
            self.send_header(name, value)
        if ctype is not None:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if status >= 400 and not body:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _refuse(self, status: int) -> None:
        self._send(status)

    def _json(self, obj: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """The stdlib's own errors (bad request line, too long) go out bare, with the headers."""
        try:
            self._send(code)
        except Exception:  # noqa: BLE001, S110 - the client is gone
            pass

    # -- routing --------------------------------------------------------

    def _host_ok(self) -> bool:
        host = self.headers.get("Host")
        if host is None:
            return False
        port = self.server.app.port
        return host in (f"127.0.0.1:{port}",) or host.lower() == f"localhost:{port}"

    def _route(self) -> str | None:
        """The name after the secret prefix (query dropped), or None when not under it."""
        path = self.path.split("?", 1)[0]
        prefix = f"/{self.server.app.secret}/"
        if not path.startswith(prefix):
            return None
        rest = path[len(prefix):]
        if rest == "":
            return "index.html"
        if rest in _ROUTES or rest in self.server.app.web_files:
            return rest
        return None

    def _handle(self) -> None:
        app = self.server.app
        try:
            if not self._host_ok():
                return self._refuse(421)
            if self.command == "GET" and self.path.split("?", 1)[0] == "/proof":
                return self._proof()
            route = self._route()
            if route is None:
                return self._refuse(404)
            # Only a request under the secret path keeps the app alive: a refused one
            # (wrong Host, wrong path) or the open `/proof` never resets the idle time.
            app.touch()
            if self.command == "GET":
                if route in ("api", "bundle"):
                    return self._refuse(405)
                if route == "mode.json":
                    return self._mode()
                if route not in app.web_files:
                    return self._refuse(404)
                body, ctype = app.web_files[route]
                return self._send(200, body, ctype)
            if self.command == "POST":
                if route not in ("api", "bundle"):
                    return self._refuse(405)
                return self._post(route)
            return self._refuse(405)
        except Exception:  # noqa: BLE001 - the boundary: a code, never a traceback
            try:
                self._refuse(500)
            except Exception:  # noqa: BLE001, S110 - the client is gone
                pass

    do_GET = _handle
    do_POST = _handle
    do_OPTIONS = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle

    # -- the routes -----------------------------------------------------

    def _proof(self) -> None:
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        m = _PROOF_QUERY.fullmatch(query)
        if m is None:
            return self._refuse(404)
        nonce = m.group(1)
        self._json({"proof": instance.proof_for(self.server.app.secret, nonce)})

    def _mode(self) -> None:
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            return self._refuse(403)
        self._json(self.server.app.mode())

    def _post(self, route: str) -> None:
        app = self.server.app
        origin = self.headers.get("Origin")
        if origin is not None and origin not in app.origins:
            return self._refuse(403)
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site != "same-origin":
            return self._refuse(403)
        token = self.headers.get("X-Piimask-Token")
        if token is None or not hmac.compare_digest(token.encode("utf-8"), app.token.encode("utf-8")):
            return self._refuse(403)
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            return self._refuse(415)
        if self.headers.get("Transfer-Encoding") is not None:
            return self._refuse(400)
        length_raw = self.headers.get("Content-Length")
        try:
            length = int(length_raw) if length_raw is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            return self._refuse(400)
        if length > MAX_BODY:
            return self._refuse(413)
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            body = None
        if not isinstance(body, dict):
            return self._json({"ok": False, "code": "bad_request"}, 400)
        if route == "api":
            return self._json(app.api(body))
        return self._json(app.bundle_request(body))


class LocalApp:
    """One running copy of the app; see the module docstring."""

    def __init__(
        self,
        home: Path,
        *,
        web_root: Traversable | Path | None = None,
        clock: Callable[[], float] = time.monotonic,
        idle_limit: float = IDLE_LIMIT_S,
        idle_poll: float = IDLE_POLL_S,
        now: Callable[[], datetime] | None = None,
        downloads: Path | None = None,
        version: str | None = None,
    ) -> None:
        from piimask.tryit.session import TryItSession  # lazy: the masker loads at start

        self.home = Path(home)
        self.version = app_version() if version is None else version
        root = _headers.default_web_root() if web_root is None else web_root
        self.response_headers = _headers.response_headers(root)
        self.web_files = _web_files(root)
        self.secret = secrets.token_urlsafe(32)
        self.token = secrets.token_urlsafe(32)
        self._clock = clock
        self._idle_limit = idle_limit
        self._idle_poll = idle_poll
        self._now = now or (lambda: datetime.now().astimezone())
        self._downloads = downloads
        self._lock = threading.Lock()
        self._last = clock()
        self._stopped = threading.Event()
        self._serving = False
        self._thread: threading.Thread | None = None
        self.state_ok = True
        self.idle_stopped = False

        counter = instance.load_counter(self.home)
        self.notices = [counter.notice] if counter.notice else []
        self.session = TryItSession(initial_counter=counter.value)
        self.log = SafeLog(self.home, now=self._now, app_version=self.version)
        self.log.prune(PRUNE_DAYS)
        self.log.session_start()

        self.httpd = _Server(("127.0.0.1", 0), _Handler)
        self.httpd.app = self
        self.port = int(self.httpd.server_address[1])
        self.origins = (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}")
        self.info = instance.RunningInfo(pid=os.getpid(), port=self.port, secret=self.secret)
        instance.write_running(self.home, self.info)
        self._watcher = threading.Thread(target=self._watch_idle, name="piimask-idle", daemon=True)
        self._watcher.start()

    # -- lifecycle ------------------------------------------------------

    @property
    def url(self) -> str:
        return instance.url_for(self.info)

    def touch(self) -> None:
        self._last = self._clock()

    def _watch_idle(self) -> None:
        while not self._stopped.wait(self._idle_poll):
            if self._clock() - self._last >= self._idle_limit:
                self.idle_stopped = True
                self.shutdown()
                return

    def serve_forever(self) -> None:
        self._serving = True
        try:
            self.httpd.serve_forever(poll_interval=0.2)
        finally:
            self._serving = False
            self._stopped.set()

    def shutdown(self) -> None:
        """Stop `serve_forever` (call from another thread than the one serving)."""
        self._stopped.set()
        self.httpd.shutdown()

    def shutdown_from_thread(self) -> None:
        """For a signal handler: shut down on a helper thread so the serving thread is not blocked."""
        threading.Thread(target=self.shutdown, name="piimask-stop", daemon=True).start()

    def close(self) -> None:
        """Free the port and clear `running.json` (only when it still names this copy)."""
        self._stopped.set()
        self.httpd.server_close()
        try:
            current = instance._read_running(instance._running_path(self.home))
            if current is None or current.secret == self.secret:
                instance.clear_running(self.home)
        except Exception:  # noqa: BLE001, S110 - stopping never fails on cleanup
            pass

    def start_in_thread(self) -> Self:
        self._thread = threading.Thread(target=self.serve_forever, name="piimask-serve", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self.shutdown()
            self._thread.join(timeout=10)
        self.close()

    def __enter__(self) -> Self:
        return self.start_in_thread()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- answers --------------------------------------------------------

    def log_ok(self) -> bool:
        return not self.log.broken and self.state_ok

    def mode(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "transport": "local",
            "token": self.token,
            "version": self.version,
            "log_ok": self.log_ok(),
        }
        if self.notices:
            out["notices"] = list(self.notices)
        return out

    def _save_counter(self) -> None:
        try:
            instance.save_counter(self.home, self.session.counter)
        except Exception:  # noqa: BLE001 - fail closed: masking goes on, the page is told
            self.state_ok = False

    def api(self, body: dict[str, Any]) -> dict[str, Any]:
        op = body.get("op")
        prompt_id = body.get("prompt_id")
        purpose = body.get("purpose")
        ui_lang = body.get("ui_lang")
        if op == "flags":
            echo = {k: body[k] for k in _FLAG_KEYS if k in body}
            with self._lock:
                code = self.log.record("flags", echo, prompt_id)
                if code is not None:
                    # Not joined to any prompt (unknown, fits none, or fits more than one).
                    return {"ok": False, "code": code}
                return {"ok": True, "log_ok": self.log_ok()}
        if op not in _SESSION_OPS:
            return {"ok": False, "code": "unknown_op"}
        request: dict[str, Any] = {"op": op}
        if op == "mask":
            request["text"] = body.get("text")
        elif op == "reveal":
            request["text"] = body.get("answer", body.get("text"))
        with self._lock:
            started = time.perf_counter()
            response: dict[str, Any] = json.loads(self.session.call(json.dumps(request)))
            ms = round((time.perf_counter() - started) * 1000, 1)
            if op == "reset":
                self.log.record("reset", response)
            else:
                self.log.record(op, response, prompt_id, purpose, ui_lang, ms=ms)
            self._save_counter()
            response["log_ok"] = self.log_ok()
        return response

    def bundle_request(self, body: dict[str, Any]) -> dict[str, Any]:
        action = body.get("action")
        if action == "preview":
            with self._lock:
                return {"ok": True, "prompts": self.log.preview(), "log_ok": self.log_ok()}
        if action == "save":
            include = body.get("include")
            if not isinstance(include, list) or not all(isinstance(i, str) for i in include):
                return {"ok": False, "code": "bad_request"}
            with self._lock:
                data = self.log.bundle(set(include))
                try:
                    folder = self._downloads if self._downloads is not None else downloads_dir()
                    path = save_bundle(data, folder, self._now())
                except Exception:  # noqa: BLE001 - a code, never a path
                    return {"ok": False, "code": "save_failed"}
            return {"ok": True, "file_name": path.name}
        return {"ok": False, "code": "bad_request"}
