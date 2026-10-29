"""
One running copy per machine, and a code counter that never goes back.

Both live under the app home's `state/` folder (see `paths`):

- `counter.json` `{"counter": n}`: the last code number any run minted.
  The app starts its `TryItSession` at `load_counter(home).value` and calls
  `save_counter(home, session.counter)` after EVERY `call`, refusals included
  (a D42 refusal comes after the spans before it were minted). A save is
  atomic (`paths.write_private_bytes`, an `os.replace`) and never lowers the
  stored number, so a later run never hands out a code an earlier run used,
  and an old answer pasted into a new run shows its codes as unresolved
  instead of revealing someone else.
  A missing file starts at the settings floor (`counter_start`) quietly.
  A damaged one (unreadable, not JSON, not a non-negative integer) also starts
  at the floor, but `load_counter` reports `reset_notice=True` with the notice
  code `NOTICE_COUNTER_RESET`, and rewrites a valid file at once so the notice
  shows only on that one start. The page owns the words for the code (English
  first, Dutch "Je codes beginnen opnieuw; oude antwoorden kan ik niet
  terugzetten").

- `running.json` `{"pid", "port", "secret"}`: written at start, removed at
  stop. `find_running` asks the copy it names whether it is alive; a file that
  is unreadable or names no live copy is stale and is removed. The default
  probe never sends the secret anywhere and never consults a proxy: the
  recorded pid must be alive, then a direct `http.client` GET of
  `http://127.0.0.1:<port>/proof?nonce=<32 hex>` (1 s timeout) must answer 200
  with `{"proof": proof_for(secret, nonce)}`. A process squatting on a stale
  port cannot answer that without the secret, so the browser is never sent
  to it. `forget` refuses with `AppRunningError` while a live copy exists,
  and otherwise deletes the whole app home. The typed confirmation belongs to
  the CLI, not here.

No message or exception here carries a value, a secret or a path: codes only.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from piimask.localapp import paths
from piimask.settings import DEFAULT_COUNTER_START

COUNTER_FILENAME = "counter.json"
RUNNING_FILENAME = "running.json"

# The notice code for a counter that had to start again at the floor.
NOTICE_COUNTER_RESET = "counter_reset"

PROBE_TIMEOUT_S = 1.0

# A secret the URL can carry as one path segment, without quoting.
_SECRET_SHAPE = re.compile(r"[A-Za-z0-9_-]{8,256}")


class InstanceError(Exception):
    """A refusal from this module; `code` says which, the message is the code only."""

    code = "instance_error"

    def __init__(self) -> None:
        super().__init__(self.code)


class AppRunningError(InstanceError):
    """`forget` while a live copy of the app is running."""

    code = "app_running"


class UnsafeHomeError(InstanceError):
    """`forget` pointed at a folder that cannot be the app home (a root or the user home)."""

    code = "unsafe_home"


# ----------------------------------------------------------------------
# The counter
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class CounterState:
    """The counter to start at, and whether the page must show the reset notice."""

    value: int
    reset_notice: bool = False

    @property
    def notice(self) -> str | None:
        """`NOTICE_COUNTER_RESET` when the page must say the codes started again, else None."""
        return NOTICE_COUNTER_RESET if self.reset_notice else None


def counter_floor() -> int:
    """The shipped `counter_start` (`Settings.defaults(...).counter_start`)."""
    return DEFAULT_COUNTER_START


def _counter_path(home: Path) -> Path:
    return paths.state_dir(Path(home)) / COUNTER_FILENAME


def _is_count(n: object) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and n >= 0


def _read_counter(path: Path) -> int | None:
    """The stored counter, or None when missing; raises ValueError when damaged."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("counter_unreadable") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("counter_not_json") from exc
    n = data.get("counter") if isinstance(data, dict) else None
    if not _is_count(n):
        raise ValueError("counter_not_a_count")
    assert isinstance(n, int)
    return n


def _write_counter(home: Path, n: int) -> None:
    paths.ensure_home(Path(home))
    payload = json.dumps({"counter": n}, sort_keys=True).encode("utf-8")
    paths.write_private_bytes(_counter_path(home), payload)


def load_counter(home: Path) -> CounterState:
    """The counter to start the session at: max(stored, floor), plus the one-time notice flag.

    Missing file: the floor, no notice. Damaged file: the floor with
    `reset_notice=True`, and a valid file is written at once so the next load
    carries no notice.
    """
    floor = counter_floor()
    try:
        stored = _read_counter(_counter_path(home))
    except ValueError:
        _write_counter(home, floor)
        return CounterState(value=floor, reset_notice=True)
    if stored is None:
        return CounterState(value=floor)
    return CounterState(value=max(stored, floor))


def save_counter(home: Path, n: int) -> int:
    """Store `n` atomically, never lowering what is stored; return the stored number.

    A damaged stored file counts as nothing stored (it is replaced).
    """
    if not _is_count(n):
        raise TypeError("instance: counter is not a non-negative integer")
    try:
        stored = _read_counter(_counter_path(home))
    except ValueError:
        stored = None
    value = n if stored is None else max(n, stored)
    if value != stored:
        _write_counter(home, value)
    return value


# ----------------------------------------------------------------------
# The running copy
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class RunningInfo:
    """Where the running copy listens. The secret is kept out of `repr`."""

    pid: int
    port: int
    secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not (isinstance(self.pid, int) and not isinstance(self.pid, bool) and self.pid > 0):
            raise ValueError("instance: pid is not a positive integer")
        if not (
            isinstance(self.port, int)
            and not isinstance(self.port, bool)
            and 0 < self.port < 65536
        ):
            raise ValueError("instance: port is out of range")
        if not (isinstance(self.secret, str) and _SECRET_SHAPE.fullmatch(self.secret)):
            raise ValueError("instance: secret has the wrong shape")


Probe = Callable[[RunningInfo], bool]


def url_for(info: RunningInfo) -> str:
    """The page URL of a running copy: `http://127.0.0.1:<port>/<secret>/`."""
    return f"http://127.0.0.1:{info.port}/{info.secret}/"


def proof_for(secret: str, nonce: str) -> str:
    """HMAC-SHA256 of `nonce` under `secret`, as lowercase hex: what `/proof` answers."""
    return hmac.new(secret.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def _pid_alive(pid: int) -> bool:
    """False only when the pid is known to be gone; True when alive or unknown."""
    if sys.platform == "win32":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # PermissionError: alive under another user; anything else: unknown
        return True
    return True


def _pid_alive_windows(pid: int) -> bool:  # pragma: no cover - Windows only
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            # 87 ERROR_INVALID_PARAMETER: no such process; anything else (access denied): unknown.
            return bool(ctypes.get_last_error() != 87)
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return bool(code.value == 259)  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - unknown: let the proof decide
        return True


def default_probe(info: RunningInfo) -> bool:
    """True only for the real copy: its pid is alive and it answers `/proof` correctly.

    The secret never leaves this process: the request carries a fresh nonce
    only, and the answer must be `proof_for(secret, nonce)`. `http.client`
    connects straight to 127.0.0.1, so no proxy setting is ever consulted.
    """
    if not _pid_alive(info.pid):
        return False
    nonce = secrets.token_hex(16)
    conn = http.client.HTTPConnection("127.0.0.1", info.port, timeout=PROBE_TIMEOUT_S)
    try:
        conn.request("GET", f"/proof?nonce={nonce}")
        resp = conn.getresponse()
        if resp.status != 200:
            return False
        data = json.loads(resp.read(4096).decode("utf-8"))
        proof = data.get("proof") if isinstance(data, dict) else None
        if not isinstance(proof, str):
            return False
        return hmac.compare_digest(proof, proof_for(info.secret, nonce))
    except Exception:  # noqa: BLE001 - any failure means "not alive"
        return False
    finally:
        conn.close()


def _running_path(home: Path) -> Path:
    return paths.state_dir(Path(home)) / RUNNING_FILENAME


def write_running(home: Path, info: RunningInfo) -> None:
    """Record this copy as the running one (atomic, 0o600)."""
    paths.ensure_home(Path(home))
    payload = json.dumps(
        {"pid": info.pid, "port": info.port, "secret": info.secret}, sort_keys=True
    ).encode("utf-8")
    paths.write_private_bytes(_running_path(home), payload)


def clear_running(home: Path) -> None:
    """Remove the running record; a missing one is fine."""
    _running_path(home).unlink(missing_ok=True)


def _read_running(path: Path) -> RunningInfo | None:
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
        if not isinstance(data, dict):
            return None
        return RunningInfo(pid=data["pid"], port=data["port"], secret=data["secret"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, TypeError):
        return None


def find_running(home: Path, probe: Probe = default_probe) -> RunningInfo | None:
    """The live running copy, or None. A stale or unreadable record is removed."""
    path = _running_path(home)
    if not path.exists():
        return None
    info = _read_running(path)
    if info is not None and probe(info):
        return info
    clear_running(home)
    return None


# ----------------------------------------------------------------------
# Forget
# ----------------------------------------------------------------------


# What `forget` may delete: the app's own entries, nothing else.
_LOGS_DIRNAME = "logs"
_STATE_DIRNAME = "state"
_STATE_FILES = frozenset({COUNTER_FILENAME, RUNNING_FILENAME, "domain.key", "domains.json"})
_LOG_FILE = re.compile(r"piimask-[^/\\]*\.jsonl")


def _is_temp_of(name: str, allowed: Callable[[str], bool]) -> bool:
    """`paths.write_private_bytes`'s temp name `.<name>.<16 hex>.tmp` for an allowed name."""
    m = re.fullmatch(r"\.(.+)\.[0-9a-f]{16}\.tmp", name)
    return m is not None and allowed(m.group(1))


def _own_files(folder: Path, allowed: Callable[[str], bool]) -> list[Path]:
    """Every entry of `folder` when each is a plain file the app writes; else UnsafeHomeError."""
    out: list[Path] = []
    for entry in folder.iterdir():
        name = entry.name
        own = allowed(name) or _is_temp_of(name, allowed)
        if not own or entry.is_symlink() or not entry.is_file():
            raise UnsafeHomeError()
        out.append(entry)
    return out


def _forget_plan(home: Path) -> tuple[list[Path], list[Path]]:
    """(files, folders) to delete, deepest first; UnsafeHomeError on anything foreign."""
    if home.is_symlink() or not home.is_dir():
        raise UnsafeHomeError()
    rules: dict[str, Callable[[str], bool]] = {
        _LOGS_DIRNAME: lambda n: _LOG_FILE.fullmatch(n) is not None,
        _STATE_DIRNAME: lambda n: n in _STATE_FILES,
    }
    files: list[Path] = []
    folders: list[Path] = []
    for entry in home.iterdir():
        rule = rules.get(entry.name)
        if rule is None or entry.is_symlink() or not entry.is_dir():
            raise UnsafeHomeError()
        files += _own_files(entry, rule)
        folders.append(entry)
    return files, folders + [home]


def forget(home: Path, probe: Probe = default_probe) -> bool:
    """Delete the whole app home; True when something was deleted, False when it was missing.

    Deletes only an app home that holds nothing but the app's own entries:
    top level `logs/` and `state/` folders only; in `logs/` only
    `piimask-*.jsonl` files; in `state/` only `counter.json`, `running.json`,
    `domain.key`, `domains.json`; in both, the temp names
    `paths.write_private_bytes` makes for those (`.<name>.<16 hex>.tmp`).
    Plain files and folders only, never a symlink. Anything else raises
    `UnsafeHomeError` and nothing is deleted. A filesystem root or the user's
    own home folder is refused the same way, and a live copy raises
    `AppRunningError`. Deletion is entry by entry, then each folder with
    `rmdir`, so anything that appears meanwhile stops it rather than going too.
    """
    home = Path(home)
    resolved = home.resolve()
    if resolved == Path(resolved.anchor) or resolved == Path.home().resolve():
        raise UnsafeHomeError()
    if not home.exists() and not home.is_symlink():
        return False
    files, folders = _forget_plan(home)
    if find_running(home, probe) is not None:
        raise AppRunningError()
    for f in files:
        f.unlink(missing_ok=True)
    for d in folders:
        d.rmdir()
    return True
