"""
Where the local try-it app keeps its files, and how it writes them privately.

The app home is resolved, never created, by `home()`:

- override: `PIIMASK_TRYIT_HOME` (used by tests);
- Windows: `%LOCALAPPDATA%\\piimask-tryit`;
- macOS: `~/Library/Application Support/piimask-tryit`;
- other POSIX: `$XDG_STATE_HOME/piimask-tryit`, else `~/.local/state/piimask-tryit`.

It holds two subfolders, `logs/` and `state/`, created by `ensure_home()`.

On POSIX every folder this module creates, and the target folder itself, is
explicitly set to owner-only with `os.chmod(path, 0o700)`: a `mkdir` mode is
cut by the umask and applies only to the last folder, so it is not relied on.
Files are created with `os.open(path, flags, 0o600)` and then chmod-ed to
0o600, so the umask cannot widen or narrow them either.

On Windows `%LOCALAPPDATA%` is already per-user, and POSIX modes are ignored
there; no ACLs are changed.

Platform is read from `sys.platform` at call time, folders from `os.environ`,
paths through `pathlib` only; there are no shell calls. This module's own
messages carry no user text.
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

APP_NAME = "piimask-tryit"

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _is_windows() -> bool:
    return sys.platform == "win32"


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None


def home() -> Path:
    """Resolve the app home for this user and platform. Never creates it."""
    override = _env("PIIMASK_TRYIT_HOME")
    if override is not None:
        return Path(override)
    platform = sys.platform
    if platform == "win32":
        local = _env("LOCALAPPDATA")
        base = Path(local) if local is not None else Path.home() / "AppData" / "Local"
        return base / APP_NAME
    if platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    xdg = _env("XDG_STATE_HOME")
    base = Path(xdg) if xdg is not None else Path.home() / ".local" / "state"
    return base / APP_NAME


_resolve_home = home


def logs_dir(home: Path) -> Path:
    """The log folder under `home`. Never creates it."""
    return home / "logs"


def state_dir(home: Path) -> Path:
    """The state folder under `home`. Never creates it."""
    return home / "state"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` and any missing parents; on POSIX set each created folder and `path` to 0o700."""
    path = Path(path)
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    path.mkdir(parents=True, exist_ok=True)
    if not _is_windows():
        for folder in reversed(missing):
            os.chmod(folder, _DIR_MODE)
        os.chmod(path, _DIR_MODE)
    return path


def ensure_home(home: Path | None = None) -> Path:
    """Create the app home with `logs/` and `state/`, all private; return the home."""
    root = _resolve_home() if home is None else Path(home)
    ensure_private_dir(root)
    ensure_private_dir(logs_dir(root))
    ensure_private_dir(state_dir(root))
    return root


def write_private_bytes(path: Path, data: bytes) -> None:
    """Atomically replace `path` with `data`, via a 0o600 temp file in the same folder."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), _FILE_MODE)
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    if not _is_windows():
        os.chmod(path, _FILE_MODE)


def append_private_text(path: Path, text: str) -> None:
    """Append `text` as UTF-8 to `path`, creating it 0o600 if missing."""
    path = Path(path)
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), _FILE_MODE
    )
    try:
        view = memoryview(text.encode("utf-8"))
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)
    if not _is_windows():
        os.chmod(path, _FILE_MODE)
