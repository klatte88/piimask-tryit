"""
The response headers every answer of the local app carries.

They come from the packaged `web/_headers` file (Netlify style: a path line
such as `/*`, then indented `Name: value` lines), read through
`importlib.resources.files("piimask.localapp") / "web"`, so the same file
works under `uv run` and from a wheel. Only the `/*` rule is used: the app
serves a handful of files and one rule covers them all.

Whatever the file says, the server's floor holds on EVERY response, errors
included:
- a `Content-Security-Policy` (the file's, else `DEFAULT_CSP`);
- `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`
  (the file's value if it names one, else these);
- `Cache-Control: no-store`, always (forced, the file cannot loosen it);
- never any `Access-Control-*` header (dropped if the file names one).

No message here carries a value: the file holds only header text.
"""

from __future__ import annotations

from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

HEADERS_FILENAME = "_headers"

DEFAULT_CSP = (
    "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

_FLOOR: tuple[tuple[str, str], ...] = (
    ("Content-Security-Policy", DEFAULT_CSP),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
)
_FORCED: tuple[tuple[str, str], ...] = (("Cache-Control", "no-store"),)


class HeadersFileError(ValueError):
    """The `_headers` file is malformed; the message is a code only."""


def default_web_root() -> Traversable:
    """The packaged page folder."""
    return resources.files("piimask.localapp") / "web"


def parse(text: str) -> dict[str, list[tuple[str, str]]]:
    """Path rule -> its (name, value) pairs, in file order.

    A non-indented, non-comment line starts a rule; an indented `Name: value`
    line belongs to the rule above it. Blank lines and `#` comments are skipped.
    """
    rules: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw[:1] not in (" ", "\t"):
            current = stripped
            rules.setdefault(current, [])
            continue
        if current is None:
            raise HeadersFileError("headers_line_before_rule")
        name, sep, value = stripped.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not name or any(c in name for c in " \t") or not value:
            raise HeadersFileError("headers_bad_line")
        if "\r" in value or "\n" in value:
            raise HeadersFileError("headers_bad_line")
        rules[current].append((name, value))
    return rules


def _read(web_root: Traversable | Path) -> str | None:
    entry = web_root / HEADERS_FILENAME
    try:
        if not entry.is_file():
            return None
        return entry.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def response_headers(web_root: Traversable | Path | None = None) -> list[tuple[str, str]]:
    """The headers for every response: the file's `/*` rule over the floor, `no-store` forced."""
    root = default_web_root() if web_root is None else web_root
    text = _read(root)
    from_file = parse(text).get("/*", []) if text is not None else []

    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    forced = {n.lower() for n, _v in _FORCED}
    for name, value in from_file:
        low = name.lower()
        if low.startswith("access-control-") or low in forced or low in seen:
            continue
        seen.add(low)
        out.append((name, value))
    for name, value in _FLOOR:
        if name.lower() not in seen:
            seen.add(name.lower())
            out.append((name, value))
    out.extend(_FORCED)
    return out
