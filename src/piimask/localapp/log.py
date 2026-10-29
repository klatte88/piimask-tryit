"""
The safe log: what a tester did with the masker, kept on their own computer.

The design invariant, and why it holds: `SafeLog` is fed ONLY by response
dicts (what `TryItSession.call` answered, or the server's validated echo of a
tester's flags). It never receives a request body, so the text a tester typed
or pasted, which holds the originals, cannot reach this module whatever a later
change does. From the request side exactly three small fields pass, each
checked against a closed shape: `prompt_id` (page-made: `p-<12 lowercase
hex>-<n>`, a random id per page load plus a counter, or the older `p-<n>`),
`purpose` (`"note"` only) and `ui_lang` (`"en"` or `"nl"` only). Anything else
is dropped.

Every event has its own allow-list; an unknown key is dropped, a malformed
value is never written (the event becomes `{"event": "error", "code":
"bad_response"}`). What each event keeps:

- `session_start`: app version, masker `rules-v1`, `platform.system()`, a
  random session id. Never a user name or host name.
- `mask`: `prompt_id`, `purpose`, `ui_lang`, the masked text exactly as the
  masker returned it, every span (kind, source, review, token, both offset
  pairs), warning codes with offsets, `ms`, and `original_length`, derived from
  the response as `len(masked) - sum((masked_end - masked_start) - (end - start))`.
  On a refusal: the code only.
- `reveal`: `prompt_id`, `restored` (token + offsets), `unresolved_count`
  and `unresolved_shapes`: one code per unresolved piece of the AI answer,
  from the session's closed vocabulary (`session.UNRESOLVED_SHAPES`:
  `other_code`, `truncated_code`, `lowercase_code`, `unknown_code`), never its
  text and never its offsets. A token-shaped piece of an answer can be a real
  value the AI wrote (a handle like `name_19850312`), so the page shows the
  texts live (the response) and the log keeps only their shapes. Never
  `revealed`. A line written before shape codes existed (`unresolved` with
  text) is read back as codes, by `session.unresolved_shape_of` with the
  shipped prefixes, so its text never reaches a preview or a bundle.
- `flags`: `prompt_id` and that ONE prompt's flags: misses as offsets + kind,
  over-masks (`span_index`, `confirmed_not_personal`, and `text` only when
  confirmed AND exactly as long as the span it names), `checked_all`,
  `useful`, `restore_wrong` (only a code the prompt's last reveal restored; any
  other entry is dropped). A confirmed over-mask text is the one value a log
  line may hold: the tester has ruled it an ordinary word.
- `error`: `{op, code}`. `reset`: the event only.

What the log CAN hold, honestly: the masked text keeps an email's domain in
clear (policy C09) and keeps anything the masker missed. That stays on the
tester's machine; the bundle scrubs domains and replaces flagged misses.

Domains: every kept email domain is also stored as an HMAC-SHA256 (key: 32
random bytes in `state/domain.key`, never bundled) in `state/domains.json`,
and so is every suffix of it of two or more labels: an address at
`mail.<company>.nl` teaches `<company>.nl` too, so the company's own site
(`<company>.nl`, `www.<company>.nl/contact`) is scrubbed with it. With no
public-suffix list this over-scrubs a shared suffix: from `x@firm.co.uk` the
log learns `co.uk` and scrubs every `*.co.uk` run. That is the safe side. A
single label (`nl`) is never learned. The bundle scrubs at build time, so a
domain first seen in a later prompt is still scrubbed from an earlier one,
across restarts too. The key sits beside the store, so the HMACs protect only
against a reader of the zip, not someone holding the app home (whose log keeps
the masked text, domain included, in clear anyway).

Files: one JSONL file per local day, `logs/piimask-<YYYY-MM-DD>.jsonl`, the
name taken from `now()` at each write (midnight rolls over on its own).
`prune(days)` deletes day files more than `days` days old.

Fail closed: any write failure sets `broken` and logging stops for good; no
method here ever raises into the caller, and nothing is logged anywhere else.
A bundle made while broken says the log could not be kept.

Bundle (`bundle(include)` -> zip bytes):
- `feedback.json`: ONE `build_feedback` call over the included prompts (each
  with its notes, its flags and its last reveal), so its redaction rules apply
  across them; `to_json` text.
- `prompts.json`: every prompt in order; an included one points at its index
  in `feedback.json`, every other one carries counts only (span kinds and
  counts, warning codes, ms, refusal code, note count).
- `summary.json`: counts (see `_summary`), app and masker versions, prompts
  per `ui_lang`, and whether the log was kept.
Then every domain-shaped run in every string of all three documents (keys
too, walked BEFORE serialisation, so a JSON escape never glues a letter onto a
domain) with ANY contiguous window of two or more labels whose HMAC is stored
becomes `[DOMEIN]` as a whole, after `build_feedback`'s own pass. The scrub
also tries every suffix of each window's first label (a word glued on in front:
`ookacme.nl`, `x-acme.nl`) and the run with its combining marks dropped;
over-scrubbing a run whose tail is a learned domain is the safe side. Learning
and scrubbing use one pattern and one normalisation (the run: NFKC, then the
ideographic full stop as `.`; per label: IDNA `xn--` where it encodes, else
casefolded), so the Unicode, NFD, fullwidth and `xn--` spellings of one
domain, in any case and with any IDNA dot, share an HMAC. Changing that
normalisation invalidates every stored domain HMAC. Only matched runs are
replaced; the rest of the text is left exactly as it was (feedback offsets
refer to it).

Prompts are keyed `<session>/<prompt_id>`. Two tabs, or a reload, of an older
page reuse `p-1`; so a second mask under an id already seen in this app run is
a second prompt, logged under `<prompt_id>~<k>` (k = 2, 3, ...), never a
replacement of the first. A note attaches to the latest mask under its id; a
reveal to the latest one whose codes include every code it restored (else the
latest). A `flags` event joins the ONE mask under its id that its offsets fit
(every miss inside the text and outside every span, every over-mask index a
span and every confirmed text that span's length): no mask known is
`unknown_prompt`, none fitting is `flags_mismatch`, more than one fitting is
`ambiguous_prompt`, each an error event with that code and no flags applied
anywhere; `record` returns the code so the server can tell the page. Within a
flags event that fits, an entry of a bad shape (an unknown kind, a duplicate
index, a miss overlapping another, an unconfirmed text) is dropped alone and
counted in `dropped`. A log written by an older version, with one id masked
twice, is read back the same way (the later mask becomes `~2`). Notes
(`purpose: "note"`) are never counted as prompts. No message here carries a
value.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import platform
import re
import secrets
import unicodedata
import zipfile
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from datetime import date, datetime
from pathlib import Path
from typing import Any

from piimask.localapp import paths
from piimask.tryit.feedback import MASKER, FeedbackRefused, build_feedback, to_json
from piimask.tryit.session import UNRESOLVED_SHAPES, unresolved_shape_of

FORMAT = "piimask-tryit-bundle"
VERSION = 1

_FILE = re.compile(r"piimask-(\d{4}-\d{2}-\d{2})\.jsonl")
# The page's id: a random 12-hex id per page load and a counter; or the older `p-<n>`.
_PROMPT_ID = re.compile(r"p-[0-9a-f]{12}-[1-9]\d{0,5}|p-\d{1,9}")
_REPEAT = "~"  # `<prompt_id>~<k>`: the k-th mask under one id in one app run
_SESSION = re.compile(r"[0-9a-f]{16}")
_CODE = re.compile(r"[a-z_]{1,40}")
_KIND = re.compile(r"[A-Z_]{1,32}")
_SOURCE = re.compile(r"[A-Za-z0-9_\-]{1,40}")
_TOKEN = re.compile(r"[A-Z]+_\d{6,}")
# ONE domain pattern, used both to learn a domain and to scrub one: a run of
# two or more dot-joined labels of Unicode word characters or hyphens. It is
# wider than `piimask.core.patterns.EMAIL`'s ASCII domain part on purpose: the
# masker only ever keeps an ASCII (or `xn--`) domain, but the same domain can be
# written in its Unicode spelling elsewhere, and the scrub must see that too.
#
# A label character is a word character, a hyphen or a character NFKC folds to
# one (U+FE63, U+FF0D), or a combining mark (any category M*): Python's `\w`
# leaves marks out, so without them an NFD spelling (`e` + U+0301) would split
# a run in two. A label separator is the full stop, U+3002, or any character
# NFKC folds to either (U+2024, U+FE52, U+FF0E, U+FF61). All three sets are
# read from `unicodedata` at import, so they follow the running Python's table.
# Every matched run is canonicalised (`_canon`) before it is split.
_IDEO_DOT = chr(0x3002)


def _char_sets() -> tuple[str, str, str]:
    """(combining-mark class ranges, dot look-alikes, hyphen look-alikes), from `unicodedata`."""
    marks: list[tuple[int, int]] = []
    dots: list[str] = []
    hyphens: list[str] = []
    for cp in range(0x110000):
        c = chr(cp)
        if unicodedata.category(c).startswith("M"):
            if marks and marks[-1][1] == cp - 1:
                marks[-1] = (marks[-1][0], cp)
            else:
                marks.append((cp, cp))
        elif c not in ".-":
            k = unicodedata.normalize("NFKC", c)
            if k in (".", _IDEO_DOT):
                dots.append(c)
            elif k == "-":
                hyphens.append(c)
    ranges = "".join(f"\\U{a:08x}" if a == b else f"\\U{a:08x}-\\U{b:08x}" for a, b in marks)
    return ranges, "".join(dots), "".join(hyphens)


_MARK_RANGES, _DOT_LIKE, _HYPHEN_LIKE = _char_sets()
_LABEL_CHAR = r"[\w\-" + re.escape(_HYPHEN_LIKE) + _MARK_RANGES + "]"
_DOT = "[." + re.escape(_DOT_LIKE) + "]"
_DOMAIN_RUN = _LABEL_CHAR + "+(?:" + _DOT + _LABEL_CHAR + "+)+"
_DOMAIN_SHAPED = re.compile(_DOMAIN_RUN)
_TOKEN_AT_DOMAIN = re.compile(r"[A-Z]+_\d{6,}@(" + _DOMAIN_RUN + ")")
_MAX_LABELS = 64
_MAX_LABEL_LEN = 63  # DNS's own cap on one label: the longest glued-prefix suffix tried
_DOMAIN_MARK = "[DOMEIN]"
_OPS = ("mask", "reveal", "flags", "reset", "feedback", "bundle")
_LANGS = ("en", "nl")
# The page may answer "was it useful" in either language; the file uses Dutch.
_USEFUL = {"ja": "ja", "deels": "deels", "nee": "nee", "yes": "ja", "partly": "deels", "no": "nee"}
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class _Bad(Exception):
    """A response that does not have the shape the log accepts (no text)."""


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _need(cond: bool) -> None:
    if not cond:
        raise _Bad


def _default_now() -> datetime:
    return datetime.now().astimezone()


# THE normalisation, in one place, for learning and scrubbing alike: NFKC (so
# NFD, fullwidth and other compatibility spellings fold to one form), then the
# ideographic full stop to `.`. Changing it changes every stored domain HMAC:
# a `state/domains.json` written under another normalisation no longer matches.
_DOT_MAP = str.maketrans({_IDEO_DOT: "."})


def _canon(found: str) -> str:
    """A matched run in its one spelling before it is split: NFKC, every IDNA dot a full stop."""
    return unicodedata.normalize("NFKC", found).translate(_DOT_MAP)


def _norm_label(label: str) -> str:
    """One canonical label in one spelling: IDNA (`xn--`) where the codec encodes it, else casefolded.

    `bücher`, `BÜCHER` and `xn--bcher-kva` all give `xn--bcher-kva`.
    """
    try:
        return label.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return label.casefold()


def _raw_labels(found: str) -> list[str]:
    return [x for x in _canon(found).split(".") if x]


def _labels(found: str) -> list[str]:
    return [_norm_label(x) for x in _raw_labels(found)]


def _norm_domain(found: str) -> str:
    """A whole domain, normalised label by label (the form that is HMAC'd)."""
    return ".".join(_labels(found))


def _windows(labels: list[str]) -> Iterator[str]:
    """Every contiguous window of two or more labels, any start, any end.

    So a learned `acme.nl` is found inside `mail.acme.nl`, `acme.nl.example`
    and `x.acme.nl.y` alike.
    """
    for i in range(len(labels) - 1):
        for j in range(i + 2, min(len(labels), i + _MAX_LABELS) + 1):
            yield ".".join(labels[i:j])


def _scrub_windows(found: str) -> Iterator[str]:
    """Every candidate the scrub tests for one run (the scrub side only; learning is `_norm_domain`).

    - The run's own windows.
    - The same with every combining mark dropped: a stray mark glued onto a
      learned label's edge (`acme.nl` + U+0301) makes its last label another.
    - For both, every suffix of a window's first label (any character
      position, so every `-` and `_` boundary too, up to 63 characters), for
      windows starting at any label: a word glued on in front (`ookacme.nl`,
      `x-acme.nl`, `mail_acme.nl`, `www.ookacme.nl`) would otherwise hide it.
    Over-scrubbing is the safe side: a run whose tail is a learned domain, or
    that differs from one only by accents, goes as a whole, and a domain whose
    letters differ never does.
    """
    raw = _raw_labels(found)
    bare = _raw_labels("".join(
        c for c in unicodedata.normalize("NFD", found) if not unicodedata.category(c).startswith("M")
    ))
    for variant in (raw, bare) if bare != raw else (raw,):
        labels = [_norm_label(x) for x in variant]
        yield from _windows(labels)
        for i in range(len(labels) - 1):
            start = variant[i]
            for k in range(max(1, len(start) - _MAX_LABEL_LEN), len(start)):
                head = _norm_label(start[k:])
                for j in range(i + 2, min(len(labels), i + _MAX_LABELS) + 1):
                    yield ".".join([head, *labels[i + 1:j]])


class SafeLog:
    """The tester's local log; see the module docstring for what it may hold."""

    def __init__(
        self,
        home: Path,
        now: Callable[[], datetime] | None = None,
        app_version: str = "0",
    ) -> None:
        self.home = Path(home)
        self._now = now or _default_now
        self.app_version = app_version if isinstance(app_version, str) else "0"
        self.session = secrets.token_hex(8)
        self.broken = False
        # This app run's prompt masks, by internal id (`p-1`, `p-1~2`, ...), and
        # each page id's internal ids in order (a refused mask holds None).
        self._masks: dict[str, dict[str, Any]] = {}
        self._ids: dict[str, list[str]] = {}
        self._hmacs: set[str] = set()
        self._key: bytes | None = None
        try:
            paths.ensure_home(self.home)
            self._load_domains()
        except Exception:  # noqa: BLE001 - fail closed: the log stops, the app masks on
            self.broken = True

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def _logs(self) -> Path:
        return paths.logs_dir(self.home)

    def _write(self, event: dict[str, Any]) -> None:
        if self.broken:
            return
        try:
            now = self._now()
            line = {"session": self.session, "ts": now.isoformat(timespec="seconds"), **event}
            text = json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n"
            path = self._logs() / f"piimask-{now.date().isoformat()}.jsonl"
            paths.append_private_text(path, text)
        except Exception:  # noqa: BLE001 - fail closed: never raise into a request
            self.broken = True

    def session_start(self) -> None:
        """Write the session's first event: versions, platform, session id."""
        self._write({
            "event": "session_start",
            "app_version": self.app_version,
            "masker": MASKER,
            "platform": platform.system(),
        })

    def record(
        self,
        op: str,
        response: dict[str, Any],
        prompt_id: str | None = None,
        purpose: str | None = None,
        ui_lang: str | None = None,
        *,
        ms: float | None = None,
    ) -> str | None:
        """Log one response. Fed only by response dicts, never a request body; never raises.

        Returns the code when the event became an error event (a flags event
        that joined no prompt, a malformed response), else None. Logging
        stopped (`broken`) returns None: nothing was judged.
        """
        if self.broken:
            return None
        try:
            op_ok = op if isinstance(op, str) and op in _OPS else "other"
            pid = prompt_id if isinstance(prompt_id, str) and _PROMPT_ID.fullmatch(prompt_id) else None
            purp = "note" if purpose == "note" else None
            lang = ui_lang if isinstance(ui_lang, str) and ui_lang in _LANGS else None
            try:
                event = self._event(op_ok, response, pid, purp, lang, ms)
            except _Bad:
                event = {"event": "error", "op": op_ok, "code": "bad_response"}
            if event is not None:
                self._write(event)
                if event.get("event") == "error":
                    code = event.get("code")
                    return code if isinstance(code, str) else None
        except Exception:  # noqa: BLE001 - fail closed
            self.broken = True
        return None

    def _event(
        self,
        op: str,
        response: Any,
        pid: str | None,
        purpose: str | None,
        lang: str | None,
        ms: float | None,
    ) -> dict[str, Any] | None:
        _need(isinstance(response, dict))
        if response.get("ok") is False:
            code = response.get("code")
            _need(isinstance(code, str) and _CODE.fullmatch(code) is not None)
            if code == "internal" or op != "mask":
                return {"event": "error", "op": op, "code": code}
            if purpose is None:
                pid = self._new_id(pid, None)
            else:
                pid = self._latest(pid)
            ev: dict[str, Any] = {"event": "mask", "prompt_id": pid, "code": code}
            if purpose:
                ev["purpose"] = purpose
            if lang:
                ev["ui_lang"] = lang
            return ev
        _need(response.get("ok") is True or op == "flags")
        if op == "mask":
            return self._mask_event(response, pid, purpose, lang, ms)
        if op == "reveal":
            return self._reveal_event(response, pid)
        if op == "flags":
            return self._flags_event(response, pid)
        if op == "reset":
            return {"event": "reset"}
        return None  # feedback / bundle answers are not logged

    def _mask_event(
        self, r: dict[str, Any], pid: str | None, purpose: str | None, lang: str | None, ms: float | None
    ) -> dict[str, Any]:
        masked = r.get("masked")
        raw_spans, raw_warn = r.get("spans"), r.get("warnings", [])
        _need(isinstance(masked, str) and isinstance(raw_spans, list) and isinstance(raw_warn, list))
        spans: list[dict[str, Any]] = []
        delta = 0
        for sp in raw_spans:
            _need(isinstance(sp, dict))
            kind, source, token, review = sp.get("kind"), sp.get("source"), sp.get("token"), sp.get("review")
            s, e, ms_, me = sp.get("start"), sp.get("end"), sp.get("masked_start"), sp.get("masked_end")
            _need(isinstance(kind, str) and _KIND.fullmatch(kind) is not None)
            _need(isinstance(source, str) and _SOURCE.fullmatch(source) is not None)
            _need(isinstance(token, str) and _TOKEN.fullmatch(token) is not None)
            _need(isinstance(review, bool) and all(_int(x) for x in (s, e, ms_, me)))
            _need(0 <= s < e and 0 <= ms_ < me <= len(masked))
            spans.append({
                "kind": kind, "source": source, "token": token, "review": review,
                "start": s, "end": e, "masked_start": ms_, "masked_end": me,
            })
            delta += (me - ms_) - (e - s)
        warnings: list[dict[str, Any]] = []
        for w in raw_warn:
            _need(isinstance(w, dict))
            code, s, e = w.get("code"), w.get("start"), w.get("end")
            _need(isinstance(code, str) and _CODE.fullmatch(code) is not None and _int(s) and _int(e))
            warnings.append({"code": code, "start": s, "end": e})
        original_length = len(masked) - delta
        _need(original_length >= 0)
        self._remember_domains(masked, spans)
        if purpose is None:
            pid = self._new_id(pid, {"spans": spans, "original_length": original_length, "restored": set()})
        else:
            pid = self._latest(pid)
        ev: dict[str, Any] = {
            "event": "mask",
            "prompt_id": pid,
            "masked": masked,
            "spans": spans,
            "warnings": warnings,
            "original_length": original_length,
        }
        if purpose:
            ev["purpose"] = purpose
        if lang:
            ev["ui_lang"] = lang
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and ms >= 0:
            ev["ms"] = round(float(ms), 1)
        return ev

    def _new_id(self, pid: str | None, known: dict[str, Any] | None) -> str | None:
        """The internal id of a new mask under page id `pid`: `pid` first, then `pid~2`, ..."""
        if pid is None:
            return None
        seen = self._ids.setdefault(pid, [])
        internal = pid if not seen else f"{pid}{_REPEAT}{len(seen) + 1}"
        seen.append(internal)
        if known is not None:
            self._masks[internal] = known
        return internal

    def _latest(self, pid: str | None) -> str | None:
        """The latest mask under `pid` (a note joins it); `pid` itself when none is known."""
        seen = self._ids.get(pid) if pid is not None else None
        return seen[-1] if seen else pid

    def _reveal_event(self, r: dict[str, Any], pid: str | None) -> dict[str, Any]:
        restored, unresolved = r.get("restored"), r.get("unresolved")
        _need(isinstance(restored, list) and isinstance(unresolved, list))
        rs: list[dict[str, Any]] = []
        for x in restored:
            _need(isinstance(x, dict))
            t, s, e = x.get("token"), x.get("start"), x.get("end")
            _need(isinstance(t, str) and _TOKEN.fullmatch(t) is not None and _int(s) and _int(e))
            rs.append({"token": t, "start": s, "end": e})
        shapes: list[str] = []
        for x in unresolved:
            _need(isinstance(x, dict))
            shape = x.get("shape")
            # The text is never read here: only its shape code, from the closed vocabulary.
            _need(isinstance(shape, str) and shape in UNRESOLVED_SHAPES)
            shapes.append(shape)
        pid = self._reveal_target(pid, {x["token"] for x in rs})
        if pid is not None and pid in self._masks:
            self._masks[pid]["restored"] = {x["token"] for x in rs}
        return {
            "event": "reveal", "prompt_id": pid, "restored": rs,
            "unresolved_count": len(shapes), "unresolved_shapes": shapes,
        }

    def _reveal_target(self, pid: str | None, restored: set[str]) -> str | None:
        """The latest mask under `pid` whose codes hold every restored code, else the latest."""
        seen = [i for i in self._ids.get(pid, []) if i in self._masks] if pid is not None else []
        if restored:
            for internal in reversed(seen):
                if restored <= {sp["token"] for sp in self._masks[internal]["spans"]}:
                    return internal
        return seen[-1] if seen else self._latest(pid)

    def _flags_event(self, r: dict[str, Any], pid: str | None) -> dict[str, Any]:
        """One prompt's flags, joined to the ONE mask under its id they fit; bad entries dropped."""
        candidates = [i for i in self._ids.get(pid, []) if i in self._masks] if pid is not None else []
        if not candidates:
            return {"event": "error", "op": "flags", "code": "unknown_prompt"}
        fitting = [i for i in candidates if self._fits(r, self._masks[i])]
        if not fitting:
            return {"event": "error", "op": "flags", "code": "flags_mismatch"}
        if len(fitting) > 1:
            return {"event": "error", "op": "flags", "code": "ambiguous_prompt"}
        pid = fitting[0]
        known = self._masks[pid]
        spans, n = known["spans"], known["original_length"]
        dropped = 0
        misses: list[dict[str, Any]] = []
        for m in r.get("misses", []) if isinstance(r.get("misses", []), list) else []:
            s, e, kind = (m.get("start"), m.get("end"), m.get("kind")) if isinstance(m, dict) else (None,) * 3
            kind = kind.upper() if isinstance(kind, str) else None
            ok = (
                _int(s) and _int(e) and 0 <= s < e <= n
                and kind is not None and _KIND.fullmatch(kind) is not None
                and not any(sp["start"] < e and s < sp["end"] for sp in spans)
                and not any(x["start"] < e and s < x["end"] for x in misses)
            )
            if ok:
                misses.append({"start": s, "end": e, "kind": kind})
            else:
                dropped += 1
        over: list[dict[str, Any]] = []
        seen: set[int] = set()
        for om in r.get("over_masks", []) if isinstance(r.get("over_masks", []), list) else []:
            idx = om.get("span_index") if isinstance(om, dict) else None
            confirmed = om.get("confirmed_not_personal") if isinstance(om, dict) else None
            if not (_int(idx) and 0 <= idx < len(spans) and isinstance(confirmed, bool)) or idx in seen:
                dropped += 1
                continue
            entry: dict[str, Any] = {"span_index": idx, "confirmed_not_personal": confirmed}
            if confirmed:
                text = om.get("text")
                sp = spans[idx]
                # The one value a log line may hold, and only at the span's exact length.
                if not (isinstance(text, str) and len(text) == sp["end"] - sp["start"]):
                    dropped += 1
                    continue
                entry["text"] = text
            seen.add(idx)
            over.append(entry)
        wrong: list[dict[str, str]] = []
        restored = known.get("restored", set())
        for x in r.get("restore_wrong", []) if isinstance(r.get("restore_wrong", []), list) else []:
            t = x.get("token") if isinstance(x, dict) else None
            # Only a code this prompt's last reveal restored: never a piece of the answer.
            if isinstance(t, str) and _TOKEN.fullmatch(t) is not None and t in restored:
                wrong.append({"token": t})
            else:
                dropped += 1
        useful = r.get("useful")
        ev: dict[str, Any] = {
            "event": "flags",
            "prompt_id": pid,
            "misses": sorted(misses, key=lambda m: (m["start"], m["end"])),
            "over_masks": over,
            "restore_wrong": wrong,
            "checked_all": r.get("checked_all") is True,
            "useful": _USEFUL.get(useful) if isinstance(useful, str) else None,
        }
        if dropped:
            ev["dropped"] = dropped
        return ev

    @staticmethod
    def _fits(r: dict[str, Any], known: dict[str, Any]) -> bool:
        """Whether a flags body's offsets fit one mask: misses inside the text and outside
        every span, over-mask indexes a span, confirmed texts that span's length.

        Entries of a bad shape are not judged here (they are dropped alone later).
        """
        spans, n = known["spans"], known["original_length"]
        misses = r.get("misses", [])
        for m in misses if isinstance(misses, list) else []:
            s, e = (m.get("start"), m.get("end")) if isinstance(m, dict) else (None, None)
            if not (_int(s) and _int(e)):
                continue
            if not (0 <= s < e <= n) or any(sp["start"] < e and s < sp["end"] for sp in spans):
                return False
        over = r.get("over_masks", [])
        for om in over if isinstance(over, list) else []:
            idx = om.get("span_index") if isinstance(om, dict) else None
            if not _int(idx):
                continue
            if not 0 <= idx < len(spans):
                return False
            text = om.get("text") if isinstance(om, dict) else None
            if om.get("confirmed_not_personal") is True and isinstance(text, str):
                sp = spans[idx]
                if len(text) != sp["end"] - sp["start"]:
                    return False
        return True

    # ------------------------------------------------------------------
    # Domains (HMAC under a local key, never bundled)
    # ------------------------------------------------------------------

    def _state(self) -> Path:
        return paths.state_dir(self.home)

    def _load_domains(self) -> None:
        key_path = self._state() / "domain.key"
        if key_path.exists():
            self._key = key_path.read_bytes()
        else:
            self._key = secrets.token_bytes(32)
            paths.write_private_bytes(key_path, self._key)
        store = self._state() / "domains.json"
        if store.exists():
            try:
                data = json.loads(store.read_text(encoding="utf-8"))
                hm = data.get("hmacs", []) if isinstance(data, dict) else []
                self._hmacs.update(h for h in hm if isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h))
            except ValueError:
                pass  # a damaged store is rebuilt from what this run sees

    def _mac(self, domain: str) -> str:
        assert self._key is not None
        return hmac.new(self._key, domain.encode("utf-8"), hashlib.sha256).hexdigest()

    def _remember_domains(self, masked: str, spans: list[dict[str, Any]]) -> None:
        found: set[str] = set()
        for sp in spans:
            if sp["kind"] == "EMAIL":
                at = sp["masked_start"] + len(sp["token"])
                if masked[at:at + 1] == "@" and sp["masked_end"] > at + 1:
                    found.add(masked[at + 1:sp["masked_end"]])
        found.update(m.group(1) for m in _TOKEN_AT_DOMAIN.finditer(masked))
        normed: set[str] = set()
        for d in found:
            labels = _labels(d)
            # Every suffix of two or more labels: `mail.acme.nl` teaches `acme.nl` too.
            normed.update(".".join(labels[i:]) for i in range(len(labels) - 1))
        new = {self._mac(d) for d in normed} - self._hmacs
        if not new:
            return
        self._hmacs |= new
        try:
            body = json.dumps({"hmacs": sorted(self._hmacs)}, sort_keys=True).encode("utf-8")
            paths.write_private_bytes(self._state() / "domains.json", body)
        except Exception:  # noqa: BLE001 - a domain that cannot be stored stops the log
            self.broken = True

    def _scrub(self, text: str) -> str:
        if not self._hmacs or self._key is None:
            return text

        def repl(m: re.Match[str]) -> str:
            # Any window hit scrubs the whole run, so no label of it survives.
            if any(self._mac(c) in self._hmacs for c in _scrub_windows(m.group(0))):
                return _DOMAIN_MARK
            return m.group(0)

        return _DOMAIN_SHAPED.sub(repl, text)

    def _scrub_doc(self, obj: Any) -> Any:
        """Scrub every string in a JSON document, keys too, BEFORE it is serialised.

        Scrubbing the serialised text instead lets an escape glue its letter
        onto a domain (`\\nacme.nl` reads as the run `nacme.nl`), so the walk
        is the scrub; the serialiser only ever sees scrubbed strings.
        """
        if isinstance(obj, str):
            return self._scrub(obj)
        if isinstance(obj, dict):
            return {self._scrub(k) if isinstance(k, str) else k: self._scrub_doc(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._scrub_doc(v) for v in obj]
        return obj

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def prune(self, days: int = 30) -> int:
        """Delete day files more than `days` days old; return how many. Never raises."""
        removed = 0
        try:
            today = self._now().date()
            for f in self._logs().iterdir():
                m = _FILE.fullmatch(f.name)
                if m is None:
                    continue
                try:
                    day = date.fromisoformat(m.group(1))
                except ValueError:
                    continue
                if (today - day).days > days:
                    f.unlink()
                    removed += 1
        except Exception:  # noqa: BLE001, S110 - retention never stops the app
            pass
        return removed

    # ------------------------------------------------------------------
    # Reading back: prompts joined from their events
    # ------------------------------------------------------------------

    def _events(self) -> Iterable[dict[str, Any]]:
        try:
            files = sorted(f for f in self._logs().iterdir() if _FILE.fullmatch(f.name))
        except Exception:  # noqa: BLE001 - nothing readable, nothing to join
            return []
        out: list[dict[str, Any]] = []
        for f in files:
            try:
                lines = f.read_text(encoding="utf-8").splitlines()
            except Exception:  # noqa: BLE001, S112 - an unreadable day file is skipped
                continue
            for line in lines:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict) and isinstance(ev.get("session"), str):
                    out.append(ev)
        return out

    def _prompts(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Prompts in order (key, mask, notes, flags, reveal) and the session-wide tallies."""
        prompts: dict[str, dict[str, Any]] = {}
        latest: dict[str, str] = {}  # a key's latest prompt (an older log reused an id)
        orphan_notes = 0
        tallies: dict[str, Any] = {"errors": Counter(), "sessions": set(), "resets": 0}
        for ev in self._events():
            sess = ev["session"]
            kind = ev.get("event")
            tallies["sessions"].add(sess)
            if kind == "error":
                tallies["errors"][str(ev.get("code"))] += 1
                continue
            if kind == "reset":
                tallies["resets"] += 1
                continue
            pid = ev.get("prompt_id")
            if not isinstance(pid, str):
                if kind == "mask" and ev.get("purpose") == "note":
                    orphan_notes += 1
                continue
            key = latest.get(f"{sess}/{pid}", f"{sess}/{pid}")
            if kind == "mask" and ev.get("purpose") == "note":
                if "masked" not in ev:
                    continue  # a refused note holds nothing to attach
                if key in prompts:
                    prompts[key]["notes"].append(ev["masked"])
                else:
                    orphan_notes += 1
            elif kind == "mask":
                # An id masked again (a log from before ids were made unique): a second prompt.
                base = f"{sess}/{pid}"
                key, k = base, 1
                while key in prompts:
                    k += 1
                    key = f"{base}{_REPEAT}{k}"
                latest[base] = key
                prompts[key] = {"id": key, "mask": ev, "notes": [], "flags": None, "reveal": None}
            elif kind == "flags" and key in prompts:
                prompts[key]["flags"] = ev
            elif kind == "reveal" and key in prompts:
                prompts[key]["reveal"] = ev
        tallies["orphan_notes"] = orphan_notes
        return list(prompts.values()), tallies

    @staticmethod
    def _flagged(p: dict[str, Any]) -> bool:
        f = p["flags"]
        return bool(f and (f["misses"] or f["over_masks"] or f["restore_wrong"]))

    @classmethod
    def _reviewed(cls, p: dict[str, Any]) -> bool:
        f = p["flags"]
        return "code" not in p["mask"] and (cls._flagged(p) or bool(f and f["checked_all"]))

    @staticmethod
    def _entry(p: dict[str, Any]) -> dict[str, Any]:
        """The `build_feedback` prompt entry for one logged prompt."""
        m, f, rv = p["mask"], p["flags"] or {}, p["reveal"]
        answer = None
        if rv is not None or f.get("restore_wrong") or f.get("useful"):
            # No unresolved text goes in: the shapes are set on the built document (`_shapes`).
            answer = {
                "unresolved": [],
                "restore_wrong": f.get("restore_wrong", []),
                "useful": f.get("useful"),
            }
        return {
            "mask_result": {"ok": True, "masked": m["masked"], "spans": m["spans"], "warnings": m["warnings"]},
            "original_length": m["original_length"],
            "misses": f.get("misses", []),
            "over_masks": f.get("over_masks", []),
            "answer": answer,
            "checked_all": bool(f.get("checked_all")),
            "masked_note": "\n\n".join(p["notes"]),
        }

    @staticmethod
    def _shapes(p: dict[str, Any]) -> list[str]:
        """The prompt's last reveal's unresolved shape codes (an old line's texts become codes)."""
        rv = p["reveal"]
        if rv is None:
            return []
        shapes = rv.get("unresolved_shapes")
        if isinstance(shapes, list):
            return [x if x in UNRESOLVED_SHAPES else "other_code" for x in shapes]
        old = rv.get("unresolved")
        out: list[str] = []
        for u in old if isinstance(old, list) else []:
            t = u.get("text") if isinstance(u, dict) else None
            out.append(unresolved_shape_of(t) if isinstance(t, str) else "other_code")
        return out

    def preview(self) -> list[dict[str, Any]]:
        """Per prompt, for the page: the text as it would go in, the flags, and the default tick."""
        out: list[dict[str, Any]] = []
        prompts, _ = self._prompts()
        for p in prompts:
            m = p["mask"]
            item: dict[str, Any] = {
                "id": p["id"],
                "ui_lang": m.get("ui_lang"),
                "flags": p["flags"],
                "reviewed": self._reviewed(p),
                "include": self._reviewed(p),
                "can_include": False,
            }
            if "code" in m:
                item["code"] = m["code"]
            else:
                try:
                    doc = build_feedback([self._entry(p)])
                    fp = doc["prompts"][0]
                    item["text"] = self._scrub(fp["masked_with_misses"])
                    item["note"] = self._scrub(fp["masked_note"])
                    item["can_include"] = True
                except FeedbackRefused as refused:
                    item["code"] = refused.code
                    item["include"] = False
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # The bundle
    # ------------------------------------------------------------------

    def bundle(self, include: set[str] | None = None) -> bytes:
        """The feedback zip. `include`: prompt ids (`<session>/<prompt_id>`) in full;
        `None` means the reviewed ones (the preview's default ticks). Never raises."""
        prompts, tallies = self._prompts()
        wanted = {p["id"] for p in prompts if self._reviewed(p)} if include is None else set(include)

        full: list[dict[str, Any]] = []
        demoted: dict[str, str] = {}
        for p in prompts:
            if p["id"] not in wanted or "code" in p["mask"]:
                continue
            try:
                build_feedback([self._entry(p)])  # a prompt that cannot export alone goes as counts
                full.append(p)
            except FeedbackRefused as refused:
                demoted[p["id"]] = refused.code

        feedback_refused = None
        try:
            doc = build_feedback([self._entry(p) for p in full])
        except FeedbackRefused as refused:
            feedback_refused = refused.code
            for p in full:
                demoted[p["id"]] = refused.code
            full = []
            doc = build_feedback([])
        index = {p["id"]: i for i, p in enumerate(full)}
        for p in full:
            answer = doc["prompts"][index[p["id"]]].get("answer")
            if isinstance(answer, dict):
                answer["unresolved"] = [{"shape": c} for c in self._shapes(p)]

        listing: list[dict[str, Any]] = []
        for p in prompts:
            m = p["mask"]
            row: dict[str, Any] = {"id": p["id"], "ui_lang": m.get("ui_lang")}
            if p["id"] in index:
                row["included"] = True
                row["feedback_index"] = index[p["id"]]
            else:
                row["included"] = False
                if "code" in m:
                    row["refused"] = m["code"]
                else:
                    row["span_kinds"] = dict(sorted(Counter(sp["kind"] for sp in m["spans"]).items()))
                    row["spans"] = len(m["spans"])
                    row["warnings"] = sorted({w["code"] for w in m["warnings"]})
                    row["notes"] = len(p["notes"])
                    if p["id"] in demoted:
                        row["not_exported"] = demoted[p["id"]]
                if "ms" in m:
                    row["ms"] = m["ms"]
            listing.append(row)

        summary = self._summary(prompts, tallies, len(full), feedback_refused)
        # The scrub walks each document's strings before serialisation (see `_scrub_doc`).
        files = {
            "feedback.json": to_json(self._scrub_doc(doc)),
            "prompts.json": json.dumps(self._scrub_doc(listing), ensure_ascii=False, sort_keys=True, indent=2),
            "summary.json": json.dumps(self._scrub_doc(summary), ensure_ascii=False, sort_keys=True, indent=2),
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, text in files.items():
                info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, text.encode("utf-8"))
        return buf.getvalue()

    def _summary(
        self, prompts: list[dict[str, Any]], tallies: dict[str, Any], included: int, refused: str | None
    ) -> dict[str, Any]:
        flags: Counter[str] = Counter()
        miss_kinds: Counter[str] = Counter()
        useful: Counter[str] = Counter()
        refusals: Counter[str] = Counter()
        langs: Counter[str] = Counter()
        shapes: Counter[str] = Counter()
        notes = tallies["orphan_notes"]
        for p in prompts:
            m, f = p["mask"], p["flags"]
            langs[m.get("ui_lang") or "unknown"] += 1
            notes += len(p["notes"])
            if "code" in m:
                refusals[m["code"]] += 1
            shapes.update(self._shapes(p))
            if f:
                flags["miss"] += len(f["misses"])
                flags["over_mask"] += len(f["over_masks"])
                flags["restore_wrong"] += len(f["restore_wrong"])
                flags["checked_all"] += int(bool(f["checked_all"]))
                miss_kinds.update(x["kind"] for x in f["misses"])
                if f.get("useful"):
                    useful[f["useful"]] += 1
        return {
            "format": FORMAT,
            "version": VERSION,
            "app_version": self.app_version,
            "masker": MASKER,
            "log_kept": not self.broken,
            "log_note": None if not self.broken else "the log could not be kept; this bundle may be incomplete",
            "sessions": len(tallies["sessions"]),
            "prompts": len(prompts),
            "reviewed_prompts": sum(1 for p in prompts if self._reviewed(p)),
            "included_prompts": included,
            "prompts_by_ui_lang": dict(sorted(langs.items())),
            "notes": notes,
            "flags_by_kind": dict(sorted(flags.items())),
            "miss_kinds": dict(sorted(miss_kinds.items())),
            "refusals_by_code": dict(sorted(refusals.items())),
            "unresolved": sum(shapes.values()),
            "unresolved_by_shape": dict(sorted(shapes.items())),
            "errors_by_code": dict(sorted(tallies["errors"].items())),
            "resets": tallies["resets"],
            "useful": dict(sorted(useful.items())),
            "feedback_refused": refused,
        }
