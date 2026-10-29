"""
The try-it session: one browser tab's masker, over a key held only in memory.

`TryItSession` wraps the same three parts the eval harness's `RulesSession`
wires together (shipped settings over a temporary home, the pseudonymiser on
an in-memory store, the rules detector, the span masker) and answers in plain
dicts the page can read. It adds nothing to the masking itself: the masked
text is exactly what `SpanMasker.mask` returns, and the revealed text exactly
what `SpanMasker.reveal` returns. What it adds is what a page needs to SHOW:
offsets into both the original and the masked text for every span, which
tokens an answer restored and which token-shaped text in it stayed unresolved
(each unresolved piece with a `shape` code from `UNRESOLVED_SHAPES`, so a log
can keep the shape and never the text).

Why its own `_MemoryStore`: product code never imports the evaluation
harness, so this is a copy of the harness's in-memory store with the same
members; a contract-drift test drives both with one sequence.

Two design questions stay open:
- a prompt already holding token-shaped text is masked exactly as the masker
  masks it today, with a `token_like_in_input` warning for the page to explain;
- an address whose local part is already a token makes `SpanMasker.mask`
  refuse; that one refusal, matched exactly (message AND the span's local part
  being token-shaped), becomes `already_masked`. The same message also fires
  for a value the pseudonymiser would strip (D31), and every other `masker:`
  error is a real bug, so those re-raise.

`TryItSession(initial_counter=n)` starts the key's counter at n instead of
`settings.counter_start` (a value below that floor is raised to it), so an app
that keeps the counter between runs never mints a code an earlier run handed
out; `None` (the default) is exactly the old start. It enters the same way a
reset does, as the counter of the first in-memory key. The `counter` property
reads the current counter after any call, refusals included (a D42 refusal
comes after the spans before it were minted), so the app can store it.

`reset` drops every mapping but keeps the counter, so a code is never handed
out twice in one tab: a fresh key would mint `PERSON_001001` again, and an
answer from before the reset would then reveal that code as someone else.
It also builds a new span masker, so the review queue starts empty with the
key it describes.

`call` is the only door the page's worker uses. It takes one JSON request and
returns one JSON response, and it turns EVERY exception into
`{"ok": false, "code": "internal", "op": ...}`, never the exception text, so
no traceback holding a user value can reach the page or the console. Inside,
the Python API still fails loud (`mask` and `reveal` raise).

Never a file, never a keychain: `_MemoryStore.save` keeps the key in memory and
nothing here calls `save_mapping`; the temporary home only exists because the
pseudonymiser creates its `secure/` directory (a directory, never a file).

No error message here carries a value: kinds, offsets and codes only.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
import weakref
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

# Longest prompt the page accepts, in characters (code points).
MAX_INPUT_CHARS = 20_000

# The masker's own refusal for a span it cannot mint byte-exact (masker.py).
_UNREVEALABLE_EMAIL = re.compile(
    r"^masker: span cannot be revealed byte-exact: EMAIL \[(\d+):(\d+)\]$"
)
# An email local part that is already a token (the D42 condition).
_TOKEN_LOCAL = re.compile(r"[A-Z]+_\d{6,}")
# Token-shaped text in an AI answer, as an AI may bend it (lowercased,
# truncated to five digits): anything that could have been a token.
_ANSWER_TOKEN_LIKE = re.compile(r"[A-Za-z]+_\d{5,}")
_ANSWER_PARTS = re.compile(r"([A-Za-z]+)_(\d+)")

# The closed vocabulary of an unresolved piece's shape, judged against this
# session's real token format (a prefix from `settings.prefixes`, or the
# pseudonymiser's own fallback `ANON`, then `_`, then at least six digits).
# It is what a log or a bundle may keep about the piece instead of its text,
# because a token-shaped piece of an answer can be a real value the AI wrote
# (a handle like `name_19850312`), not a code it bent. In order of the test:
# - `other_code`: the letters are no code prefix at all (any case);
# - `truncated_code`: a code prefix, fewer than six digits;
# - `lowercase_code`: a code prefix with at least six digits, but its letters
#   are not all uppercase (the AI changed the case);
# - `unknown_code`: exactly the real format, yet no code this key holds (from
#   before a reset, another run, or invented by the AI).
UNRESOLVED_SHAPES = ("other_code", "truncated_code", "lowercase_code", "unknown_code")
_TOKEN_DIGITS = 6


def unresolved_shape_of(text: str, prefixes: Iterable[str] | None = None) -> str:
    """One of `UNRESOLVED_SHAPES` for a token-shaped piece of an answer (see there).

    `prefixes`: the session's code prefixes; None means the shipped defaults
    (`settings.DEFAULT_PREFIXES`), for a reader with no session (an old log line).
    Never raises; the text is only tested, never kept.
    """
    if prefixes is None:
        from piimask.settings import DEFAULT_PREFIXES

        prefixes = DEFAULT_PREFIXES.values()
    m = _ANSWER_PARTS.fullmatch(text)
    if m is None:
        return "other_code"
    letters, digits = m.group(1), m.group(2)
    known = {str(v).upper() for v in prefixes} | {"ANON"}
    if letters.upper() not in known:
        return "other_code"
    if len(digits) < _TOKEN_DIGITS:
        return "truncated_code"
    if letters != letters.upper():
        return "lowercase_code"
    return "unknown_code"


class _MemoryStore:
    """Duck-types MappingStore in memory: never writes a file, never a keychain.

    A copy of the evaluation harness's in-memory store (product code never
    imports the harness). `path` only exists because the pseudonymiser reads it and
    creates its parent directory; nothing is ever written there.
    """

    def __init__(self, path: Path, state: object | None = None) -> None:
        self.path = Path(path)
        self._data: dict[str, Any] | None = (
            copy.deepcopy(dict(state)) if isinstance(state, Mapping) else None
        )

    def exists(self) -> bool:
        return self._data is not None

    def load(self) -> dict[str, Any]:
        return copy.deepcopy(self._data) if self._data is not None else {}

    def save(self, data: dict[str, Any]) -> None:
        self._data = copy.deepcopy(data)


def _refusal(code: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "spans": [], "warnings": []}


class TryItSession:
    """The masker for one tab: mask, reveal, reset, and the `call` JSON door."""

    def __init__(self, initial_counter: int | None = None) -> None:
        if initial_counter is not None and (
            not isinstance(initial_counter, int) or isinstance(initial_counter, bool)
        ):
            raise TypeError("tryit: initial_counter is not an integer")
        # Lazy: keeps cryptography and the word lists out of a bare import.
        from piimask.core.pseudonymize import UnifiedPseudonymizer
        from piimask.detect.detector import FreeTextDetector
        from piimask.detect.lexicon import load_default
        from piimask.detect.masker import _TOKEN_SHAPE, SpanMasker, find_token_spans
        from piimask.settings import Settings

        self._pseudo_cls = UnifiedPseudonymizer
        self._span_masker_cls = SpanMasker
        self._find_token_spans = find_token_spans
        # The masker's token shape, and its case-insensitive variant (an input
        # the user typed or an AI bent): both are D41 candidates.
        self._input_token_like = re.compile(_TOKEN_SHAPE.pattern, re.IGNORECASE)

        self._tmp = tempfile.TemporaryDirectory(prefix="piimask-tryit-")
        weakref.finalize(self, self._tmp.cleanup)
        self.home = Path(self._tmp.name)
        self.settings = Settings.defaults(self.home)
        self.detector = FreeTextDetector(load_default(), titles=self.settings.dutch_titles)
        start = self.settings.counter_start
        if initial_counter is not None:
            start = max(initial_counter, start)
        self._fresh_key({"forward": {}, "reverse": {}, "counter": start})

    def _fresh_key(self, state: Mapping[str, Any]) -> None:
        self.pseudo = self._pseudo_cls(
            self.settings, store=_MemoryStore(self.settings.mapping_path, state)
        )
        self.spans = self._span_masker_cls(self.pseudo, self.detector)

    # ------------------------------------------------------------------
    # The Python API (fails loud)
    # ------------------------------------------------------------------

    def mask(self, text: str) -> dict[str, Any]:
        """The masked text with every span's offsets in both texts, or a refusal code."""
        if not isinstance(text, str):
            raise TypeError("tryit: mask text is not a string")
        if not text.strip():
            return _refusal("empty_input")
        if len(text) > MAX_INPUT_CHARS:
            return _refusal("too_long")

        warnings = [
            {"code": "token_like_in_input", "start": m.start(), "end": m.end()}
            for m in self._input_token_like.finditer(text)
        ]
        try:
            masked, pairs = self.spans.mask(text)
        except ValueError as err:
            if self._is_already_masked(text, str(err)):
                return _refusal("already_masked")
            raise

        queued = {value for value, _kind in self.spans.review_queue()}
        out_spans: list[dict[str, Any]] = []
        shift = 0  # masked offset minus original offset, left to right
        for span, token in pairs:
            value = text[span.start:span.end]
            if span.kind == "EMAIL":
                replacement = f"{token}@{value.rsplit('@', 1)[1]}"
            else:
                replacement = token
            masked_start = span.start + shift
            masked_end = masked_start + len(replacement)
            shift += len(replacement) - (span.end - span.start)
            out_spans.append({
                "kind": span.kind,
                "source": span.source,
                "start": span.start,
                "end": span.end,
                "token": token,
                "masked_start": masked_start,
                "masked_end": masked_end,
                "review": value in queued,
            })
        return {"ok": True, "masked": masked, "spans": out_spans, "warnings": warnings}

    @staticmethod
    def _is_already_masked(text: str, message: str) -> bool:
        """True only for the masker's D42 refusal: an address whose local part is a token."""
        m = _UNREVEALABLE_EMAIL.fullmatch(message)
        if m is None:
            return False
        start, end = int(m.group(1)), int(m.group(2))
        if not (0 <= start < end <= len(text)):
            return False
        local = text[start:end].rsplit("@", 1)[0]
        return _TOKEN_LOCAL.fullmatch(local) is not None

    def reveal(self, answer: str) -> dict[str, Any]:
        """The answer with every known token back, which were restored, and what stayed unresolved."""
        if not isinstance(answer, str):
            raise TypeError("tryit: reveal text is not a string")
        revealed = self.spans.reveal(answer)
        found = self._find_token_spans(answer, self.pseudo.reverse_map)

        restored: list[dict[str, Any]] = []
        shift = 0
        for token, start, end in found:
            value = self.pseudo.depseudonymize(token)
            r_start = start + shift
            restored.append({"token": token, "start": r_start, "end": r_start + len(value)})
            shift += len(value) - (end - start)

        unresolved = [
            {"text": m.group(0), "start": m.start(), "end": m.end(), "shape": self.unresolved_shape(m.group(0))}
            for m in _ANSWER_TOKEN_LIKE.finditer(answer)
            if not any(s < m.end() and m.start() < e for _t, s, e in found)
        ]
        return {"ok": True, "revealed": revealed, "restored": restored, "unresolved": unresolved}

    def unresolved_shape(self, text: str) -> str:
        """One of `UNRESOLVED_SHAPES` for a token-shaped piece of an answer, by this key's prefixes."""
        return unresolved_shape_of(text, self.settings.prefixes.values())

    @property
    def counter(self) -> int:
        """The key's current counter: the last code number minted (read-only)."""
        return int(self.pseudo.counter)

    def review_queue(self) -> tuple[tuple[str, str], ...]:
        """(value, kind) for each unruled outlier value seen since the last reset."""
        return tuple(self.spans.review_queue())

    def reset(self) -> None:
        """Drop every mapping and the review queue; keep the counter (no code twice per tab)."""
        self._fresh_key({"forward": {}, "reverse": {}, "counter": self.pseudo.counter})

    # ------------------------------------------------------------------
    # The JSON door (never raises, never passes exception text)
    # ------------------------------------------------------------------

    def call(self, request_json: str) -> str:
        """One JSON request in, one JSON response out; every failure is a code.

        Requests:
        - `{"op": "mask", "text": str}` -> the `mask()` dict
        - `{"op": "reveal", "text": str}` -> the `reveal()` dict
        - `{"op": "feedback", "prompts": list}` -> `{"ok": true, "feedback": dict,
          "feedback_json": str}` (the dict from `build_feedback`, and the exact
          file text from its `to_json`, so the page previews and saves the same
          bytes), or `{"ok": false, "code": <refusal code>}`
        - `{"op": "reset"}` -> `{"ok": true}`

        Every response carries `"op"` (the request's op when it is a string,
        else null). A malformed request, an unknown op or any exception gives
        `{"ok": false, "code": "internal", "op": ...}`. Output is
        `json.dumps(..., ensure_ascii=False, sort_keys=True)`, so CPython and
        Pyodide give byte-comparable strings.
        """
        op: Any = None
        try:
            request = json.loads(request_json)
            if not isinstance(request, dict):
                raise TypeError("tryit: request is not an object")
            op = request.get("op")
            if not isinstance(op, str):
                op = None
                raise TypeError("tryit: request has no op")
            response = self._dispatch(op, request)
            response["op"] = op
            return json.dumps(response, ensure_ascii=False, sort_keys=True)
        except Exception:  # noqa: BLE001 - the page boundary: any failure becomes one code, never its text
            return json.dumps(
                {"ok": False, "code": "internal", "op": op}, ensure_ascii=False, sort_keys=True
            )

    def _dispatch(self, op: str, request: dict[str, Any]) -> dict[str, Any]:
        if op == "mask":
            return self.mask(request["text"])
        if op == "reveal":
            return self.reveal(request["text"])
        if op == "reset":
            self.reset()
            return {"ok": True}
        if op == "feedback":
            from piimask.tryit.feedback import FeedbackRefused, build_feedback, to_json

            prompts = request["prompts"]
            if not isinstance(prompts, list):
                raise TypeError("tryit: feedback prompts is not a list")
            try:
                doc = build_feedback(prompts)
            except FeedbackRefused as refused:
                return {"ok": False, "code": str(refused.code)}
            return {"ok": True, "feedback": doc, "feedback_json": to_json(doc)}
        raise ValueError("tryit: unknown op")
