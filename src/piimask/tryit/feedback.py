"""
The try-it feedback file: what a tester flagged, with no real value in it.

A practitioner tries the masker on their own prompt and flags what went wrong:
personal data the masker missed, an ordinary word it masked, a code the AI
mangled in its answer. Those flags seed the next evaluation set, so they have to reach
Chris, but the prompt they sit on is a real client prompt. This module turns
the flags into a file that carries the SHAPE of every mistake and none of the
values the masker or the tester identified:

- the prompt is exported masked (tokens, never their values);
- every email domain the masker kept in clear (policy C09, `masker.py`) is
  replaced by `[DOMEIN]`, because a domain often names the client's company.
  Any other literal occurrence of such a domain anywhere in the file (typed
  alone in the prompt, in the note, in another prompt) is replaced too, case
  insensitive, and a domain kept after a token in the note
  (`EMAIL_001001@klant.nl`, the note was masked by the session) joins the set;
- a miss is replaced by `[GEMIST:<KIND>]`; its kind, length and position in
  the exported text survive, its text never does (the function never even
  receives it: only original offsets);
- an over-mask carries its text only when the tester ticked "this is not
  personal", and only when that text is exactly as long as the span it claims
  to be, so a page bug cannot put arbitrary text in the export;
- an answer problem carries only token-shaped text, which holds no value.

Why one left-to-right pass over the masked text: misses arrive as offsets into
the ORIGINAL text. Each span records both its original and its masked offsets,
so a miss's masked position is its original position plus the length change of
every span before it. Every replacement (miss marker, domain) is then one edit
on the masked text, applied in order, and each marker's position in the output
is the running offset when it is written. No offset is ever patched afterwards.

Why it refuses rather than guesses: a miss overlapping a masked span, or two
overlapping misses, or a mask result whose offsets do not add up, has no single
right export. A refusal names a stable code, prompt and flag indexes and
offsets. No error message here carries text.

Stdlib only: the page masks the note through the session BEFORE calling this,
so the module never needs the session or the key.
"""

from __future__ import annotations

import json
import re
from itertools import pairwise
from typing import Any

FORMAT = "piimask-tryit-feedback"
VERSION = 1
MASKER = "rules-v1"

# Kinds and sources are short labels; anything else is not a label.
_KIND = re.compile(r"[A-Z_]{1,32}")
_SOURCE = re.compile(r"[A-Za-z0-9_\-]{1,40}")
# A real token, as the masker mints it.
_TOKEN = re.compile(r"[A-Z]+_\d{6,}")
# Token-shaped text in an AI answer (the session's case-insensitive scan).
_TOKEN_LIKE = re.compile(r"[A-Za-z]+_\d{5,}")
# A domain kept after a token (`EMAIL_001001@klant.nl`), the shape of
# `piimask.core.patterns.EMAIL`'s domain part.
_TOKEN_AT_DOMAIN = re.compile(r"[A-Z]+_\d{6,}@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_USEFUL = ("ja", "deels", "nee")

DOMAIN_MARK = "[DOMEIN]"


class FeedbackRefused(ValueError):
    """The flags cannot be exported as given. `.code` is a stable code; no text."""

    def __init__(self, code: str, where: str = "") -> None:
        self.code = code
        super().__init__(f"feedback: {code}" + (f": {where}" if where else ""))


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _need(cond: bool, where: str) -> None:
    if not cond:
        raise FeedbackRefused("bad_input", where)


def _spans(mr: Any, original_length: int, at: str) -> tuple[str, list[dict[str, Any]]]:
    """Validate one mask() result; return (masked, spans) with offsets proven consistent."""
    _need(isinstance(mr, dict) and mr.get("ok") is True, f"{at} mask_result")
    masked = mr.get("masked")
    spans = mr.get("spans")
    _need(isinstance(masked, str) and isinstance(spans, list), f"{at} mask_result")
    out: list[dict[str, Any]] = []
    cursor = 0
    delta = 0
    for k, sp in enumerate(spans):
        w = f"{at} span {k}"
        _need(isinstance(sp, dict), w)
        kind, source, token = sp.get("kind"), sp.get("source"), sp.get("token")
        s, e, ms, me = sp.get("start"), sp.get("end"), sp.get("masked_start"), sp.get("masked_end")
        _need(isinstance(kind, str) and _KIND.fullmatch(kind) is not None, w)
        _need(isinstance(source, str) and _SOURCE.fullmatch(source) is not None, w)
        _need(isinstance(token, str) and _TOKEN.fullmatch(token) is not None, w)
        _need(isinstance(sp.get("review"), bool), w)
        _need(all(_int(x) for x in (s, e, ms, me)), w)
        _need(cursor <= s < e <= original_length, f"{w} [{s}:{e}]")
        _need(ms == s + delta and ms < me <= len(masked), f"{w} [{s}:{e}]")
        domain = None
        if kind == "EMAIL":
            at_sign = ms + len(token)
            _need(masked[ms:at_sign] == token and masked[at_sign:at_sign + 1] == "@", w)
            domain = (at_sign + 1, me)
        else:
            _need(masked[ms:me] == token, w)
        out.append({**sp, "_domain": domain})
        delta += (me - ms) - (e - s)
        cursor = e
    _need(len(masked) == original_length + delta, f"{at} masked length")
    return masked, out


def _misses(raw: Any, spans: list[dict[str, Any]], original_length: int, at: str) -> list[dict[str, Any]]:
    _need(isinstance(raw, list), f"{at} misses")
    misses: list[dict[str, Any]] = []
    for j, m in enumerate(raw):
        w = f"{at} miss {j}"
        _need(isinstance(m, dict), w)
        s, e, kind = m.get("start"), m.get("end"), m.get("kind")
        _need(_int(s) and _int(e) and 0 <= s < e <= original_length, w)
        _need(isinstance(kind, str), w)
        kind = kind.upper()
        _need(_KIND.fullmatch(kind) is not None, w)
        for sp in spans:
            if sp["start"] < e and s < sp["end"]:
                raise FeedbackRefused("miss_overlaps_span", f"{w} [{s}:{e}]")
        misses.append({"start": s, "end": e, "kind": kind})
    misses.sort(key=lambda m: (m["start"], m["end"]))
    for prev, cur in pairwise(misses):
        if cur["start"] < prev["end"]:
            raise FeedbackRefused(
                "miss_overlaps_miss", f"{at} [{prev['start']}:{prev['end']}] [{cur['start']}:{cur['end']}]"
            )
    return misses


def _domain_re(domains: set[str]) -> re.Pattern[str] | None:
    if not domains:
        return None
    alts = sorted(domains, key=lambda d: (-len(d), d))
    return re.compile("|".join(re.escape(d) for d in alts), re.IGNORECASE)


def _scrub(text: str, dre: re.Pattern[str] | None) -> str:
    return text if dre is None else dre.sub(DOMAIN_MARK, text)


def _masked_with_misses(
    masked: str,
    spans: list[dict[str, Any]],
    misses: list[dict[str, Any]],
    dre: re.Pattern[str] | None,
) -> tuple[str, list[dict[str, Any]]]:
    """One left-to-right pass of edits; returns the text and each miss's marker position."""
    # Original offset -> masked offset, for an offset outside every span.
    def to_masked(p: int) -> int:
        shift = 0
        for sp in spans:
            if sp["end"] <= p:
                shift += (sp["masked_end"] - sp["masked_start"]) - (sp["end"] - sp["start"])
        return p + shift

    # (start, end, replacement, miss or None) on the masked text
    edits: list[tuple[int, int, str, dict[str, Any] | None]] = []
    for m in misses:
        edits.append((to_masked(m["start"]), to_masked(m["end"]), f"[GEMIST:{m['kind']}]", m))
    for sp in spans:
        if sp["_domain"] is not None and sp["_domain"][0] < sp["_domain"][1]:
            edits.append((sp["_domain"][0], sp["_domain"][1], DOMAIN_MARK, None))
    # Any other literal occurrence of a kept domain, where nothing else edits
    # and no token sits.
    if dre is not None:
        blocked = [(a, b) for a, b, _, _ in edits]
        blocked += [(sp["masked_start"], sp["masked_start"] + len(sp["token"])) for sp in spans]
        for mt in dre.finditer(masked):
            a, b = mt.start(), mt.end()
            if not any(x < b and a < y for x, y in blocked):
                edits.append((a, b, DOMAIN_MARK, None))
    edits.sort(key=lambda t: (t[0], t[1]))

    parts: list[str] = []
    out_misses: list[dict[str, Any]] = []
    cursor = 0
    pos = 0
    for a, b, repl, miss in edits:
        gap = masked[cursor:a]
        parts.append(gap)
        pos += len(gap)
        if miss is not None:
            out_misses.append(
                {
                    "kind": miss["kind"],
                    "length": miss["end"] - miss["start"],
                    "start": pos,
                    "end": pos + len(repl),
                }
            )
        parts.append(repl)
        pos += len(repl)
        cursor = b
    parts.append(masked[cursor:])
    return "".join(parts), out_misses


def _over_masks(raw: Any, spans: list[dict[str, Any]], at: str) -> list[dict[str, Any]]:
    _need(isinstance(raw, list), f"{at} over_masks")
    out: list[dict[str, Any]] = []
    for j, om in enumerate(raw):
        w = f"{at} over_mask {j}"
        _need(isinstance(om, dict), w)
        idx, confirmed = om.get("span_index"), om.get("confirmed_not_personal")
        _need(_int(idx) and 0 <= idx < len(spans) and isinstance(confirmed, bool), w)
        sp = spans[idx]
        entry: dict[str, Any] = {
            "span_index": idx,
            "kind": sp["kind"],
            "source": sp["source"],
            "confirmed_not_personal": confirmed,
        }
        if confirmed:
            text = om.get("text")
            _need(isinstance(text, str), w)
            if len(text) != sp["end"] - sp["start"]:
                raise FeedbackRefused("over_mask_text_mismatch", f"{w} span {idx}")
            entry["text"] = text
        out.append(entry)
    return out


def _answer(raw: Any, at: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    w = f"{at} answer"
    _need(isinstance(raw, dict), w)
    unresolved, wrong, useful = raw.get("unresolved", []), raw.get("restore_wrong", []), raw.get("useful")
    _need(isinstance(unresolved, list) and isinstance(wrong, list), w)
    _need(useful is None or (isinstance(useful, str) and useful in _USEFUL), w)
    texts: list[dict[str, str]] = []
    for j, u in enumerate(unresolved):
        t = u.get("text") if isinstance(u, dict) else None
        _need(isinstance(t, str) and _TOKEN_LIKE.fullmatch(t) is not None, f"{w} unresolved {j}")
        texts.append({"text": t})
    tokens: list[dict[str, str]] = []
    for j, r in enumerate(wrong):
        t = r.get("token") if isinstance(r, dict) else None
        _need(isinstance(t, str) and _TOKEN_LIKE.fullmatch(t) is not None, f"{w} restore_wrong {j}")
        tokens.append({"token": t})
    return {"unresolved": texts, "restore_wrong": tokens, "useful": useful}


def build_feedback(prompts: list[dict[str, Any]]) -> dict[str, Any]:
    """The feedback document for `prompts` (entries per the try-it data contract).

    Raises `FeedbackRefused` (`.code`: `bad_input`, `miss_overlaps_span`,
    `miss_overlaps_miss`, `over_mask_text_mismatch`, `domain_survives`).
    """
    _need(isinstance(prompts, list), "prompts")
    checked: list[dict[str, Any]] = []
    domains: set[str] = set()
    for i, p in enumerate(prompts):
        at = f"prompt {i}"
        _need(isinstance(p, dict), at)
        n = p.get("original_length")
        _need(_int(n) and n >= 0, f"{at} original_length")
        masked, spans = _spans(p.get("mask_result"), n, at)
        note = p.get("masked_note", "")
        _need(isinstance(note, str), f"{at} masked_note")
        _need(isinstance(p.get("checked_all"), bool), f"{at} checked_all")
        for sp in spans:
            if sp["_domain"] is not None:
                d = masked[sp["_domain"][0]:sp["_domain"][1]]
                if d:
                    domains.add(d)
        for text in (masked, note):
            domains.update(m.group(1) for m in _TOKEN_AT_DOMAIN.finditer(text))
        checked.append(
            {
                "masked": masked,
                "spans": spans,
                "misses": _misses(p.get("misses", []), spans, n, at),
                "over_masks": _over_masks(p.get("over_masks", []), spans, at),
                "answer": _answer(p.get("answer"), at),
                "checked_all": p["checked_all"],
                "masked_note": note,
            }
        )

    dre = _domain_re(domains)
    out_prompts: list[dict[str, Any]] = []
    for c in checked:
        text, misses = _masked_with_misses(c["masked"], c["spans"], c["misses"], dre)
        over = [
            {**om, "text": _scrub(om["text"], dre)} if "text" in om else om
            for om in c["over_masks"]
        ]
        out_prompts.append(
            {
                "masked_with_misses": text,
                "spans": [
                    {"kind": sp["kind"], "source": sp["source"], "review": sp["review"], "token": sp["token"]}
                    for sp in c["spans"]
                ],
                "misses": misses,
                "over_masks": over,
                "answer": c["answer"],
                "checked_all": c["checked_all"],
                "masked_note": _scrub(c["masked_note"], dre),
            }
        )
    doc = {"format": FORMAT, "version": VERSION, "masker": MASKER, "prompts": out_prompts}
    # Fail closed: no kept domain anywhere in the serialised file.
    if dre is not None:
        for i, op in enumerate(out_prompts):
            if dre.search(to_json(op)) is not None:
                raise FeedbackRefused("domain_survives", f"prompt {i}")
    return doc


def to_json(doc: dict[str, Any]) -> str:
    """Stable serialisation: equal documents give byte-equal text."""
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2)
