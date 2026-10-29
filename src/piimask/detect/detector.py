"""
`FreeTextDetector`: where the PII is in a free-text prompt, by rules only.

The detector runs the rules in `piimask.detect.rules` in the fixed order of
`ALL_RULES` (each followed by its follow-up in `rules.FOLLOW_UPS`, if any) and
keeps one per-character claimed map (review finding L2: a lookup per
candidate, not a scan of every earlier claim).
A candidate that overlaps anything already claimed is dropped whole, never
trimmed, so an earlier, more certain rule always wins and the output can never
hold two overlapping spans.
That is what lets the masker replace spans right to left without one
replacement corrupting another, and what makes reveal byte-exact by
construction.

`rules` selects which rules run (a knockout test removes one at a time); the
order is always `ALL_RULES`, whatever order the caller lists them in.
`titles` are the short honorifics from `Settings.dutch_titles`; when none are
passed, the shipped defaults are used, and the Dutch spelled forms in
`rules.SPELLED_TITLES` are always added.

`known` maps a value the key already holds to its kind; only PERSON and
COMPANY values are used (identifiers and emails have their own rules).

Deterministic: every rule sorts its candidates before they are claimed, and no
set iteration order reaches the output; two calls on the same input give the
same tuple.

NFC (review finding M5): the rules and word lists are NFC, so a text that is
not NFC (an accent typed as a letter plus a combining mark) is normalised
first and every span is mapped back to the ORIGINAL text's offsets.
The text is cut into segments, each a starter character with the combining
marks after it; each segment is normalised on its own, and the segments'
NFC forms must join up to the NFC of the whole text, or detection refuses
(fail closed: no spans guessed on a text it cannot map).
A span edge inside a segment widens to the whole segment (more masked, never
less), and two spans that would then share a segment are refused too.
Key values are matched in their NFC form; the span the masker replaces is
always the original surface, so reveal stays byte-exact.

No value ever leaves this module except as offsets: a `Detected` carries a
kind, offsets and a rule id, never the text it covers.
"""

from __future__ import annotations

import itertools
import unicodedata
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from piimask.detect.rules import (
    COMPANY,
    ECHO_SOURCES,
    FOLLOW_UPS,
    PERSON,
    RULES,
    build_context,
)
from piimask.detect.types import ALL_RULES, Detected, Lexicon
from piimask.settings import DEFAULT_DUTCH_TITLES

_EMPTY: Mapping[str, str] = MappingProxyType({})


class FreeTextDetector:
    """Finds PII spans in free text with deterministic rules over word lists."""

    def __init__(
        self,
        lexicon: Lexicon,
        *,
        titles: Iterable[str] = (),
        rules: Iterable[str] = ALL_RULES,
    ) -> None:
        wanted = tuple(rules)
        unknown = sorted(set(wanted) - set(ALL_RULES))
        if unknown:
            raise ValueError(f"unknown detector rule id(s): {', '.join(unknown)}")
        self.lexicon = lexicon
        self.titles: tuple[str, ...] = tuple(titles) or DEFAULT_DUTCH_TITLES
        self.rules: tuple[str, ...] = tuple(r for r in ALL_RULES if r in set(wanted))

    def detect(self, text: str, known: Mapping[str, str] = _EMPTY) -> tuple[Detected, ...]:
        """Sorted by (start, end); spans never overlap; offsets index `text` as given."""
        if unicodedata.is_normalized("NFC", text):
            return self._detect_nfc(text, known)
        nfc, starts, ends = _nfc_map(text)
        nfc_known = {unicodedata.normalize("NFC", v): k for v, k in known.items()}
        out: list[Detected] = []
        last_end = 0
        for d in self._detect_nfc(nfc, nfc_known):
            start, end = starts[d.start], ends[d.end - 1]
            if start < last_end:
                raise ValueError(
                    f"detector: two spans share one NFC segment: {d.kind} [{d.start}:{d.end}]"
                )
            out.append(Detected(d.kind, start, end, d.source))
            last_end = end
        return tuple(out)

    def _detect_nfc(self, text: str, known: Mapping[str, str]) -> tuple[Detected, ...]:
        ctx = build_context(text, self.lexicon, self.titles, known)
        claimed = bytearray(len(text))
        found: list[Detected] = []
        for rule_id in self.rules:
            steps = [RULES[rule_id]]
            if rule_id in FOLLOW_UPS:
                steps.append(FOLLOW_UPS[rule_id])
            for step in steps:
                for start, end, kind in step(ctx):
                    if start >= end or claimed.find(1, start, end) != -1:
                        continue
                    claimed[start:end] = b"\x01" * (end - start)
                    found.append(Detected(kind, start, end, rule_id))
                    if kind == PERSON and rule_id in ECHO_SOURCES:
                        ctx.persons.append((start, end, rule_id))
                    elif kind == COMPANY and rule_id == "company_form":
                        ctx.companies.append((start, end))
                    elif kind == PERSON and rule_id == "outlier":
                        ctx.outliers.append((start, end))
        return tuple(sorted(found, key=lambda d: (d.start, d.end)))


def _nfc_map(text: str) -> tuple[str, list[int], list[int]]:
    """The NFC text, and for each NFC index the original segment's (start, end).

    Fails closed (ValueError) if the per-segment NFC forms do not join up to
    the NFC of the whole text.
    """
    cuts = [i for i, c in enumerate(text) if i == 0 or unicodedata.combining(c) == 0]
    cuts.append(len(text))
    parts: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for a, b in itertools.pairwise(cuts):
        seg = unicodedata.normalize("NFC", text[a:b])
        parts.append(seg)
        starts += [a] * len(seg)
        ends += [b] * len(seg)
    nfc = "".join(parts)
    if nfc != unicodedata.normalize("NFC", text):
        raise ValueError("detector: text cannot be mapped to NFC segment by segment")
    return nfc, starts, ends


__all__ = ["FreeTextDetector"]
