"""
The span masker: replaces exactly the detected spans, and reveals by token.

The as-found free-text path rewrites strings (a known-value scrub, then
regexes that also edit literal text), so it cannot promise a byte-exact
reveal. This masker can, by construction: the detector says WHICH characters
are PII, the masker swaps exactly those characters for a token and leaves
every other character as written, and the key maps each token back to the
exact surface text it replaced. Reveal is then a token lookup, nothing more.

Why tokens come from the existing pseudonymiser: one value must have one
token everywhere. Each span is minted through `UnifiedPseudonymizer.pseudonymize`
with the same category the database pseudonymiser uses for that kind
(PERSON -> person, COMPANY -> company, IBAN -> account, VAT and PHONE ->
reference; the same table the evaluation harness uses, copied here because
the masking path never imports the harness). An EMAIL span covers the whole
address, but only the local part is minted (`pseudonymize(local, "email")`,
exactly what `pseudonymize_email` does) and the domain is kept, policy C09.
The value minted is the exact surface text: "Wietske" and "wietske" get two
tokens (Chris, 28 Oct, decision 2: variant consistency is reported, never
forced).

Tokens are minted in reading order (left to right), so a key grows the same
way on every run over the same text, and a cold start reproduces the masked
text exactly. The masked text is assembled in one pass from the literal gaps
and the replacements, so no offset ever shifts under a later span.

The caveat this design inherits (review finding 11): `forward_map` is keyed
by VALUE only (`pseudonymize.py`, the existing-mapping check), not by value
and kind. A PERSON surface equal to an email local part learned earlier
("wietske" after `wietske@...`) therefore gets the EMAIL_ token, and an email
local part equal to a name learned earlier gets the PERSON_ token. The token's
prefix may name the other kind; the reveal is still byte-exact, because the
token still maps back to the same exact string. `known()` reads kinds from
prefixes, so such a value is offered to the detector under the prefix's kind
(or not at all, for EMAIL_), never under a guessed one.

`known()` offers the detector only PERSON_ and COMPANY_ values of at least
two characters (a one-letter key value would match every lone capital letter,
review finding M4). EMAIL_ is
never a name (the f06 bug was an address's local part masking its owner's
name); ACCT_ and REF_ values are identifiers, found by shape (rule D01).
It is computed fresh on every `mask` call, so a value learned earlier in the
session is matched later in it (consistency within a run).

The review queue (review finding 7): a value the outlier rule (D09) masked is
"unruled" until a person accepts or dismisses it (rulings arrive next slice).
The masker keeps the set of unruled outlier values and hands it out through
`state()` as `{"outliers": [...]}`, carried beside the key the way the core
carries `freetext_derived`; a masker built with that state restores it. A
span is queued when its value is in that set, whichever rule found it this
time: in a later session the value is a key value, so rule D04 finds it, and
it must still reach the queue. The queue holds one entry per value per
session, in first-seen order. A value that was never an outlier (a key value
from Moneybird, a lexicon name) is never queued.

Reveal: every `[A-Z]+_\\d{6,}` match resolves to the LONGEST reverse-map key
inside it that starts in the letter run and ends in the digit run (a glued
IBAN comes out as `ACCT_001016TRTP`, so the token sits inside the match).
This is the same rule the evaluation harness uses to find tokens, written
again here because product code must not import the harness; a contract-drift test
drives both with the same inputs.

No error message here carries a value: kinds and offsets only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from piimask.detect.types import Detected, DetectorProtocol

# Detected kind -> pseudonymiser category. Mirrors the evaluation harness's
# table (the database pseudonymiser's categories);
# EMAIL is minted on its local part instead.
_KIND_CATEGORY = {
    "PERSON": "person",
    "COMPANY": "company",
    "IBAN": "account",
    "VAT": "reference",
    "PHONE": "reference",
}

# The pseudonym shape, scanned WITHOUT \b (see the module docstring).
_TOKEN_SHAPE = re.compile(r"([A-Z]+)_(\d{6,})")

# The rule id whose hits are unruled until a person rules on them.
_OUTLIER_SOURCE = "outlier"


def find_token_spans(
    masked: str, reverse_map: Mapping[str, str]
) -> tuple[tuple[str, int, int], ...]:
    """Every real token in `masked` as (token, start, end).

    For each `[A-Z]+_\\d{6,}` match, the token is the LONGEST reverse-map key
    inside it that starts in the letter run and ends in the digit run; letters
    before it and digits after it are literal. A match holding no known token
    is literal text.
    """
    found: list[tuple[str, int, int]] = []
    for m in _TOKEN_SHAPE.finditer(masked):
        letters_end = m.end(1)  # index of "_"
        best: tuple[int, int] | None = None
        for s in range(m.start(1), letters_end):
            # the digit run must keep at least 6 digits
            for e in range(m.end(2), letters_end + 6, -1):
                if masked[s:e] in reverse_map:
                    if best is None or (e - s) > (best[1] - best[0]):
                        best = (s, e)
                    break
        if best is not None:
            found.append((masked[best[0]:best[1]], best[0], best[1]))
    return tuple(found)


class SpanMasker:
    """Masks the spans a detector finds with tokens from one pseudonymiser.

    `pseudonymizer` is a `UnifiedPseudonymizer` (duck-typed: `pseudonymize`,
    `depseudonymize`, `forward_map`, `reverse_map`, `prefixes`); `detector`
    satisfies `DetectorProtocol`. `state` is a previous `state()` (or a whole
    session state holding an `"outliers"` list); it restores the unruled
    outlier set.
    """

    def __init__(
        self,
        pseudonymizer: Any,
        detector: DetectorProtocol,
        *,
        state: Mapping[str, Any] | None = None,
    ) -> None:
        self._pseudo = pseudonymizer
        self._detector = detector
        self._outliers: set[str] = set()
        self._queue: list[tuple[str, str]] = []
        self._queued: set[str] = set()
        if state is not None:
            carried = state.get("outliers", [])
            if not isinstance(carried, (list, tuple)) or not all(
                isinstance(v, str) for v in carried
            ):
                raise ValueError("masker state: outliers is not a list of strings")
            self._outliers.update(carried)

    def _prefix(self, category: str, default: str) -> str:
        prefixes = getattr(self._pseudo, "prefixes", {}) or {}
        return f"{prefixes.get(category, default)}_"

    def known(self) -> dict[str, str]:
        """Key value -> PERSON or COMPANY, by the token's prefix; other kinds skipped.

        Values shorter than two characters are skipped (review finding M4).
        """
        person = self._prefix("person", "PERSON")
        company = self._prefix("company", "COMPANY")
        out: dict[str, str] = {}
        for value, token in self._pseudo.forward_map.items():
            if len(value) < 2:
                continue
            if token.startswith(person):
                out[value] = "PERSON"
            elif token.startswith(company):
                out[value] = "COMPANY"
        return out

    def _mint(self, span: Detected, value: str) -> tuple[str, str]:
        """(token, replacement text) for one span; fails closed on a lossy mint."""
        where = f"{span.kind} [{span.start}:{span.end}]"
        if span.kind == "EMAIL":
            if "@" not in value:
                raise ValueError(f"masker: email span has no @: {where}")
            local, domain = value.rsplit("@", 1)
            token = self._pseudo.pseudonymize(local, "email")
            replacement = f"{token}@{domain}"
            minted = local
        elif span.kind in _KIND_CATEGORY:
            token = self._pseudo.pseudonymize(value, _KIND_CATEGORY[span.kind])
            replacement = token
            minted = value
        else:
            raise ValueError(f"masker: unknown kind: {where}")
        # The pseudonymiser strips values and passes pseudonym-shaped input
        # through; either would make the reveal lossy, so refuse the span.
        if self._pseudo.reverse_map.get(token) != minted:
            raise ValueError(f"masker: span cannot be revealed byte-exact: {where}")
        return token, replacement

    def mask(self, text: str) -> tuple[str, tuple[tuple[Detected, str], ...]]:
        """The masked text, and each detected span with its token, left to right."""
        spans = sorted(
            self._detector.detect(text, self.known()), key=lambda d: (d.start, d.end)
        )
        cursor = 0
        for span in spans:
            if not (cursor <= span.start < span.end <= len(text)):
                raise ValueError(
                    f"masker: span out of order or bounds: {span.kind} [{span.start}:{span.end}]"
                )
            cursor = span.end

        parts: list[str] = []
        pairs: list[tuple[Detected, str]] = []
        cursor = 0
        for span in spans:
            value = text[span.start:span.end]
            token, replacement = self._mint(span, value)
            parts.append(text[cursor:span.start])
            parts.append(replacement)
            pairs.append((span, token))
            cursor = span.end

            if span.source == _OUTLIER_SOURCE:
                self._outliers.add(value)
            if value in self._outliers and value not in self._queued:
                self._queued.add(value)
                self._queue.append((value, span.kind))
        parts.append(text[cursor:])
        return "".join(parts), tuple(pairs)

    def reveal(self, masked: str) -> str:
        """Every known token back to its exact value; everything else as written."""
        out: list[str] = []
        cursor = 0
        for token, start, end in find_token_spans(masked, self._pseudo.reverse_map):
            out.append(masked[cursor:start])
            out.append(self._pseudo.depseudonymize(token))
            cursor = end
        out.append(masked[cursor:])
        return "".join(out)

    def review_queue(self) -> tuple[tuple[str, str], ...]:
        """(value, kind) for each unruled outlier value seen this session, first-seen order."""
        return tuple(self._queue)

    def state(self) -> dict[str, Any]:
        """{"outliers": sorted unruled outlier values}, to merge into the session state."""
        return {"outliers": sorted(self._outliers)}
