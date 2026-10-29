"""
The shared types of the free-text detector, and the detector contract.

Every other detector module (lexicon, rules, detector, masker, the harness
adapter) codes against these names, so they are fixed in ONE place: modules
built in parallel cannot drift on a field name or a rule id, and a second
detector only has to satisfy `DetectorProtocol` to sit behind the masker.

`SOURCES` names every rule, in the order the detector runs them.
The order is the design: identifiers first (VAT before the generic IBAN, so a
number's kind is right), then whole email addresses, then companies by legal
form, then people by key, honorific, header, name lexicon, echo and, last,
the outlier rule.
Each later rule skips characters an earlier one claimed, so an earlier, more
certain rule always wins an overlap.
`ALL_RULES` is the same tuple: the default rule set, and the list a knockout
test removes one rule from at a time.

`KINDS` is a literal copy of the evaluation harness's kind list, not an
import: the detector is the masking path, and the masking path must never
depend on the harness that measures it.
A test should pin the two tuples equal, so the copy cannot drift silently.

`Lexicon` holds the three word lists the rules read, already normalised, so
every lookup is one set membership and the rules never re-normalise:
common words are lowercase (a sentence-initial capital still finds the word),
names are NFC Titlecase and case-exact (the lowercase word is not the name).
`from_words` builds one from small lists with the same normalisation the
packaged loader applies, so a unit test can state exactly which words exist
without loading the full lists.

All data types are frozen: a detected span never changes after it is made,
so the masker cannot quietly alter what the scorer reads.

Stdlib only, and no `piimask.core` or evaluation-harness import.

No type here carries a PII value into output on its own: `Detected` holds a
kind, offsets and a rule id, never the text it covers.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

# The PII kinds a detected span may carry: a literal copy of the evaluation
# harness's kind list (see the module docstring for why not an import).
KINDS = ("PERSON", "COMPANY", "EMAIL", "IBAN", "VAT", "PHONE")

# Every rule id, in run order: a later rule skips characters an earlier one claimed.
SOURCES = (
    "identifier",
    "email",
    "company_form",
    "key",
    "honorific",
    "header",
    "name_lexicon",
    "echo",
    "outlier",
)

# The default rule set: every rule, in run order.
ALL_RULES = SOURCES


@dataclass(frozen=True)
class Detected:
    """A detected span: `kind` is one of KINDS, `source` the rule (one of SOURCES)."""

    kind: str
    start: int
    end: int
    source: str


@dataclass(frozen=True)
class Lexicon:
    """The word lists the rules read, already normalised.

    `nl_words` and `en_words` hold lowercase forms; `nl_names` holds NFC
    Titlecase forms and is matched case-exact.
    """

    nl_words: frozenset[str]
    nl_names: frozenset[str]
    en_words: frozenset[str]

    def is_word(self, w: str) -> bool:
        """True if `w`, lowercased, is a Dutch or English common word."""
        lowered = w.lower()
        return lowered in self.nl_words or lowered in self.en_words

    def is_name(self, w: str) -> bool:
        """True if `w`, NFC-normalised, is a Dutch proper name (case-exact)."""
        return unicodedata.normalize("NFC", w) in self.nl_names

    @classmethod
    def from_words(
        cls,
        nl_words: Iterable[str] = (),
        nl_names: Iterable[str] = (),
        en_words: Iterable[str] = (),
    ) -> Lexicon:
        """Build a lexicon from plain lists, normalised the way the loader does."""
        return cls(
            nl_words=frozenset(unicodedata.normalize("NFC", w).lower() for w in nl_words),
            nl_names=frozenset(unicodedata.normalize("NFC", w) for w in nl_names),
            en_words=frozenset(unicodedata.normalize("NFC", w).lower() for w in en_words),
        )


class DetectorProtocol(Protocol):
    """Anything that can say where the PII is in a free-text prompt.

    `known` maps a value the key already holds to its kind; the result is
    sorted by (start, end) and its spans never overlap.
    """

    def detect(self, text: str, known: Mapping[str, str] = ...) -> tuple[Detected, ...]: ...
