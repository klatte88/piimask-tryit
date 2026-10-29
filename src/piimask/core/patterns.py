"""
The free-text PII patterns, in ONE place.

The pseudonymiser (which replaces these shapes in free text) and the leak
validator (which blocks when they survive) used to carry their own copies of
the same regexes. Two copies drift: a form one side misses, the other side can
then never catch. Both now import from here, so a fix lands on both at once.

Stdlib only (`re`): the validator's stdlib-only promise (C23) depends on it.

Moved as found in CP2 Task 6; fixed in CP2 Task 7: the mobile pattern opens
with a lookbehind instead of \\b, so `+31` forms match (C11/C20), and both IBAN
patterns also see the printed form in groups of four (C70), the Dutch one in
lower case too.
"""

from __future__ import annotations

import re

# IBAN, Dutch form: NL + 2 check digits + 4 bank letters + 10 digits, exactly
# 18 characters.
#
# The fixed length matters. A \b-anchored generic pattern misses any IBAN
# glued to adjacent text - bank messages contain runs like
# "NL37BUNQ0123456789TRTPSEPA" with no separator, where the trailing \b can
# never match. Real IBANs survived that way. Matching an exact length needs no
# trailing boundary.
#
# Also the printed form, groups of four separated by single spaces
# ("NL91 ABNA 0417 1643 00"), and lower case ("nl91 abna ..."): people write
# IBANs that way in notes and messages (C70). The spaces are optional one by
# one, so the compact and glued forms match exactly as before.
IBAN_NL = re.compile(r'(?i:NL\d{2} ?[A-Z]{4} ?\d{4} ?\d{4} ?\d{2})')

# Other countries: bounded generic form.
# Compact, or printed in groups of four with single spaces (C70). Upper case
# only: a case-blind grouped form would read ordinary Dutch ("ab12 deze week")
# as an IBAN.
IBAN_GENERIC = re.compile(
    r'\b[A-Z]{2}\d{2}(?:[A-Z0-9]{10,28}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)\b'
)

# Dutch VAT number (BTW-nummer).
BTW_NL = re.compile(r'\bNL\d{9}B\d{2}\b')

# Dutch mobile number, with or without country code and separators.
# Opens with a lookbehind, not \b: a \b can never match before `+`, so every
# `+31` form slipped through (C11/C20). Not preceded by a word character or a
# `+` keeps "x06..." and the inner "0" of "0031..." from matching.
MOBILE_NL = re.compile(
    r'(?<![\w+])(?:\+31|0031|0)\s?6[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}\b'
)

# Email address. Group 1 = local part, group 2 = domain (the pseudonymiser
# replaces the local part and keeps the domain; the validator uses group 0).
# The validator's TLD class `[A-Za-z]` is the one kept: the pseudonymiser's
# copy read `[A-Z|a-z]`, a typo that also let a `|` count as a TLD letter.
EMAIL = re.compile(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')

__all__ = ["BTW_NL", "EMAIL", "IBAN_GENERIC", "IBAN_NL", "MOBILE_NL"]
