"""
The detector's rules, and the small vocabulary they read.

Every rule is plain code over the text, the shared regexes in
`piimask.core.patterns` and the word lists in a `Lexicon`; there is no model
anywhere in the masking path, by design.
A rule is a function `rule(ctx) -> list[Candidate]`; `RULES` maps each rule id
in `piimask.detect.types.ALL_RULES` to its function, and `FreeTextDetector`
runs them in that order.
A rule returns candidates in the order it wants them claimed: the detector
accepts each candidate unless it overlaps a character an earlier candidate
(of this or an earlier rule) already claimed, in which case it is DROPPED,
never trimmed.
So an earlier, more certain rule always wins: identifiers before emails,
companies before people, a key hit before a guess, and the outlier rule last.

The rules read NFC text only.
The packaged word lists are NFC; `FreeTextDetector` normalises a non-NFC
input to NFC before the rules run and maps every span back to the original
text's offsets (review finding M5), so a rule never sees a combining mark
split a name.

The design, rule by rule (ids D01-D09 in the claim ledger):

- D01 identifier: IBAN (Dutch form first), Dutch VAT before the generic IBAN
  so a VAT number is never labelled IBAN, then Dutch mobile numbers.
  The regexes are imported from `core/patterns.py`, never copied, so the
  detector and the leak validator can never disagree on a shape.
- D02 email: the whole address.
  The local part is never used as a name source (that is what broke f06 in the
  string-rewriting path).
- D03 company_form: a short run of capitalised words directly before a legal
  form (`BV`, `B.V.`, `VOF`, `GmbH`, ...) on one line.
  It runs before every person rule, so a name inside a company name is the
  company's, not a person's.
- D04 key: values the key already holds as PERSON or COMPANY, case-exact and
  whole-word, longest first.
  Case-exact is deliberate: a key name that is also an everyday word is not
  masked in its lowercase, everyday use (the f11 finding).
- D05 honorific: a title (`Dhr.`, `mevrouw`, `t.a.v.`, ...) then a name; the
  span is the name only, never the title.
- D06 header: the display name on a `Van:` / `From:` / `Aan:` ... line.
- D07 name_lexicon: a capitalised word that is a known proper name and NOT a
  common word ("strong"), or two adjacent known names where the first is not a
  sentence-initial common word.
- D08 echo: a person already found in THIS text, found again elsewhere: the
  full value, its all-caps form (a signature line), each capitalised part of
  it, and the lowercase first name when that lowercase form is not a common
  word.
- D09 outlier: a capitalised word mid-sentence that is in no word list and not
  vetoed.
  The 28 Oct decision: an unknown capitalised word is masked and queued for
  review, because the risk on that side is over-masking, never a leak.

Two follow-ups run right after the rule they extend, over the spans that rule
had accepted, and carry that rule's id (review findings M1 and H1):

- after D03, the company echo: the company name without its legal form,
  found again in the same text, case-exact and whole-word, as COMPANY; only a
  name of two or more words, or one word that is not a common word, so a
  company called after an everyday word does not mask that word everywhere.
- after D09, the outlier echo: the full outlier value, found again in the same
  text, case-exact and whole-word, so the same unknown word at the start of a
  later sentence (where D09 itself never looks) is masked too.
  Only the full value: outliers never feed D08's parts or lowercase forms.

D05 and D06 never take a one-token value of fewer than two letters, or one
token that is a common word and not a name (review finding M4): such a value
would enter the key and D04 would then mask that letter or word in every
later text. D04 ignores key values shorter than two characters for the same
reason.

Shared definitions, used by several rules:

- Token: `TOKEN_RE`, letters only, with inner hyphens and apostrophes.
  A token touching a digit or `_` on either side (inside an id such as a
  payment reference) is never a name candidate.
- Titlecase: each hyphen/apostrophe part has only lowercase letters after its
  first letter, and the token's first letter is uppercase.
  `str.istitle` is not used: it reads some mixed forms differently.
- Sentence-initial: only spaces, quotes, brackets, `-`, `*` or bullets
  between the token and the start of the text, a newline, or `. ! ? : ;`.
- Name sequence: from a start token, extend right over Titlecase tokens and
  over tussenvoegsels that are followed by a Titlecase token, each step
  separated by exactly ONE space, at most five words.
  Any other character between two tokens ends the sequence, so a name at the
  end of one sentence never joins the first word of the next.
  Tussenvoegsels (including `'t`, which can never be a token because a token
  cannot start with an apostrophe) are matched by a regex on the text at the
  position after a token, not as tokens.
- Never a name: a title token, a header-label token, and a vetoed word (the
  payment processors, a few software and platform brands).

No function here returns or logs the text it matched: candidates carry offsets
and a kind only, so no value can leave through a rule.
"""

from __future__ import annotations

import bisect
import functools
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from piimask.core.patterns import BTW_NL, EMAIL, IBAN_GENERIC, IBAN_NL, MOBILE_NL
from piimask.detect.types import ALL_RULES, Detected, Lexicon

# -- vocabulary ---------------------------------------------------------------

# Dutch spelled titles, matched case-insensitively with an optional trailing
# `.`; the short forms (Mw, Dhr, ...) come from `Settings.dutch_titles`.
SPELLED_TITLES: tuple[str, ...] = (
    "mevrouw",
    "meneer",
    "mevr",
    "de heer",
    "heer",
    "t.a.v.",
    "tav",
    "juffrouw",
)

# Name particles. Multiword forms are listed first so the regex prefers them.
TUSSENVOEGSELS: tuple[str, ...] = (
    "van der",
    "van den",
    "van de",
    "in 't",
    "de la",
    "van",
    "de",
    "der",
    "den",
    "het",
    "'t",
    "te",
    "ter",
    "ten",
    "in",
    "op",
    "von",
    "du",
    "la",
    "le",
    "el",
    "al",
)

# Legal forms, case-exact (lowercase `bv` is "bijvoorbeeld" in Dutch).
# Longer forms first so `BVBA` is never read as `BV`.
LEGAL_FORMS: tuple[str, ...] = (
    "BVBA",
    "B.V.",
    "N.V.",
    "V.O.F.",
    "C.V.",
    "GmbH",
    "LLC",
    "Ltd",
    "Inc",
    "VOF",
    "BV",
    "NV",
    "CV",
)

# Email header labels, matched line-initial and followed by `:`.
HEADER_LABELS: tuple[str, ...] = ("Van", "Aan", "From", "To", "Cc", "CC", "Bcc", "Afzender")

# The payment processors the bookkeeping settings list
# (`patterns.payment_processors`). `Settings` does not expose them, so they
# are a constant here.
PAYMENT_PROCESSORS: tuple[str, ...] = ("Mollie", "PayPal", "Stripe", "iDEAL")

# Generic software and platform brand names that turn up capitalised
# mid-sentence in business text and are never a person.
PLATFORM_BRANDS: tuple[str, ...] = (
    "Google",
    "Gmail",
    "Microsoft",
    "Outlook",
    "Excel",
    "Windows",
    "Apple",
    "Android",
    "Linux",
    "Slack",
    "Zoom",
    "Dropbox",
    "Shopify",
    "WordPress",
    "WhatsApp",
    "LinkedIn",
    "Facebook",
    "Instagram",
    "YouTube",
    "GitHub",
    "Netflix",
    "Spotify",
    "Amazon",
    "Moneybird",
    "Exact",
    "Notion",
    "Trello",
    "Canva",
)

VETOES: frozenset[str] = frozenset(PAYMENT_PROCESSORS + PLATFORM_BRANDS)

# -- regexes ------------------------------------------------------------------

TOKEN_RE = re.compile(r"[^\W\d_]+(?:['’-][^\W\d_]+)*")

_PART_SPLIT = re.compile(r"['’-]")

_TUSSEN_RE = re.compile(
    "(?:"
    + "|".join(re.escape(t).replace("'", "['’]").replace(r"\ ", " ") for t in TUSSENVOEGSELS)
    + ")(?= )",
    re.IGNORECASE,
)

_LEGAL_RE = re.compile(
    r"(?<!\w)(?:" + "|".join(re.escape(f) for f in LEGAL_FORMS) + r")(?!\w)"
)

_HEADER_RE = re.compile(
    r"^[ \t>]*(?:" + "|".join(HEADER_LABELS) + r"):[ \t]*(?P<rest>[^\n]*)$",
    re.MULTILINE,
)

# Characters skipped when looking back for a sentence or line start.
_LOOKBACK_SKIP = frozenset(" \t\"'“”‘’„«»`()[]{}-*•")

PERSON = "PERSON"
COMPANY = "COMPANY"

# A candidate span: (start, end, kind).
Candidate = tuple[int, int, str]


# -- shared definitions --------------------------------------------------------


def is_titlecase(token: str) -> bool:
    """True for `Vermaat-Oost`-style tokens: uppercase first, lowercase after each part's first."""
    if not token or not token[0].isupper():
        return False
    for part in _PART_SPLIT.split(token):
        if not part:
            return False
        rest = part[1:]
        if rest and not all(c.islower() for c in rest):
            return False
    return True


def is_tussenvoegsel(word: str) -> bool:
    """True if `word` (any case) is a single-word name particle."""
    return word.lower().replace("’", "'") in TUSSENVOEGSELS


def at_start(text: str, pos: int, marks: str) -> bool:
    """True if only skippable characters sit between `pos` and a text/line start or a mark."""
    i = pos - 1
    while i >= 0 and text[i] in _LOOKBACK_SKIP:
        i -= 1
    return i < 0 or text[i] in "\n\r" or text[i] in marks


def sentence_initial(text: str, pos: int) -> bool:
    """The detector's sentence-initial test: start, newline, or one of `. ! ? : ;`."""
    return at_start(text, pos, ".!?:;")


@dataclass(frozen=True)
class Token:
    start: int
    end: int
    text: str


@dataclass
class Context:
    """Everything one `detect` call's rules read; built once per call."""

    text: str
    lexicon: Lexicon
    titles: frozenset[str]
    title_re: re.Pattern[str]
    known: Mapping[str, str]
    tokens: tuple[Token, ...]
    by_start: dict[int, int]
    # token index by end offset, and the sorted start offsets (for bisect)
    by_end: dict[int, int] = field(default_factory=dict)
    starts: list[int] = field(default_factory=list)
    # PERSON spans accepted so far, with their rule id: the echo rule's sources.
    persons: list[tuple[int, int, str]] = field(default_factory=list)
    # COMPANY spans D03 accepted, and PERSON spans D09 accepted: the follow-ups' sources.
    companies: list[tuple[int, int]] = field(default_factory=list)
    outliers: list[tuple[int, int]] = field(default_factory=list)

    # -- token predicates --

    def touches_id(self, tok: Token) -> bool:
        """True if a digit or `_` sits directly before or after the token."""
        t = self.text
        before = t[tok.start - 1] if tok.start > 0 else ""
        after = t[tok.end] if tok.end < len(t) else ""
        return any(c.isdigit() or c == "_" for c in (before, after))

    def is_title(self, word: str) -> bool:
        return word.lower() in self.titles

    def name_ok(self, tok: Token) -> bool:
        """A token that may start or join a name sequence."""
        return (
            is_titlecase(tok.text)
            and not self.touches_id(tok)
            and not self.is_title(tok.text)
            and tok.text not in HEADER_LABELS
            and tok.text not in VETOES
        )

    def token_at(self, pos: int) -> int | None:
        return self.by_start.get(pos)

    # -- name sequences --

    def tussen_at(self, pos: int) -> tuple[int, int] | None:
        """A tussenvoegsel at `pos` followed by one space and a name token: (end, words)."""
        m = _TUSSEN_RE.match(self.text, pos)
        if m is None:
            return None
        word = m.group()
        if word[1:] != word[1:].lower():
            return None
        nxt = self.token_at(m.end() + 1)
        if nxt is None or not self.name_ok(self.tokens[nxt]):
            return None
        return m.end(), word.count(" ") + 1

    def sequence(self, idx: int, *, start: int | None = None, words: int = 0) -> tuple[int, int]:
        """Extend a name sequence from token `idx`; returns (start, end) offsets.

        `start` and `words` let a caller begin with a tussenvoegsel already
        consumed before token `idx`.
        """
        tok = self.tokens[idx]
        span_start = tok.start if start is None else start
        end = tok.end
        count = words + 1
        while count < 5 and self.text[end : end + 1] == " ":
            pos = end + 1
            tv = self.tussen_at(pos)
            if tv is not None:
                tv_end, tv_words = tv
                if count + tv_words + 1 > 5:
                    break
                nxt = self.tokens[self.by_start[tv_end + 1]]
                end = nxt.end
                count += tv_words + 1
                continue
            j = self.token_at(pos)
            if j is None or not self.name_ok(self.tokens[j]):
                break
            end = self.tokens[j].end
            count += 1
        return span_start, end


def build_context(
    text: str, lexicon: Lexicon, titles: Iterable[str], known: Mapping[str, str]
) -> Context:
    """Tokenise once and compile the title regex for one `detect` call."""
    title_words = sorted(
        {t.lower().rstrip(".") for t in titles} | {t.rstrip(".") for t in SPELLED_TITLES},
        key=lambda w: (-len(w), w),
    )
    title_re = re.compile(
        r"(?<!\w)(?:"
        + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in title_words)
        + r")\.?\s+",
        re.IGNORECASE,
    )
    tokens = tuple(Token(m.start(), m.end(), m.group()) for m in TOKEN_RE.finditer(text))
    single = frozenset(w for w in title_words if " " not in w and "." not in w)
    return Context(
        text=text,
        lexicon=lexicon,
        titles=single,
        title_re=title_re,
        known=known,
        tokens=tokens,
        by_start={tok.start: i for i, tok in enumerate(tokens)},
        by_end={tok.end: i for i, tok in enumerate(tokens)},
        starts=[tok.start for tok in tokens],
    )


def _ordered(cands: Iterable[Candidate]) -> list[Candidate]:
    """Deterministic claim order inside one group: by start, longest first, then kind."""
    return sorted(set(cands), key=lambda c: (c[0], -(c[1] - c[0]), c[2]))


# -- the rules -----------------------------------------------------------------


def rule_identifier(ctx: Context) -> list[Candidate]:
    """D01: Dutch IBAN, Dutch VAT, generic IBAN, Dutch mobile - in that claim order."""
    out: list[Candidate] = []
    for pattern, kind in (
        (IBAN_NL, "IBAN"),
        (BTW_NL, "VAT"),
        (IBAN_GENERIC, "IBAN"),
        (MOBILE_NL, "PHONE"),
    ):
        out += _ordered((m.start(), m.end(), kind) for m in pattern.finditer(ctx.text))
    return out


def rule_email(ctx: Context) -> list[Candidate]:
    """D02: the whole email address; the local part is never a name source."""
    return _ordered((m.start(), m.end(), "EMAIL") for m in EMAIL.finditer(ctx.text))


def _run_word(tok: Token, ctx: Context) -> bool:
    t = tok.text
    return not ctx.touches_id(tok) and (is_titlecase(t) or (t.isupper() and t.isalpha()))


def rule_company_form(ctx: Context) -> list[Candidate]:
    """D03: 1-5 capitalised words directly before a legal form, on one line -> COMPANY."""
    text = ctx.text
    out: list[Candidate] = []
    for m in _LEGAL_RE.finditer(text):
        # Walk left over word tokens (and `&`, `-`, and particles followed by a
        # run word), separated by spaces or tabs only.
        words: list[Token] = []
        pos = m.start()
        while len(words) < 5:
            gap_end = pos
            while pos > 0 and text[pos - 1] in " \t":
                pos -= 1
            if pos == gap_end:
                break  # the form (or previous word) is not preceded by a space
            # Skip a standalone `&` or `-` connector.
            if pos > 0 and text[pos - 1] in "&-" and (pos < 2 or text[pos - 2] in " \t"):
                pos -= 1
                if not words:
                    break  # a connector directly before the form ends the run
                continue
            prev = _token_ending_at(ctx, pos)
            if prev is None:
                break
            tok = ctx.tokens[prev]
            if _run_word(tok, ctx):
                words.insert(0, tok)
                pos = tok.start
                continue
            if words and is_tussenvoegsel(tok.text) and tok.text.islower():
                words.insert(0, tok)
                pos = tok.start
                continue
            break
        # A run never starts with a particle or a connector.
        while words and not _run_word(words[0], ctx):
            words.pop(0)
        if not words:
            continue
        lead = words[0]
        if (
            len(words) >= 3
            and at_start(text, lead.start, ".!?")
            and ctx.lexicon.is_word(lead.text)
            and not ctx.lexicon.is_name(lead.text)
        ):
            words.pop(0)
            while words and not _run_word(words[0], ctx):
                words.pop(0)
        if words:
            out.append((words[0].start, m.end(), COMPANY))
    return _ordered(out)


def _token_ending_at(ctx: Context, pos: int) -> int | None:
    # Tokens never overlap, so at most one ends at `pos` (review finding L2:
    # a dict lookup, not a scan from the end of the text).
    return ctx.by_end.get(pos)


# The leading word-character run of a key value: D04's index key.
_LEAD_RE = re.compile(r"\w+")


@dataclass(frozen=True)
class KeyMatcher:
    """D04's matcher for one key content, built once and cached (review finding H2).

    `by_lead` maps a value's leading `\\w+` run to its (value, kind) pairs;
    `odd` holds the rare values that start with a non-word character, each
    with its own compiled pattern.
    """

    by_lead: Mapping[str, tuple[tuple[str, str], ...]]
    odd: tuple[tuple[str, str, re.Pattern[str]], ...]


@functools.lru_cache(maxsize=8)
def key_matcher(items: frozenset[tuple[str, str]]) -> KeyMatcher:
    """The D04 matcher for a key's (value, kind) pairs; cached per key content."""
    return _build_matcher(items)


def _build_matcher(items: Iterable[tuple[str, str]]) -> KeyMatcher:
    by_lead: dict[str, list[tuple[str, str]]] = {}
    odd: list[tuple[str, str, re.Pattern[str]]] = []
    for value, kind in sorted(items):
        m = _LEAD_RE.match(value)
        if m is None:
            odd.append((value, kind, re.compile(r"(?<!\w)" + re.escape(value) + r"(?!\w)")))
        else:
            by_lead.setdefault(m.group(), []).append((value, kind))
    return KeyMatcher({k: tuple(v) for k, v in by_lead.items()}, tuple(odd))


def key_items(known: Mapping[str, str]) -> frozenset[tuple[str, str]]:
    """The (value, kind) pairs D04 uses: PERSON/COMPANY, at least two characters, not blank."""
    return frozenset(
        (v, k) for v, k in known.items() if k in (PERSON, COMPANY) and len(v) >= 2 and v.strip()
    )


def rule_key(ctx: Context) -> list[Candidate]:
    """D04: values the key already holds (PERSON/COMPANY), case-exact, whole-word.

    Claim order is the longest value first, then the value, then the kind,
    then the position: exactly the order of one regex per value, longest
    first, without compiling one regex per value per call.
    """
    items = key_items(ctx.known)
    if not items:
        return []
    return _match_all(ctx.text, key_matcher(items))


def _match_all(text: str, matcher: KeyMatcher) -> list[Candidate]:
    """Every case-exact, whole-word hit of the matcher's values: longest value first,
    then value, kind and position (the order of one regex per value, longest first)."""
    hits: list[tuple[str, str, int]] = []
    for m in _LEAD_RE.finditer(text):
        for value, kind in matcher.by_lead.get(m.group(), ()):
            end = m.start() + len(value)
            if text.startswith(value, m.start()) and (end == len(text) or not _is_w(text[end])):
                hits.append((value, kind, m.start()))
    for value, kind, pattern in matcher.odd:
        hits += [(value, kind, h.start()) for h in pattern.finditer(text)]
    hits.sort(key=lambda h: (-len(h[0]), h[0], h[1], h[2]))
    return [(p, p + len(v), k) for v, k, p in hits]


def _is_w(c: str) -> bool:
    """True if `c` is a regex word character (the `\\w` of `(?!\\w)`)."""
    return c.isalnum() or c == "_"


def _after_initials(text: str, pos: int) -> int:
    """The position after a run of initials at `pos` ("K. ", "K.L. "), or `pos` if none.

    An initial is one uppercase letter directly followed by `.`, then at most
    one space ("R.Surname" glued is an initial too); the caller still needs a
    name token right after the run. Only used right after a title, where an initial is part of the
    name ("Dhr. K. Surname"): without this, the `.` ends the name sequence at
    the bare letter, and that one-letter value, once in the key, is matched by
    D04 as every lone capital letter in later texts.
    """
    cur = pos
    while (
        cur + 1 < len(text)
        and text[cur].isupper()
        and text[cur + 1] == "."
        and (cur == pos or not text[cur - 1].isalpha())
    ):
        cur += 2
        if text[cur : cur + 1] == " ":
            cur += 1
    return cur


def _person_value_ok(ctx: Context, start: int, end: int) -> bool:
    """D05/D06's guard on a PERSON value (review finding M4).

    A one-token value of fewer than two letters (`J`), or one token that is a
    common word and not a name (`Klantenservice`), is refused: once in the key,
    D04 would mask that letter or word in every later text.
    """
    tokens = TOKEN_RE.findall(ctx.text, start, end)
    if len(tokens) != 1:
        return True
    tok = tokens[0]
    if sum(c.isalpha() for c in tok) < 2:
        return False
    return not (ctx.lexicon.is_word(tok) and not ctx.lexicon.is_name(tok))


def rule_honorific(ctx: Context) -> list[Candidate]:
    """D05: a title, optional `.`, whitespace, then a name -> PERSON over the name only.

    Initials between the title and the name belong to the name ("Mw. K. Surname"
    -> "K. Surname"); initials with no name after them leave the old behaviour.
    """
    out: list[Candidate] = []
    for m in ctx.title_re.finditer(ctx.text):
        pos = m.end()
        name_pos = _after_initials(ctx.text, pos)
        if name_pos != pos:
            j = ctx.token_at(name_pos)
            if j is not None and ctx.name_ok(ctx.tokens[j]):
                out.append((pos, ctx.sequence(j)[1], PERSON))
                continue
            tv = ctx.tussen_at(name_pos)
            if tv is not None:
                tv_end, tv_words = tv
                _, e = ctx.sequence(ctx.by_start[tv_end + 1], start=name_pos, words=tv_words)
                out.append((pos, e, PERSON))
                continue
        idx = ctx.token_at(pos)
        if idx is not None and ctx.name_ok(ctx.tokens[idx]):
            s, e = ctx.sequence(idx)
            out.append((s, e, PERSON))
            continue
        tv = ctx.tussen_at(pos)
        if tv is not None:
            tv_end, tv_words = tv
            s, e = ctx.sequence(ctx.by_start[tv_end + 1], start=pos, words=tv_words)
            out.append((s, e, PERSON))
    return _ordered(c for c in out if _person_value_ok(ctx, c[0], c[1]))


def rule_header(ctx: Context) -> list[Candidate]:
    """D06: the display name on an email header line -> PERSON (COMPANY if a legal form ends it)."""
    text = ctx.text
    out: list[Candidate] = []
    for m in _HEADER_RE.finditer(text):
        seg_start = m.start("rest")
        rest = m.group("rest")
        offset = 0
        for segment in re.split(r"[,;]", rest):
            base = seg_start + offset
            offset += len(segment) + 1
            cut = len(segment)
            lt = segment.find("<")
            if lt != -1:
                cut = lt
            em = EMAIL.search(segment)
            if em is not None:
                cut = min(cut, em.start())
            display_end = base + cut
            idx = _first_token_from(ctx, base, display_end)
            while idx is not None and ctx.is_title(ctx.tokens[idx].text):
                idx = _first_token_from(ctx, ctx.tokens[idx].end, display_end)
            if idx is None or not ctx.name_ok(ctx.tokens[idx]):
                continue
            s, e = ctx.sequence(idx)
            if e > display_end:
                continue
            form = _LEGAL_RE.match(text, e + 1) if text[e : e + 1] == " " else None
            if form is not None and form.end() <= display_end:
                out.append((s, form.end(), COMPANY))
            elif _person_value_ok(ctx, s, e):
                out.append((s, e, PERSON))
    return _ordered(out)


def _first_token_from(ctx: Context, lo: int, hi: int) -> int | None:
    """The first token starting in [lo, hi), by bisect over the start offsets."""
    i = bisect.bisect_left(ctx.starts, lo)
    if i < len(ctx.starts) and ctx.starts[i] < hi:
        return i
    return None


def rule_name_lexicon(ctx: Context) -> list[Candidate]:
    """D07: a strong name (a name, not a word), or two adjacent names -> PERSON."""
    lex = ctx.lexicon
    out: list[Candidate] = []
    for i, tok in enumerate(ctx.tokens):
        if not ctx.name_ok(tok) or not lex.is_name(tok.text):
            continue
        if not lex.is_word(tok.text):
            out.append((*ctx.sequence(i), PERSON))
            continue
        if sentence_initial(ctx.text, tok.start):
            continue  # a sentence-initial common word never starts a pair
        nxt = ctx.token_at(tok.end + 1) if ctx.text[tok.end : tok.end + 1] == " " else None
        if nxt is not None and ctx.name_ok(ctx.tokens[nxt]) and lex.is_name(ctx.tokens[nxt].text):
            out.append((*ctx.sequence(i), PERSON))
    return _ordered(out)


def rule_echo(ctx: Context) -> list[Candidate]:
    """D08: a person found in THIS text by D04-D07, found again elsewhere -> PERSON."""
    text = ctx.text
    needles: set[str] = set()
    for s, e, _source in ctx.persons:
        value = text[s:e]
        needles.add(value)
        if sum(c.isalpha() for c in value) >= 3:
            needles.add(value.upper())  # a signature in capitals (review finding L1)
        parts = [m.group() for m in TOKEN_RE.finditer(value)]
        for part in parts:
            if len(part) >= 3 and is_titlecase(part) and not is_tussenvoegsel(part):
                needles.add(part)
        if parts:
            low = parts[0].lower()
            if low != parts[0] and not ctx.lexicon.is_word(low):
                needles.add(low)
    return _ordered(_whole_word(text, needles, PERSON))


def rule_outlier(ctx: Context) -> list[Candidate]:
    """D09: an unknown capitalised word mid-sentence, not vetoed -> PERSON, queued for review."""
    lex = ctx.lexicon
    out: list[Candidate] = []
    for i, tok in enumerate(ctx.tokens):
        if (
            len(tok.text) >= 3
            and ctx.name_ok(tok)
            and not sentence_initial(ctx.text, tok.start)
            and not lex.is_word(tok.text)
            and not lex.is_name(tok.text)
        ):
            out.append((*ctx.sequence(i), PERSON))
    return _ordered(out)


def _whole_word(text: str, needles: Iterable[str], kind: str) -> list[Candidate]:
    """Every case-exact, whole-word hit of `needles`, in one pass over the text."""
    return _match_all(text, _build_matcher((n, kind) for n in needles if n))


def company_echo(ctx: Context) -> list[Candidate]:
    """D03 follow-up: each D03 company name without its legal form, again in this text.

    Case-exact and whole-word, as COMPANY (review finding M1). Only a name of
    two or more words, or of one word of at least two letters that is not a
    common word.
    """
    text = ctx.text
    needles: set[str] = set()
    for s, e in ctx.companies:
        form = None
        for form in _LEGAL_RE.finditer(text, s, e):
            pass
        if form is None or form.end() != e:
            continue
        name = text[s : form.start()].rstrip(" \t")
        words = TOKEN_RE.findall(name)
        if len(words) >= 2 or (
            len(words) == 1
            and name == words[0]
            and len(name) >= 2
            and not ctx.lexicon.is_word(name)
        ):
            needles.add(name)
    return _ordered(_whole_word(text, needles, COMPANY))


def outlier_echo(ctx: Context) -> list[Candidate]:
    """D09 follow-up: each full D09 value again in this text, case-exact, whole-word.

    Catches the same unknown word where D09 never looks, at the start of a
    sentence (review finding H1). Only the full value: never its parts, never
    a lowercase form.
    """
    needles = {ctx.text[s:e] for s, e in ctx.outliers}
    return _ordered(_whole_word(ctx.text, needles, PERSON))


# Follow-ups: run right after the named rule, under that rule's id.
FOLLOW_UPS: dict[str, Callable[[Context], list[Candidate]]] = {
    "company_form": company_echo,
    "outlier": outlier_echo,
}

RULES: dict[str, Callable[[Context], list[Candidate]]] = {
    "identifier": rule_identifier,
    "email": rule_email,
    "company_form": rule_company_form,
    "key": rule_key,
    "honorific": rule_honorific,
    "header": rule_header,
    "name_lexicon": rule_name_lexicon,
    "echo": rule_echo,
    "outlier": rule_outlier,
}

# The rules whose PERSON spans the echo rule repeats (never the outlier rule).
ECHO_SOURCES: frozenset[str] = frozenset({"key", "honorific", "header", "name_lexicon"})

assert tuple(RULES) == ALL_RULES, "rules.RULES must follow types.ALL_RULES"

__all__ = [
    "ECHO_SOURCES",
    "FOLLOW_UPS",
    "HEADER_LABELS",
    "LEGAL_FORMS",
    "PAYMENT_PROCESSORS",
    "PLATFORM_BRANDS",
    "RULES",
    "SPELLED_TITLES",
    "TOKEN_RE",
    "TUSSENVOEGSELS",
    "VETOES",
    "Candidate",
    "Context",
    "Detected",
    "build_context",
    "company_echo",
    "is_titlecase",
    "is_tussenvoegsel",
    "key_items",
    "key_matcher",
    "outlier_echo",
    "sentence_initial",
]
