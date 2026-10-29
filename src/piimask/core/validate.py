"""
Pseudonymization Leak Validator

WHAT THIS IS FOR
----------------
This is the gate between your accounting data and an AI model. It scans a
pseudonymized database and refuses to certify it if any personal data
survived. Nothing should be sent to an LLM until this exits 0.

It is deliberately dependency-light (stdlib + optional PyYAML) so it can be
handed to another Moneybird user and run on their own machine, against their
own data, without installing this project. The one exception is an
ENCRYPTED key file (the format MappingStore writes): opening it needs the
piimask package with `cryptography`, imported only at that moment. Without a
key, or with an old plaintext JSON key, nothing beyond the stdlib is loaded.

THE FIVE CHECKS
---------------
1. KNOWN-VALUE LEAK (critical, zero false positives)
   The mapping file records every real value we replaced. If any of those
   strings still appears verbatim anywhere in the output, that is proven
   leakage - not a heuristic guess. This is the strongest check available
   and the reason the mapping is worth loading here. A value the free-text
   regex learned (it may be a product name rather than a person) blocks too:
   over-masking a product name is the accepted cost (decided 21 Oct).

2. PII COLUMN COVERAGE (critical)
   Every column the manifest classifies as PII must contain pseudonyms
   (PREFIX_123456) - at least `required_pseudonym_ratio` of its values, 1.0
   by default. This is what would have caught the
   sales_invoices.contact_name failure: the column still held real names.

3. PATTERN SCAN (critical / high)
   IBANs, email addresses, BTW and mobile numbers anywhere in any text
   column, regardless of what the manifest claims. Defence in depth: catches
   PII that arrived in a column nobody expected it in.

   Checks 1 and 3 also read the schema itself: every `sqlite_master.sql`
   text (tables, views, triggers, indexes). A view's WHERE, a trigger body,
   a CHECK or DEFAULT literal is stored in the file verbatim and travels with
   it; a hit there is CRITICAL at location `schema:<object name>`.

4. NAME HEURISTIC (medium, advisory)
   Dutch honorifics and tussenvoegsel name shapes in free text. Noisy by
   nature, so it never fails the run on its own - it flags text for review.

5. RAW-FILE RESIDUE (critical)
   SQL only sees live rows. A database that was copied and then updated in
   place still holds the replaced values in its free pages, and a leftover
   journal holds whole pages of the original. So the file's raw bytes (and
   any -journal / -wal / -shm sidecar beside it) are searched for every
   indexed known value. A value found there that no live row holds is
   residue. Schema text does not count as live: a known value written only
   into a view, trigger or CHECK is a finding here too. The comparison is
   case- and accent-insensitive (`fold` on decoded text, in the
   file's own text encoding), so a key value starting with an E-acute
   matches its capitalised form in the bytes.
   Known limit: a value that also lives on inside a live value
   (say a street name that contains it) is left to check 1, which already
   sees that live value.

No column is skipped without a word: a column the scan cannot read, and any
BLOB value, is named in the report (C41).

EXIT CODES
----------
    0  PASS - no critical or high findings. Safe to release.
    1  FAIL - leakage found. Do not send this data anywhere.
    2  ERROR - could not complete the scan (missing file, unreadable DB,
       unreadable key, unusable manifest).

PRIVACY NOTE
------------
This tool never prints a personal data value. Findings are reported as
location + count + a redacted preview, so the report itself stays shareable.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:  # portable mode: pattern + known-value checks still run
    _HAS_YAML = False

# The free-text shapes are shared with the pseudonymiser (one source, so the
# two cannot drift). patterns.py and errors.py import only stdlib, so this
# stays stdlib-only.
try:
    from piimask.core import patterns as _patterns
    from piimask.core.errors import MappingUnreadableError
except ImportError:  # handed over as loose files: validate.py + patterns.py + errors.py
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    import patterns as _patterns  # type: ignore[no-redef]

    try:
        from errors import MappingUnreadableError  # type: ignore[no-redef]
    except ImportError:  # validate.py + patterns.py only

        class MappingUnreadableError(Exception):  # type: ignore[no-redef]
            """A pseudonym key exists but cannot be read or parsed."""


def _looks_encrypted(raw: bytes) -> bool:
    """True when `raw` starts with the encrypted key's header line (CP3)."""
    first, sep, _ = raw.partition(b'\n')
    if not sep:
        return False
    try:
        header = json.loads(first.decode('ascii'))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(header, dict) and header.get('format') == 'piimask-mapping'


class ManifestError(ValueError):
    """
    The PII manifest cannot be used as given: unreadable, PyYAML missing for
    a manifest the caller named, or a validation setting with a value the
    validator refuses (e.g. forbid_known_original_values: false).

    The scan is refused (exit 2) rather than run with a quietly weaker rule.
    """


# ----------------------------------------------------------------------
# Severity
# ----------------------------------------------------------------------

CRITICAL = 'CRITICAL'
HIGH = 'HIGH'
MEDIUM = 'MEDIUM'

# Findings at these levels block release
BLOCKING = {CRITICAL, HIGH}

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}


# ----------------------------------------------------------------------
# Detection patterns
# ----------------------------------------------------------------------

# A well-formed pseudonym produced by UnifiedPseudonymizer
PSEUDONYM_RE = re.compile(r'^[A-Z]+_\d{6,}$')

# Pseudonymized email keeps its real domain: EMAIL_001234@klant.nl
PSEUDO_EMAIL_RE = re.compile(r'^[A-Z]+_\d{6,}@')

# A pseudonym after _normalize(): "PERSON_001858" -> "person 001858".
# Matching on the normalised form catches every case and punctuation variant.
NORMALIZED_PSEUDONYM_RE = re.compile(r'^[a-z]+ \d{6,}$')

# Word separators for _normalize: anything that is not a letter or digit in
# any script. str patterns are Unicode-aware, so accented letters stay in.
_NON_WORD_RE = re.compile(r'[\W_]+')


def fold(text: str) -> str:
    """
    The one case-and-accent fold every comparison uses (R2/R8, CP2 review):
    casefold, NFKD, then drop combining marks. "Édwyn", "EDWYN" and "edwyn"
    fold equal - a name written without its accent is still that person
    (when in doubt, refuse). Letters that are not decomposable (Ø, ß after
    casefold becomes ss) keep their own form.
    """
    folded = unicodedata.normalize('NFKD', str(text).casefold())
    if folded.isascii():
        return folded
    # Strip only the marks actually present: a class of every combining mark
    # Unicode knows is ~2x slower over a 20 MB file than a set() pass plus a
    # small class.
    marks = sorted(c for c in set(folded) if unicodedata.combining(c))
    if not marks:
        return folded
    return re.sub('[' + ''.join(map(re.escape, marks)) + ']+', '', folded)

PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    (
        # Dutch IBAN, exact 18 chars. No trailing \b: bank messages glue
        # IBANs to following text ("NL37BUNQ0123456789TRTPSEPA"), and a
        # boundary-anchored pattern silently misses every one of those.
        'iban_nl',
        _patterns.IBAN_NL,
        CRITICAL,
        'Dutch bank account number (IBAN)',
    ),
    (
        'iban',
        _patterns.IBAN_GENERIC,
        CRITICAL,
        'Bank account number (IBAN)',
    ),
    (
        'email',
        _patterns.EMAIL,
        CRITICAL,
        'Email address',
    ),
    (
        'btw',
        _patterns.BTW_NL,
        HIGH,
        'Dutch VAT number (BTW-nummer)',
    ),
    (
        'phone_nl',
        _patterns.MOBILE_NL,
        HIGH,
        'Dutch mobile number',
    ),
    (
        'dutch_name',
        re.compile(
            r'\b(?:Mw|Mevr|Dhr|Hr|Mr|Mrs|Ms|Dr|Ing|Drs)\.?\s+'
            r'[A-Z][a-z]+(?:\s+(?:de|van|der|den|te|ter|ten|von|het)\b)*'
        ),
        MEDIUM,
        'Dutch honorific followed by a name',
    ),
]

# Sidecar files SQLite may leave beside a database. Validating
# "x.db.partial" covers "x.db.partial-journal" the same way.
SIDECAR_SUFFIXES = ('-journal', '-wal', '-shm')

# Text encoding byte in the SQLite header (offset 56): 1 UTF-8, 2 UTF-16le,
# 3 UTF-16be. The raw-byte search encodes known values the same way.
_HEADER_ENCODINGS = {1: 'utf-8', 2: 'utf-16-le', 3: 'utf-16-be'}


def quote_ident(name: str) -> str:
    """Quote an SQLite identifier: a space or a double quote in a table or
    column name must neither break nor skip the scan (C41)."""
    return '"' + str(name).replace('"', '""') + '"'


# ----------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------

@dataclass
class Finding:
    """One category of leak, aggregated across rows."""

    severity: str
    check: str
    location: str
    count: int
    description: str
    sample: str = ''

    def format(self) -> str:
        line = f"  [{self.severity:8}] {self.location}"
        line += f"\n             {self.description}"
        line += f"\n             affected values: {self.count}"
        if self.sample:
            line += f"\n             example (redacted): {self.sample}"
        return line


@dataclass
class SkippedColumn:
    """A column (or part of one) the SQL checks could not read as text."""

    location: str   # "table.column"
    reason: str     # "unreadable" | "blob"
    count: int = 0  # values affected (0 when the column could not be read at all)
    detail: str = ''


@dataclass
class ValidationResult:
    """Outcome of a full scan."""

    database: str = ''
    findings: list[Finding] = field(default_factory=list)
    tables_scanned: int = 0
    columns_scanned: int = 0
    values_scanned: int = 0
    known_values_loaded: int = 0
    manifest_used: bool = False
    # False only when PyYAML is missing: the coverage check and the
    # stopwords could not run.
    yaml_available: bool = True
    # Columns, or BLOB values in them, the text checks could not read
    # directly. Each also has a finding; this list is the plain inventory.
    skipped_columns: list[SkippedColumn] = field(default_factory=list)
    # Files the raw-residue check (check 5) read: the DB plus any sidecar.
    raw_files_scanned: list[str] = field(default_factory=list)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in BLOCKING]

    @property
    def advisory(self) -> list[Finding]:
        return [f for f in self.findings if f.severity not in BLOCKING]

    @property
    def passed(self) -> bool:
        return not self.blocking

    def _mode_lines(self) -> list[str]:
        """Loud lines for every check that did not run."""
        if not self.yaml_available:
            return [
                "!! PYYAML IS NOT INSTALLED: THE MANIFEST WAS NOT READ, SO THE",
                "!! PII-COLUMN COVERAGE CHECK AND THE STOPWORDS DID NOT RUN.",
                "!! Only the known-value, pattern and raw-file checks ran.",
                "",
            ]
        if not self.manifest_used:
            return [
                "!! NO MANIFEST GIVEN: THE PII-COLUMN COVERAGE CHECK AND THE",
                "!! STOPWORDS DID NOT RUN (pattern-only mode).",
                "",
            ]
        return []

    def format_report(self) -> str:
        lines = [
            "=" * 70,
            "PSEUDONYMIZATION LEAK VALIDATION",
            "=" * 70,
            f"Database:      {self.database}",
            f"Tables:        {self.tables_scanned}",
            f"Text columns:  {self.columns_scanned}",
            f"Values:        {self.values_scanned:,}",
            (f"Known values:  {self.known_values_loaded:,} "
             f"({'loaded from mapping' if self.known_values_loaded else 'NO MAPPING - weaker scan'})"),
            f"Manifest:      {'yes' if self.manifest_used else 'no (pattern-only mode)'}",
            f"Raw files:     {len(self.raw_files_scanned)} read byte for byte",
            "",
        ]
        lines += self._mode_lines()

        if self.skipped_columns:
            lines.append(f"NOT READ AS TEXT ({len(self.skipped_columns)}):")
            for skipped in self.skipped_columns:
                extra = f", {skipped.count} values" if skipped.count else ''
                lines.append(f"  {skipped.location} ({skipped.reason}{extra})")
            lines.append("")

        if not self.findings:
            lines += [
                "No findings.",
                "",
                "PASS - no personal data detected. Safe to release to an AI model.",
                "=" * 70,
            ]
            return "\n".join(lines)

        ordered = sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.count),
        )

        if self.blocking:
            lines.append(f"BLOCKING FINDINGS ({len(self.blocking)}):")
            lines.append("")
            for finding in ordered:
                if finding.severity in BLOCKING:
                    lines.append(finding.format())
                    lines.append("")

        if self.advisory:
            lines.append(f"ADVISORY FINDINGS ({len(self.advisory)}) - review, non-blocking:")
            lines.append("")
            for finding in ordered:
                if finding.severity not in BLOCKING:
                    lines.append(finding.format())
                    lines.append("")

        if self.passed:
            lines += [
                "PASS - no blocking findings. Review advisory items above.",
            ]
        else:
            lines += [
                "FAIL - personal data survived pseudonymization.",
                "",
                "DO NOT send this database to any AI model, cloud service or",
                "third party. Fix the classifications in config/pii_schema.yaml,",
                "re-run pseudonymization, then validate again.",
            ]
        lines.append("=" * 70)
        return "\n".join(lines)


# ----------------------------------------------------------------------
# Validator
# ----------------------------------------------------------------------

def redact(value: str, keep: int = 2) -> str:
    """
    Render a value safe to print in a report.

    Keeps enough of a prefix to locate the problem, never enough to
    identify a person.
    """
    text = str(value)
    if len(text) <= keep:
        return '*' * len(text)
    return text[:keep] + '*' * min(len(text) - keep, 12)


class PseudonymizationValidator:
    """
    Scans a pseudonymized database for surviving personal data.

    Usage:
        validator = PseudonymizationValidator(
            Path('data/moneybird_pseudo.db'),
            manifest_path=Path('config/pii_schema.yaml'),
            mapping=Path('secure/pseudonym_mapping.json'),
        )
        result = validator.validate()
        if not result.passed:
            raise SystemExit(result.format_report())

    Raises (from the constructor):
        MappingUnreadableError: a mapping path was given but the file is
            missing, unreadable or not a valid key (C40). Fail-closed: the
            caller asked for the known-value check, so a weaker scan without
            it is never run in its place.
        ManifestError: a manifest path was given but cannot be used (PyYAML
            missing, unreadable, invalid validation settings - C23/C42).
    """

    # A purely numeric original shorter than this is not searched for. Short
    # numbers collide with unrelated internal ids by coincidence: mapped value
    # "12345" appears inside primary key "123456789", which is not a leak.
    MIN_NUMERIC_LENGTH = 9

    # Upper bound on how many words a known value may span. Keeps the n-gram
    # sweep linear even when the mapping holds long company names.
    MAX_NGRAM = 6

    DEFAULT_MIN_KNOWN_LENGTH = 5

    def __init__(
        self,
        db_path: Path,
        *,
        manifest_path: Path | None,
        mapping: Any = None,
        min_known_length: int | None = None,
    ):
        """
        Args:
            db_path: The pseudonymised database to scan.
            manifest_path: The PII manifest. Required keyword: the caller
                names the file (C05/C72) - there is no search for one.
                Passing None explicitly means pattern-only mode (no coverage
                check, no stopwords).
            mapping: The pseudonym key for the known-value check: a
                MappingStore (library use - the encrypted key, CP3), or a
                path to a key file (the encrypted format is opened through
                MappingStore, imported only then; an old plaintext JSON key
                is read with the standard library alone), or None for a
                weaker scan without it.
            min_known_length: Shortest original searched for. None (default)
                takes validation.min_known_value_length from the manifest,
                else 5. An explicit value wins over the manifest.
        """
        self.db_path = Path(db_path)
        # A store is anything with load() and path (duck-typed, so this
        # module never imports mapping_store - or cryptography - for it).
        self._mapping_store = mapping if hasattr(mapping, 'load') else None
        if self._mapping_store is not None:
            self.mapping_path = Path(self._mapping_store.path)
        else:
            self.mapping_path = Path(mapping) if mapping else None
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self._explicit_min_known_length = min_known_length

        self.known_values: set[str] = set()
        self.manifest: dict[str, Any] = {}
        self.min_known_length: int = self.DEFAULT_MIN_KNOWN_LENGTH
        self.required_pseudonym_ratio: float = 1.0

        # Normalised n-gram index of known values, built once
        self._known_index: set[str] = set()
        self._max_ngram: int = 1
        self._stopwords: set[str] = set()
        # Normalised originals learned only from free-text regex capture
        self._freetext_only: set[str] = set()
        # Originals whose normalised form made it into the index: the raw
        # residue check searches these, byte for byte.
        self._indexed_originals: set[str] = set()

        # Manifest first: it supplies the stopwords and settings the index
        # depends on.
        self._load_manifest()
        self._apply_validation_settings()
        self._load_stopwords()
        self._load_known_values()
        self._build_known_index()

    def _load_stopwords(self) -> None:
        """
        Load single words that must not be treated as personal data.

        See config/pii_schema.yaml for why this is needed: the legacy
        mapping stores generic finance vocabulary as original values.
        """
        validation = (self.manifest.get('validation') or {})
        words = validation.get('known_value_stopwords') or []
        self._stopwords = {self._normalize(w) for w in words if str(w).strip()}

    def _apply_validation_settings(self) -> None:
        """
        Honour every `validation:` setting the manifest carries (C42).

        - min_known_value_length: shortest original searched for.
        - required_pseudonym_ratio: share of a PII column that must be
          pseudonyms (0.0 - 1.0).
        - forbid_known_original_values: only `true` is allowed. The
          known-value check is the zero-false-positive test; a manifest that
          switches it off is refused rather than honoured or ignored.
        """
        validation = self.manifest.get('validation') or {}
        if not isinstance(validation, dict):
            raise ManifestError(
                f"manifest {self.manifest_path}: 'validation' must be a mapping")

        if ('forbid_known_original_values' in validation
                and validation['forbid_known_original_values'] is not True):
            raise ManifestError(
                f"manifest {self.manifest_path}: forbid_known_original_values "
                "must be true - the known-value check cannot be switched off")

        length = validation.get('min_known_value_length')
        if length is not None:
            if isinstance(length, bool) or not isinstance(length, int) or length < 1:
                raise ManifestError(
                    f"manifest {self.manifest_path}: min_known_value_length must be "
                    "a whole number of at least 1")
            self.min_known_length = length

        ratio = validation.get('required_pseudonym_ratio')
        if ratio is not None:
            if (isinstance(ratio, bool) or not isinstance(ratio, (int, float))
                    or not 0.0 <= float(ratio) <= 1.0):
                raise ManifestError(
                    f"manifest {self.manifest_path}: required_pseudonym_ratio must be "
                    "a number from 0.0 to 1.0")
            self.required_pseudonym_ratio = float(ratio)

        if self._explicit_min_known_length is not None:
            self.min_known_length = self._explicit_min_known_length

    # -- known-value index ---------------------------------------------

    @staticmethod
    def _normalize(text: str) -> str:
        """
        Fold a string to comparable word tokens.

        Folds case and accents (`fold`) and reduces every run of non-word characters (and '_') to a
        single space, so "Mw. J. Jansen-de Vries" and "mw j jansen de vries"
        compare equal. Unicode-aware (R8, CP2 review): an accented letter is
        part of its word, so "Édwyn" becomes "edwyn" - never the shorter,
        different word "dwyn" - and matches "Edwyn" written without it. The index and the scanned text both go
        through here, so the two sides always fold the same way.
        """
        return _NON_WORD_RE.sub(' ', fold(text)).strip()

    def _build_known_index(self) -> None:
        """
        Index known values as normalised word n-grams.

        The naive approach - testing `known in value` for every pair - is
        O(values x mappings). With tens of thousands of mappings over tens of
        thousands of values that is hundreds of millions of substring scans,
        which took minutes. Indexing by
        n-gram turns each lookup into a set membership test, and gets word
        boundaries for free: "12345" no longer matches inside "123456789".
        """
        for original in self.known_values:
            normalized = self._normalize(original)
            if not normalized:
                continue

            # A legacy mapping may contain pseudonym -> pseudonym entries from
            # before pseudonymization was idempotent. Finding PERSON_001858 in
            # the output is correct behaviour, not a leak.
            #
            # Test the NORMALISED form, not the raw string: the database holds
            # case variants ("person_001858", "Person_001858") that an
            # uppercase-anchored regex silently lets through, which is exactly
            # how false positives survived the first attempt at this check.
            if NORMALIZED_PSEUDONYM_RE.match(normalized):
                continue

            # Drop short pure-digit values: they are internal ids, not PII,
            # and they generate the bulk of false positives.
            digits_only = normalized.replace(' ', '')
            if digits_only.isdigit() and len(digits_only) < self.MIN_NUMERIC_LENGTH:
                continue

            tokens = normalized.split()
            token_count = len(tokens)
            if token_count > self.MAX_NGRAM:
                continue

            # Suppress single generic words only. A multi-word value that
            # merely contains one ("Jansen Accounting") is still indexed.
            if token_count == 1 and normalized in self._stopwords:
                continue

            self._known_index.add(normalized)
            self._indexed_originals.add(original)
            self._max_ngram = max(self._max_ngram, token_count)

        self._max_ngram = min(self._max_ngram, self.MAX_NGRAM)

    def _find_known_value(self, value: str) -> str | None:
        """
        Return the first known original found in `value`, or None.

        Sweeps every word n-gram up to the longest indexed known value.
        Cost is O(tokens x MAX_NGRAM) set lookups per value.
        """
        if not self._known_index:
            return None

        tokens = self._normalize(value).split()
        if not tokens:
            return None

        total = len(tokens)
        for size in range(1, min(self._max_ngram, total) + 1):
            for start in range(total - size + 1):
                candidate = ' '.join(tokens[start:start + size])
                if candidate in self._known_index:
                    return candidate
        return None

    # -- setup ---------------------------------------------------------

    def _load_known_values(self) -> None:
        """
        Load the original values we replaced, for the verbatim leak check.

        Short values are skipped: a two-letter original like "BV" would
        match everywhere and drown the report in noise.

        Fail-closed (C40): when a mapping path is given, it must be read.
        A missing file, a permission error or broken JSON raises
        MappingUnreadableError - never a silent drop to a weaker scan. The
        message names the path only, never the contents.
        """
        if not self.mapping_path:
            return

        # lexists: a dangling symlink is an unreachable key, opened below so
        # the store says so - not "not found" (K1).
        if not os.path.lexists(self.mapping_path):
            raise MappingUnreadableError(
                f"pseudonym key not found: {self.mapping_path} - the known-value "
                "check was asked for and cannot run")

        data = self._read_key()

        forward = data.get('forward') if isinstance(data, dict) else None
        derived = data.get('freetext_derived') if isinstance(data, dict) else None
        if not isinstance(forward, dict) or not isinstance(derived, (list, type(None))):
            raise MappingUnreadableError(
                f"pseudonym key malformed: {self.mapping_path} (no 'forward' table)")

        self._freetext_only = {self._normalize(v) for v in (derived or [])}

        for original in forward:
            text = str(original).strip()
            if len(text) >= self.min_known_length:
                self.known_values.add(text)

    def _read_key(self) -> Any:
        """The key's data, from the store or the file. Fail-closed throughout.

        An encrypted key (CP3) is opened through MappingStore, imported here
        and only here, so the stdlib-only mode (C23/C71) holds whenever no
        encrypted key is in play. An old plaintext JSON key is read with the
        standard library (tools/name_sweep.py hands the validator one).
        """
        if self._mapping_store is not None:
            return self._mapping_store.load()

        try:
            with open(self.mapping_path, 'rb') as f:
                raw = f.read()
        except OSError as exc:
            raise MappingUnreadableError(
                f"pseudonym key unreadable: {self.mapping_path} "
                f"({type(exc).__name__})") from None

        if _looks_encrypted(raw):
            try:
                from piimask.core.mapping_store import MappingStore
            except ImportError:
                raise MappingUnreadableError(
                    f"pseudonym key is encrypted: {self.mapping_path} - opening it "
                    "needs the piimask package with 'cryptography' installed") from None
            self._mapping_store = MappingStore(self.mapping_path)
            return self._mapping_store.load()

        try:
            return json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as exc:
            raise MappingUnreadableError(
                f"pseudonym key unreadable: {self.mapping_path} "
                f"({type(exc).__name__})") from None

    def _load_manifest(self) -> None:
        """
        Load the PII manifest the caller named.

        No manifest named = pattern-only mode, said loudly in the report.
        A manifest named but unusable is refused (ManifestError, exit 2):
        a missing file, broken YAML, or PyYAML not installed (C23) - the
        caller asked for the coverage check and would otherwise not get it.
        """
        path = self.manifest_path
        if path is None:
            return

        if not _HAS_YAML:
            raise ManifestError(
                f"manifest {path} given, but PyYAML is not installed - the coverage "
                "check and the stopwords cannot run. Install PyYAML, or run "
                "without --manifest for the pattern-only scan.")

        if not path.exists():
            raise ManifestError(f"manifest not found: {path}")

        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded = yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
            raise ManifestError(
                f"manifest unreadable: {path} ({type(exc).__name__})") from None

        if not isinstance(loaded, dict):
            raise ManifestError(f"manifest {path} is not a mapping")
        self.manifest = loaded

    def _declared_pii_columns(self) -> dict[str, dict[str, str]]:
        """{table: {column: classification}} from the manifest."""
        result: dict[str, dict[str, str]] = {}
        for table, spec in (self.manifest.get('tables') or {}).items():
            columns = ((spec or {}).get('columns') or {})
            pii = {
                col: cls for col, cls in columns.items()
                if cls not in ('safe',)
            }
            if pii:
                result[table] = pii
        return result

    # -- scanning ------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        """Open the DB read-only: the scan must never change what it judges."""
        uri = self.db_path.resolve().as_uri() + '?mode=ro'
        return sqlite3.connect(uri, uri=True)

    def validate(self) -> ValidationResult:
        """Run every check and return an aggregated result."""
        result = ValidationResult(
            database=str(self.db_path),
            known_values_loaded=len(self.known_values),
            manifest_used=bool(self.manifest),
            yaml_available=_HAS_YAML,
        )

        # Raw bytes FIRST, before SQLite opens the file: opening can roll a
        # hot journal back into the DB and delete the very sidecar check 5
        # needs to read.
        raw_files = self._read_raw_files()
        result.raw_files_scanned = [str(p) for p, _ in raw_files]

        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
            tables = [row[0] for row in cursor.fetchall()]
            result.tables_scanned = len(tables)

            declared = self._declared_pii_columns()

            for table in tables:
                cursor.execute(f"PRAGMA table_info({quote_ident(table)})")
                columns = [row[1] for row in cursor.fetchall()]

                for column in columns:
                    classification = declared.get(table, {}).get(column)
                    location = f"{table}.{column}"

                    fetched = self._text_values(cursor, table, column)
                    if fetched.error is not None:
                        result.skipped_columns.append(SkippedColumn(
                            location, 'unreadable', 0, fetched.error))
                        result.findings.append(Finding(
                            severity=CRITICAL if classification else HIGH,
                            check='column_unreadable',
                            location=location,
                            count=0,
                            description=(
                                f"Column could not be read ({fetched.error}); "
                                "the scan cannot vouch for what it holds."
                                + (f" Declared as PII ('{classification}')."
                                   if classification else '')
                            ),
                        ))
                        continue

                    if fetched.blobs:
                        result.skipped_columns.append(SkippedColumn(
                            location, 'blob', len(fetched.blobs)))
                        result.findings.append(self._blob_finding(
                            location, classification, len(fetched.blobs)))

                    if fetched.texts is None:
                        continue

                    values = fetched.texts
                    result.columns_scanned += 1
                    result.values_scanned += len(values)

                    # Check 2: declared PII columns must hold pseudonyms.
                    # Only the real text values: a BLOB is never a pseudonym
                    # and is judged by its own finding above.
                    if classification and classification != 'freetext' and fetched.strings:
                        finding = self._check_pseudonym_coverage(
                            table, column, classification, fetched.strings
                        )
                        if finding:
                            result.findings.append(finding)

                    # Check 1: verbatim known-value leak
                    result.findings.extend(
                        self._check_known_values(table, column, values)
                    )

                    # Checks 3 & 4: pattern scans
                    result.findings.extend(
                        self._check_patterns(table, column, values, classification)
                    )

            # Checks 1 & 3 over the schema text itself (R1, CP2 review)
            result.findings.extend(self._check_schema(cursor))

            # Check 5: raw-file residue
            result.findings.extend(self._check_raw_residue(conn, raw_files))
        finally:
            conn.close()

        return result

    @staticmethod
    def _blob_finding(location: str, classification: str | None, count: int) -> Finding:
        if classification:
            return Finding(
                severity=CRITICAL,
                check='pii_column_blob',
                location=location,
                count=count,
                description=(
                    f"Declared as PII ('{classification}') but holds {count} BLOB "
                    "value(s). A pseudonym is text; a BLOB here is unprocessed data."
                ),
            )
        return Finding(
            severity=MEDIUM,
            check='blob_values',
            location=location,
            count=count,
            description=(
                f"Holds {count} BLOB value(s). They were decoded as UTF-8 and "
                "scanned with the text checks; review what they are."
            ),
        )

    @dataclass
    class _Fetched:
        texts: list[str] | None = None    # every value to scan, BLOBs decoded
        strings: list[str] = field(default_factory=list)  # real TEXT values only
        blobs: list[bytes] = field(default_factory=list)
        error: str | None = None

    @classmethod
    def _text_values(
        cls, cursor: sqlite3.Cursor, table: str, column: str
    ) -> PseudonymizationValidator._Fetched:
        """
        Fetch non-null values from a column.

        Numeric-only columns cannot carry a name or an IBAN, so `texts` is
        None for them and the text checks skip them. Nothing else is dropped
        (C41): BLOB values are returned (and decoded as UTF-8 for the text
        checks), and a column whose SELECT fails comes back with `error` set
        so the caller reports it.
        """
        col = quote_ident(column)
        try:
            cursor.execute(
                f'SELECT {col} FROM {quote_ident(table)} '
                f"WHERE {col} IS NOT NULL AND CAST({col} AS TEXT) != ''"
            )
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            return cls._Fetched(error=type(exc).__name__)

        fetched = cls._Fetched()
        values: list[str] = []
        has_text = False
        for (raw,) in rows:
            if isinstance(raw, (bytes, bytearray)):
                fetched.blobs.append(bytes(raw))
                values.append(bytes(raw).decode('utf-8', errors='replace'))
                has_text = True
                continue
            if isinstance(raw, str):
                has_text = True
                fetched.strings.append(raw)
            values.append(str(raw))

        fetched.texts = values if has_text else None
        return fetched

    def _check_pseudonym_coverage(
        self, table: str, column: str, classification: str, values: list[str]
    ) -> Finding | None:
        """
        Values in a declared PII column must look like pseudonyms - at least
        `required_pseudonym_ratio` of them (manifest; 1.0 = every one).

        This is the check that catches silent no-ops: a column the manifest
        promises is protected, but which still holds raw values.
        """
        matcher = PSEUDO_EMAIL_RE if classification == 'email' else PSEUDONYM_RE
        unmapped = [v for v in values if not matcher.match(v)]

        if not unmapped:
            return None

        share = (len(values) - len(unmapped)) / len(values)
        if share >= self.required_pseudonym_ratio:
            return None

        return Finding(
            severity=CRITICAL,
            check='pii_column_coverage',
            location=f"{table}.{column}",
            count=len(unmapped),
            description=(
                f"Declared as PII ('{classification}') but {len(unmapped)} of "
                f"{len(values)} values are not pseudonyms (required share "
                f"{self.required_pseudonym_ratio:g}). The pseudonymizer did not "
                f"process this column."
            ),
            sample=redact(unmapped[0]),
        )

    def _check_known_values(
        self, table: str, column: str, values: list[str]
    ) -> list[Finding]:
        """
        Look for original values, verbatim, anywhere in the output.

        Zero false positives: every hit is a string we know we were
        supposed to have replaced.
        """
        if not self._known_index:
            return []

        # A column whose every value is numeric cannot hold a name, an
        # address or a free-text note. Skipping it removes the remaining
        # source of coincidental id-vs-id matches.
        if all(v.replace('.', '').replace('-', '').isdigit() for v in values):
            return []

        confirmed: list[str] = []
        guessed: list[str] = []

        for value in values:
            found = self._find_known_value(value)
            if not found:
                continue
            # Split by provenance: a value seen in a structured PII column is
            # confirmed personal data; one only ever captured by the free-text
            # regex may be a product name it mistook for a person. Both block
            # (C36, decided 21 Oct); the split only explains the finding.
            if found in self._freetext_only:
                guessed.append(found)
            else:
                confirmed.append(found)

        findings: list[Finding] = []

        if confirmed:
            findings.append(Finding(
                severity=CRITICAL,
                check='known_value_leak',
                location=f"{table}.{column}",
                count=len(confirmed),
                description=(
                    "Contains original values that appeared in a structured "
                    "PII column. These are confirmed personal data, not "
                    "heuristic matches."
                ),
                sample=redact(confirmed[0]),
            ))

        if guessed:
            findings.append(Finding(
                severity=CRITICAL,
                check='known_value_leak_freetext',
                location=f"{table}.{column}",
                count=len(guessed),
                description=(
                    "Contains values the free-text regex mapped, but which "
                    "never appeared in a structured PII column. It may be a "
                    "product name rather than a person; it blocks anyway - "
                    "over-masking a product name is the accepted cost."
                ),
                sample=redact(guessed[0]),
            ))

        return findings

    def _check_patterns(
        self,
        table: str,
        column: str,
        values: list[str],
        classification: str | None,
    ) -> list[Finding]:
        """Regex scan for PII shapes in any text column."""
        findings: list[Finding] = []

        for name, pattern, severity, description in PATTERNS:
            # A correctly pseudonymized email column keeps its real domain,
            # so the email pattern matches by design. Not a leak.
            if name == 'email' and classification == 'email':
                continue

            matches: list[str] = []
            for value in values:
                found = pattern.search(value)
                if found:
                    matched = found.group(0)
                    # EMAIL_001234@klant.nl is the intended output shape
                    if name == 'email' and PSEUDO_EMAIL_RE.match(matched):
                        continue
                    # ACCT_001234 will not match the IBAN pattern, but a
                    # pseudonym elsewhere in the string might trip it
                    if name == 'iban' and PSEUDONYM_RE.match(value):
                        continue
                    matches.append(matched)

            if matches:
                findings.append(Finding(
                    severity=severity,
                    check=f'pattern_{name}',
                    location=f"{table}.{column}",
                    count=len(matches),
                    description=f"{description} detected in column content.",
                    sample=redact(matches[0]),
                ))

        return findings

    # Check 3 shapes that block. The honorific heuristic (MEDIUM, advisory)
    # is left out of the schema scan: it is noisy and never blocks anyway.
    SCHEMA_PATTERNS = ('iban_nl', 'iban', 'email', 'btw', 'phone_nl')

    def _check_schema(self, cursor: sqlite3.Cursor) -> list[Finding]:
        """
        Checks 1 and 3 over every `sqlite_master.sql` text: tables, views,
        triggers and indexes, internal objects included (R1, CP2 review).

        The schema is stored in the file verbatim and travels with it, so a
        view filtering on a real name, a trigger selecting a real IBAN or a
        CHECK/DEFAULT literal holding an email is as much a leak as a cell.
        Every hit is CRITICAL at `schema:<object name>`; the report shows a
        redacted preview only.
        """
        findings: list[Finding] = []
        rows = cursor.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
        ).fetchall()
        for obj_type, name, sql in rows:
            text = str(sql)
            location = f"schema:{name}"

            found = self._find_known_value(text)
            if found:
                guessed = found in self._freetext_only
                findings.append(Finding(
                    severity=CRITICAL,
                    check='schema_known_value_leak' + ('_freetext' if guessed else ''),
                    location=location,
                    count=1,
                    description=(
                        f"The {obj_type} definition holds an original value from "
                        "the pseudonym key. Schema text is stored in the file "
                        "verbatim and travels with it."
                    ),
                    sample=redact(found),
                ))

            for pname, pattern, _severity, description in PATTERNS:
                if pname not in self.SCHEMA_PATTERNS:
                    continue
                matches = [
                    m.group(0) for m in pattern.finditer(text)
                    if not (pname == 'email' and PSEUDO_EMAIL_RE.match(m.group(0)))
                ]
                if matches:
                    findings.append(Finding(
                        severity=CRITICAL,
                        check=f'schema_pattern_{pname}',
                        location=location,
                        count=len(matches),
                        description=(
                            f"{description} detected in the {obj_type} definition "
                            "(schema text travels with the file)."
                        ),
                        sample=redact(matches[0]),
                    ))
        return findings

    # -- check 5: raw-file residue -------------------------------------

    def _read_raw_files(self) -> list[tuple[Path, bytes]]:
        """The DB file and every sidecar present, as raw bytes."""
        files: list[tuple[Path, bytes]] = []
        candidates = [self.db_path] + [
            self.db_path.with_name(self.db_path.name + suffix)
            for suffix in SIDECAR_SUFFIXES
        ]
        for path in candidates:
            if path.is_file():
                files.append((path, path.read_bytes()))
        return files

    @staticmethod
    def _file_encoding(raw_files: list[tuple[Path, bytes]]) -> str:
        if raw_files:
            header = raw_files[0][1]
            if len(header) >= 60 and header[:16] == b'SQLite format 3\x00':
                return _HEADER_ENCODINGS.get(int.from_bytes(header[56:60], 'big'), 'utf-8')
        return 'utf-8'

    @staticmethod
    def _decoded_views(raw: bytes, encoding: str) -> list[str]:
        """
        The raw bytes as folded text (`fold`), in the file's own text encoding.

        Decoding with errors='replace' turns page headers, varints and other
        binary into U+FFFD without swallowing the text beside it, and
        fold() handles case and accents in every script (E-acute, O-umlaut, O-slash...) where
        bytes.lower() folded ASCII only (R2, CP2 review). SQLite packs record
        bytes with no alignment, so a UTF-16 string may start on an odd
        offset: UTF-16 files are decoded at both offsets.
        """
        if encoding == 'utf-8':
            return [fold(raw.decode('utf-8', errors='replace'))]
        return [fold(raw[shift:].decode(encoding, errors='replace'))
                for shift in (0, 1)]

    @staticmethod
    def _find_needles(haystack: str, needles: dict[str, str]) -> dict[str, int]:
        """
        Count occurrences of every needle in `haystack` (both casefolded).

        Plain substring, no word boundaries: SQLite stores a row's values
        back to back, so residue is glued to its neighbours. A dict keyed on
        each needle's first `width` characters keeps this one pass over the
        file instead of one pass per known value.
        """
        if not needles or not haystack:
            return {}
        width = min(len(n) for n in needles)
        by_prefix: dict[str, list[str]] = {}
        for needle in needles:
            by_prefix.setdefault(needle[:width], []).append(needle)

        counts: dict[str, int] = {}
        end = len(haystack) - width + 1
        get = by_prefix.get
        for i in range(max(end, 0)):
            group = get(haystack[i:i + width])
            if group is None:
                continue
            for needle in group:
                if haystack.startswith(needle, i):
                    counts[needle] = counts.get(needle, 0) + 1
        return counts

    @staticmethod
    def _live_blob(conn: sqlite3.Connection) -> str:
        """Every live TEXT/BLOB value, casefolded - what SQL can see in rows.

        Schema text is deliberately NOT live (R1, CP2 review): a known value
        that survives only in a view, trigger or CHECK literal is still in
        the file, so check 5 reports it alongside the schema scan."""
        parts: list[str] = []
        cursor = conn.cursor()
        tables = [r[0] for r in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            try:
                rows = cursor.execute(f"SELECT * FROM {quote_ident(table)}").fetchall()
            except sqlite3.Error:
                continue  # already reported as unreadable by the column scan
            for row in rows:
                for value in row:
                    if isinstance(value, str):
                        parts.append(fold(value))
                    elif isinstance(value, (bytes, bytearray)):
                        parts.append(fold(bytes(value).decode('utf-8', errors='replace')))
        return '\x00'.join(parts)

    def _check_raw_residue(
        self, conn: sqlite3.Connection, raw_files: list[tuple[Path, bytes]]
    ) -> list[Finding]:
        """
        Check 5: search the raw bytes of the DB and its sidecars for every
        indexed known value (case-insensitive). A value found in the bytes
        that no live row holds is residue: a freed page, a freeblock or a
        journal still carrying the original - or schema text (a view,
        trigger or CHECK literal), which is not counted as live.
        """
        if not self._indexed_originals or not raw_files:
            return []

        encoding = self._file_encoding(raw_files)
        needles: dict[str, str] = {}
        for original in self._indexed_originals:
            needle = fold(original)
            if needle:
                needles[needle] = original

        hits_per_file: list[tuple[Path, dict[str, int]]] = []
        for path, raw in raw_files:
            hits: dict[str, int] = {}
            for view in self._decoded_views(raw, encoding):
                for needle, count in self._find_needles(view, needles).items():
                    hits[needle] = hits.get(needle, 0) + count
            hits_per_file.append((path, hits))
        if not any(hits for _, hits in hits_per_file):
            return []

        live = self._live_blob(conn)
        findings: list[Finding] = []
        for path, hits in hits_per_file:
            residue = sorted(
                (needles[n] for n in hits if n not in live),
                key=lambda v: (len(v), v),
            )
            if residue:
                findings.append(Finding(
                    severity=CRITICAL,
                    check='raw_file_residue',
                    location=f"{path.name} (raw bytes)",
                    count=len(residue),
                    description=(
                        "The file's raw bytes still hold original values no live "
                        "row holds (freed pages, freeblocks or a journal). SQL "
                        "cannot see them; anyone with the file can."
                    ),
                    sample=redact(residue[0]),
                ))
        return findings


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Validate that a pseudonymized database contains no personal data.',
        epilog=(
            'Exit codes: 0 = safe to release, 1 = leakage found, 2 = scan failed.\n'
            'Run this before sending any data to an AI model.'
        ),
    )
    parser.add_argument('database', type=Path, help='Pseudonymized SQLite database')
    parser.add_argument(
        '--mapping', '-m', type=Path, default=None,
        help='Pseudonym key file (the encrypted key, or an old plaintext JSON '
             'key). Strongly recommended: enables the zero-false-positive '
             'known-value check. If given, it must open (exit 2 otherwise).',
    )
    parser.add_argument(
        '--manifest', type=Path, default=None,
        help='Path to pii_schema.yaml (default: none - pattern-only mode). '
             'If given, it must be usable, PyYAML included (exit 2 otherwise).',
    )
    parser.add_argument(
        '--strict', action='store_true',
        help='Treat advisory (MEDIUM) findings as blocking too.',
    )
    parser.add_argument(
        '--quiet', '-q', action='store_true',
        help='Print only the verdict line.',
    )
    args = parser.parse_args()

    if not args.database.exists():
        print(f"ERROR: database not found: {args.database}")
        return 2

    try:
        validator = PseudonymizationValidator(
            args.database,
            manifest_path=args.manifest,
            mapping=args.mapping,
        )
        result = validator.validate()
    except MappingUnreadableError as e:
        print(f"ERROR: {e}")
        return 2
    except ManifestError as e:
        print(f"ERROR: {e}")
        return 2
    except (sqlite3.Error, OSError) as e:
        print(f"ERROR: could not read database: {type(e).__name__}")
        return 2

    passed = result.passed and (not args.strict or not result.advisory)

    if args.quiet:
        print(
            f"{'PASS' if passed else 'FAIL'} - "
            f"{len(result.blocking)} blocking, {len(result.advisory)} advisory"
        )
        if not result.yaml_available:
            print("PYYAML NOT INSTALLED: COVERAGE CHECK AND STOPWORDS DID NOT RUN")
    else:
        print(result.format_report())

    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
