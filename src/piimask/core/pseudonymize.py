"""
Unified Pseudonymization System

Solves:
- Two separate mapping files causing inconsistencies
- Same person getting different IDs across updates
- Weak audit trail across databases
- Scattered pseudonymization logic

Provides:
- SINGLE mapping file for all entity types
- Consistent IDs: same value always maps to same pseudonym
- Handles: persons, companies, emails, messages, accounts, invoices
- Atomic save with temp file + rename
- GDPR-compliant reversible pseudonymization
"""

import logging
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Self

from piimask.core import patterns
from piimask.core.errors import (
    MappingUnreadableError,
    PseudonymizationLeakError,
)
from piimask.core.mapping_store import MappingStore
from piimask.settings import Settings
from piimask.settings import coerce_file_mode as _coerce_file_mode  # noqa: F401 - re-export

logger = logging.getLogger(__name__)


# A value already in pseudonym form (PERSON_001234, EMAIL_001234@domain.nl).
# Used to keep pseudonymization idempotent across repeated/incremental runs.
PSEUDONYM_PATTERN = re.compile(r'^[A-Z]+_\d{6,}(@|$)')

# The same shape as a token inside free text, for patterns that must never
# capture (part of) a pseudonym.
_PSEUDONYM_TOKEN = r'[A-Z]+_\d{6,}'


class UnifiedPseudonymizer:
    """
    Unified pseudonymization system with single mapping file.

    Replaces:
    - reversible_pseudonymize.py
    - pseudonymize_invoices.py
    - execution/pseudonymize_db.py

    Usage:
        settings = Settings.load(home)        # or Settings.defaults(home)
        pseudo = UnifiedPseudonymizer(settings)

        # Pseudonymize a single value
        name = pseudo.pseudonymize("John Doe", "person")
        # Returns: "PERSON_001234"

        # Pseudonymize email
        email = pseudo.pseudonymize_email("john@example.com")
        # Returns: "EMAIL_001235@example.com"

        # Pseudonymize entire database (every path explicit)
        pseudo.pseudonymize_database(
            settings.original_db, settings.pseudo_db,
            manifest_path=settings.manifest_path,
        )

        # Save mapping (auto-called on context manager exit)
        pseudo.save_mapping()

        # Depseudonymize
        original = pseudo.depseudonymize("PERSON_001234")
        # Returns: "John Doe"
    """

    def __init__(
        self,
        settings: Settings,
        mapping_path: Path | None = None,
        *,
        store: MappingStore | None = None,
    ):
        """
        Initialize unified pseudonymizer.

        Args:
            settings: Explicit settings (prefixes, counter start, titles,
                      file mode, default key location). Nothing is read from
                      the environment or a config file here.
            mapping_path: Path to the key file. Defaults to
                          settings.mapping_path.
            store: The encrypted key store (CP3). Defaults to a
                   MappingStore at mapping_path; every read and write of
                   the key goes through it.
        """
        self.settings = settings
        if store is None:
            if mapping_path is None:
                mapping_path = settings.mapping_path
            store = MappingStore(Path(mapping_path))

        self.store = store
        self.mapping_path = store.path
        self.mapping_path.parent.mkdir(parents=True, exist_ok=True)

        self.prefixes = dict(settings.prefixes)

        # Initialize mappings
        self.forward_map: dict[str, str] = {}  # original -> pseudonym
        self.reverse_map: dict[str, str] = {}  # pseudonym -> original
        self.counter = settings.counter_start
        self.metadata: dict[str, Any] = {}

        # Originals learned only from free-text regex capture, never from
        # a structured PII column. Lower confidence - see pseudonymize_database.
        self.freetext_derived: set = set()

        # Stats tracking
        self.stats = {
            'new_mappings': 0,
            'reused_mappings': 0,
            'rows_processed': 0
        }

        # Load existing mapping
        self._load_mapping()

    def _load_mapping(self) -> None:
        """
        Load the existing key, or start fresh when there is none.

        A MISSING file is a legitimate first run. A file that EXISTS but cannot
        be read or parsed raises MappingUnreadableError (C17): starting an empty
        key at the counter start would hand out pseudonyms that already mean
        someone else in data shared earlier, and the run would then overwrite
        the damaged key. The message names the path, never the contents.
        """
        if not self.store.exists():
            return
        # The store fails closed on its own (wrong key, tamper, plaintext
        # key, bad header): its MappingUnreadableError passes through as is.
        data = self.store.load()
        try:
            if not isinstance(data, dict):
                raise ValueError("key file is not a JSON object")  # noqa: TRY004 - malformed key-file content is a bad value, not a bad argument type; caught below and re-raised as MappingUnreadableError
            forward = data.get('forward', {})
            reverse = data.get('reverse', {})
            counter = data.get('counter', self.counter)
            if not isinstance(forward, dict) or not isinstance(reverse, dict):
                raise ValueError("key file has no forward/reverse maps")  # noqa: TRY004 - malformed key-file content is a bad value, not a bad argument type; caught below and re-raised as MappingUnreadableError
            if not isinstance(counter, int) or isinstance(counter, bool):
                raise ValueError("key file counter is not an integer")  # noqa: TRY004 - malformed key-file content is a bad value, not a bad argument type; caught below and re-raised as MappingUnreadableError
            freetext_derived = set(data.get('freetext_derived', []))
            metadata = data.get('metadata', {})
        except Exception as e:  # noqa: BLE001 - fail-closed (C17): ANY failure to read the key becomes the one typed error, chain dropped so no message can quote key contents
            # `from None`: the parser's own message can quote file contents.
            raise MappingUnreadableError(
                f"The pseudonym key at {self.mapping_path} exists but cannot be "
                f"read ({type(e).__name__}). Nothing was changed; restore the "
                f"key from a backup before running again."
            ) from None

        self.forward_map = forward
        self.reverse_map = reverse
        self.counter = counter
        self.metadata = metadata
        self.freetext_derived = freetext_derived
        logger.info(
            "Loaded existing mapping",
            extra={'mapping_file': str(self.mapping_path), 'count': len(forward)},
        )

    def save_mapping(self) -> None:
        """
        Save the key encrypted, atomically, owner-only at every moment
        (C14/C15/C16/C37) - through MappingStore.save, which also refuses to
        write over a key it cannot open (C38).
        """
        data = {
            'forward': self.forward_map,
            'reverse': self.reverse_map,
            'counter': self.counter,
            'freetext_derived': sorted(self.freetext_derived),
            'metadata': {
                'updated_at': datetime.now().isoformat(),
                'version': '3.0',
                'total_mappings': len(self.forward_map),
                'stats': self.stats
            }
        }
        self.store.save(data)
        logger.info(
            "Saved mapping",
            extra={
                'mapping_file': str(self.mapping_path),
                'count': len(self.forward_map),
                'new_mappings': self.stats['new_mappings']
            }
        )

    def pseudonymize(self, value: str, category: str = 'person') -> str:
        """
        Pseudonymize a value.

        Args:
            value: Original value to pseudonymize
            category: Type ('person', 'company', 'account', 'email', 'reference', etc.)

        Returns:
            Pseudonymized value (e.g., PERSON_001234)
        """
        if not value or str(value).strip() == '':
            return value

        # Normalize value
        normalized = str(value).strip()

        # IDEMPOTENCY: never pseudonymize a pseudonym.
        #
        # data/moneybird.db can hold a mix of raw and already-pseudonymized
        # values (a large share of counterparty names were pseudonyms before
        # this run), because pseudonymization was once applied in place.
        # Without this guard, re-running builds PERSON_001858 -> PERSON_007421
        # chains: depseudonymize() then returns another pseudonym instead of a
        # name, and the mapping grows on every run.
        if PSEUDONYM_PATTERN.match(normalized):
            return normalized

        # Check existing mapping (CRITICAL for consistency)
        if normalized in self.forward_map:
            self.stats['reused_mappings'] += 1
            return self.forward_map[normalized]

        # Generate new pseudonym
        self.counter += 1
        prefix = self.prefixes.get(category, 'ANON')
        pseudonym = f"{prefix}_{self.counter:06d}"

        # Store bidirectional mapping
        self.forward_map[normalized] = pseudonym
        self.reverse_map[pseudonym] = normalized
        self.stats['new_mappings'] += 1

        # Keep the free-text scrub index live.
        #
        # It is built once before the free-text pass, so without this a value
        # first learned while scrubbing financial_mutations.message would not
        # be recognised in invoice_details.description processed afterwards -
        # leaving the same name redacted in one table and exposed in another.
        if getattr(self, '_scrub_index', None) is not None:
            self._register_scrub_value(normalized, pseudonym)

        return pseudonym

    def _register_scrub_value(self, original: str, pseudonym: str) -> None:
        """Add one mapping to the live free-text scrub index."""
        self._index_scrub_value(original, pseudonym)

    def _scrub_entry(self, original: str, pseudonym: str) -> tuple[str, bool] | None:
        """
        Decide whether one mapping belongs in the free-text scrub index.

        Returns (normalised form, is-email-entry), or None when the value must
        not be scrubbed. This one helper serves both the batch build and the
        live register, so the two index paths can never drift apart again.
        """
        normalized = self._normalize_token(original)
        if not normalized:
            return None

        # Short pure-digit values are internal ids, not PII, and would
        # corrupt amounts and dates if blindly substituted.
        digits_only = normalized.replace(' ', '')
        if digits_only.isdigit() and len(digits_only) < 9:
            return None

        if len(normalized.split()) > 6:
            return None

        email_prefix = f"{self.prefixes.get('email', 'EMAIL')}_"
        return normalized, pseudonym.startswith(email_prefix)

    def _index_scrub_value(self, original: str, pseudonym: str) -> None:
        """
        Put one mapping into the scrub index (shared by build and register).

        The rule (C73, the f06 finding): an email local part stays in the
        index, but it is flagged. "ruben.smits" folds onto the same tokens as
        the name "Ruben Smits"; reusing the EMAIL token there masked the name
        with the wrong kind and revealed it in the address's spelling, so a
        match on an email entry is minted as a PERSON from the exact surface
        text instead (see _scrub_known_values). "As written" holds for each
        exact spelling: in a LATER text a case variant of an already-minted
        name reuses that name's PERSON token through the case-blind scrub
        (the existing f11 class). Skipping the entry was
        rejected: a name known only through an address would then survive in
        free text, and the validator (which indexes every forward-map
        original, local parts included) would refuse the run as a leak.

        Between two non-email entries the first mapping wins. A non-email
        entry does replace an email entry on the same tokens, so a person
        learned after their address keeps their own token in free text.
        """
        entry = self._scrub_entry(original, pseudonym)
        if entry is None:
            return
        normalized, is_email = entry
        current = self._scrub_index.get(normalized)
        if current is None or (current[1] and not is_email):
            self._scrub_index[normalized] = (pseudonym, is_email)
        token_count = len(normalized.split())
        self._scrub_max_ngram = min(
            max(getattr(self, '_scrub_max_ngram', 1), token_count), 6
        )

    def depseudonymize(self, pseudonym: str) -> str:
        """
        Convert pseudonym back to original value.

        Args:
            pseudonym: Pseudonymized value

        Returns:
            Original value or pseudonym if not found
        """
        return self.reverse_map.get(pseudonym, pseudonym)

    def pseudonymize_email(self, email: str) -> str:
        """
        Pseudonymize email address preserving domain.

        Args:
            email: Email address

        Returns:
            Pseudonymized email (e.g., EMAIL_001234@example.com)
        """
        if not email or '@' not in str(email):
            return email

        local, domain = str(email).rsplit('@', 1)
        pseudo_local = self.pseudonymize(local, 'email')
        return f"{pseudo_local}@{domain}"

    def pseudonymize_account_number(self, account: str) -> str:
        """
        Pseudonymize bank account number.

        Args:
            account: Account number (e.g., IBAN)

        Returns:
            Pseudonymized account number
        """
        if not account or str(account).strip() == '':
            return account

        return self.pseudonymize(str(account), 'account')

    def pseudonymize_message(self, message: str) -> str:
        """
        Pseudonymize PII in message content.

        Handles:
        - Dutch name prefixes (Mw, Dhr, etc.)
        - Mollie payment patterns
        - PayPal patterns
        - Email addresses in text
        - Long reference numbers
        """
        if not message:
            return message

        result = self._pseudonymize_identifiers(str(message))

        # Dutch name prefixes from settings
        titles = self.settings.dutch_titles
        titles_pattern = '|'.join(re.escape(t) for t in titles)

        # Pattern: "Mw. Surname" or "Dhr Surname van der Berg".
        # The separator (full stop + whitespace) is kept as written (C13): a
        # re-run sees "Dhr. PERSON_n" after the known-value scrub, and dropping
        # the stop on the first run only made the two outputs differ. A name
        # that is already a pseudonym is never captured.
        dutch_pattern = (
            rf'\b({titles_pattern})(\.?\s+)(?!{_PSEUDONYM_TOKEN})'
            r'([A-Z][A-Za-z]*(?:\s+(?:de|van|der|den|te|ter|ten|von|[A-Z])[A-Za-z]*)*)\b'
        )

        def dutch_replace(match):
            prefix = match.group(1)
            name = self.pseudonymize(match.group(3).strip(), 'person')
            return f"{prefix}{match.group(2)}{name}"

        result = re.sub(dutch_pattern, dutch_replace, result)

        # Mollie payments pattern
        mollie_pattern = r'Mollie [Pp]ayment\s*-\s*([^-]+?)\s*-\s*([^-]+?)(?:\s*-\s*([^\s,]+))?(?:\s|$|,)'

        def mollie_replace(match):
            name = self.pseudonymize(match.group(1).strip(), 'person')
            desc = self.pseudonymize(match.group(2).strip(), 'reference')
            ref = match.group(3)
            if ref:
                ref = self.pseudonymize(ref.strip(), 'reference')
                return f"Mollie Payment - {name} - {desc} - {ref}"
            return f"Mollie Payment - {name} - {desc}"

        result = re.sub(mollie_pattern, mollie_replace, result)

        # PayPal pattern. An existing pseudonym inside the merchant is kept
        # whole (it maps to itself), never cut at its "_" so that "COMPANY"
        # became a new merchant and chained into COMPANY_n_m on a re-run (C13).
        # The words around it are still masked, each run as one merchant.
        paypal_pattern = (
            rf'PayPal\s*\*?\s*((?:{_PSEUDONYM_TOKEN}\b|[A-Za-z0-9\s])+)'
        )

        def paypal_replace(match):
            parts = re.split(rf'({_PSEUDONYM_TOKEN}\b)', match.group(1).strip())
            merchant = ' '.join(
                self.pseudonymize(part.strip(), 'company')
                for part in parts if part.strip()
            )
            return f"PayPal {merchant}"

        result = re.sub(paypal_pattern, paypal_replace, result)

        # Email addresses in text (shared pattern: group 1 local, group 2 domain)
        return self._pseudonymize_emails(result)

    def _pseudonymize_identifiers(self, text: str) -> str:
        """IBAN, BTW and mobile shapes in free text, replaced through the key."""
        # --- Structured identifiers embedded in free text -----------------
        # These never pass through a structured column, so the mapping never
        # learns them and known-value scrubbing cannot catch them. On a real
        # dataset, raw IBANs, mobile numbers and BTW numbers survived in
        # financial_mutations.message without this pass.
        # Each is pseudonymized through the normal mapping, so it stays
        # reversible and consistent with the same value seen elsewhere.

        def _sub_mapped(pattern: re.Pattern, category: str, text: str) -> str:
            return pattern.sub(
                lambda m: self.pseudonymize(m.group(0), category),
                text,
            )

        # The shapes live in core/patterns.py, shared with the validator so
        # the two can never drift apart. Order matters: Dutch IBAN first
        # (exact 18 chars, catches the glued "...TRTPSEPA" form), then the
        # generic IBAN, BTW, mobile.
        result = _sub_mapped(patterns.IBAN_NL, 'account', text)
        result = _sub_mapped(patterns.IBAN_GENERIC, 'account', result)
        result = _sub_mapped(patterns.BTW_NL, 'reference', result)
        result = _sub_mapped(patterns.MOBILE_NL, 'reference', result)
        return result

    def _pseudonymize_emails(self, text: str) -> str:
        """Replace every email's local part through the key, keeping the domain."""
        def email_replace(match):
            local = self.pseudonymize(match.group(1), 'email')
            domain = match.group(2)
            return f"{local}@{domain}"

        return patterns.EMAIL.sub(email_replace, text)

    # ------------------------------------------------------------------
    # Free-text scrubbing driven by the mapping itself
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_token(text: str) -> str:
        """Fold text to comparable word tokens (see _scrub_known_values)."""
        return re.sub(r'[^a-z0-9]+', ' ', str(text).lower()).strip()

    def _build_scrub_index(self) -> None:
        """
        Build a normalised lookup of every value we have already mapped.

        This powers the strongest free-text defence available: once the
        structured pass has learned that a given string is a counterparty
        name, we can find and replace that exact string wherever it appears
        in free text - no regex guesswork required.
        """
        # normalised form -> (pseudonym, is-email-entry); see _index_scrub_value
        self._scrub_index: dict[str, tuple[str, bool]] = {}
        self._scrub_max_ngram = 1

        for original, pseudonym in list(self.forward_map.items()):
            self._index_scrub_value(original, pseudonym)

    def _scrub_known_values(self, text: str) -> str:
        """
        Replace every known original value found in free text.

        Walks word spans longest-first so that "Jan Jansen" is replaced as
        one person rather than as two separate tokens.
        """
        if not text or not getattr(self, '_scrub_index', None):
            return text

        tokens = list(re.finditer(r'\w+', str(text)))
        if not tokens:
            return text

        result = str(text)
        # Collect first, mint after: minting a PERSON calls pseudonymize(),
        # which registers into this live index; nothing is minted while the
        # token walk is still reading it.
        found: list[tuple[int, int, str, bool]] = []
        index = 0

        while index < len(tokens):
            matched = False
            upper = min(self._scrub_max_ngram, len(tokens) - index)

            # Longest span first - greedy match keeps multi-word names intact
            for size in range(upper, 0, -1):
                span = tokens[index:index + size]
                candidate = self._normalize_token(
                    ' '.join(t.group(0) for t in span)
                )
                entry = self._scrub_index.get(candidate)
                if entry is not None:
                    pseudonym, is_email = entry
                    found.append((span[0].start(), span[-1].end(), pseudonym, is_email))
                    index += size
                    matched = True
                    break

            if not matched:
                index += 1

        # An email entry's match is never a whole address (addresses were
        # replaced whole before this pass). It is usually a name written in
        # free text, but can also be part of a domain (with "bram.kok@..."
        # learned, "info@bram-kok.example" mints "bram-kok"). Either way it is
        # minted as a PERSON from the exact surface, so reveal stays
        # byte-exact (C73).
        replacements = [
            (start, end,
             self.pseudonymize(result[start:end], 'person') if is_email else pseudonym)
            for start, end, pseudonym, is_email in found
        ]

        # Apply right-to-left so earlier offsets stay valid
        for start, end, pseudonym in reversed(replacements):
            result = result[:start] + pseudonym + result[end:]

        return result

    def pseudonymize_freetext(self, text: str) -> str:
        """
        Full free-text treatment: known values first, then regex patterns.

        Order matters. Email addresses and identifier shapes (IBAN, BTW,
        mobile) go first, each whole through the key (C11/C13): the known-value
        scrub works on word tokens, so it would replace a name inside
        "jan.jansen@..." with the PERSON pseudonym (the address could then
        never be reversed), and on a re-run it would match "31 6 ..." of a
        known "+31 6 ..." and leave the "+" behind. Known-value substitution
        is exact and lossless, so it runs next; the regex pass then catches
        names that never appeared in a structured column.
        """
        if not text:
            return text
        text = self._pseudonymize_identifiers(self._pseudonymize_emails(str(text)))
        return self.pseudonymize_message(self._scrub_known_values(text))

    # ------------------------------------------------------------------
    # Manifest-driven database pseudonymization
    # ------------------------------------------------------------------

    def _pseudonymize_column_value(self, value: Any, classification: str) -> Any:
        """Apply the right transform for a column's declared classification."""
        if value is None or str(value).strip() == '':
            return value

        if classification == 'email':
            return self.pseudonymize_email(str(value))
        if classification == 'account':
            return self.pseudonymize_account_number(str(value))
        if classification == 'identifier':
            # Deterministic, so JOINs across tables still resolve
            return self.pseudonymize(str(value), 'contact')
        if classification in ('person', 'company', 'contact', 'reference'):
            return self.pseudonymize(str(value), classification)

        return value

    def _mask_row(
        self,
        row: dict[str, Any],
        pii_cols: dict[str, str],
        freetext_cols: list[str],
        *,
        freetext: bool,
    ) -> dict[str, Any]:
        """One row with its structured PII (and, if asked, free text) masked."""
        out = dict(row)
        for col, classification in pii_cols.items():
            out[col] = self._pseudonymize_column_value(out[col], classification)
        if freetext:
            for col in freetext_cols:
                if out[col]:
                    out[col] = self.pseudonymize_freetext(out[col])
        return out

    @staticmethod
    def _read_rows(src: sqlite3.Connection, table: str) -> tuple[list[str], list[dict[str, Any]]]:
        """All rows of a source table as dicts, in rowid order as stored."""
        cursor = src.execute(f'SELECT * FROM {_quote(table)}')
        columns = [d[0] for d in cursor.description]
        return columns, [dict(zip(columns, r)) for r in cursor.fetchall()]

    def pseudonymize_database(
        self,
        source_db: Path,
        target_db: Path,
        *,
        manifest_path: Path,
    ) -> dict[str, Any]:
        """
        Pseudonymize an entire database, fail-closed at both ends.

        Two guards bracket the work:

        1. BEFORE - SchemaGuard aborts if any column is unclassified. An
           earlier version instead skipped unknown columns silently, which is how
           real customer names shipped in a database documented as safe to
           share.

        2. AFTER - the leak validator scans the output. It ALWAYS runs; there
           is no switch to skip it (C34). If personal data survived, nothing
           is written under the target name.

        A real value never reaches the output file, not even for a moment
        (C25/C26/C39). The old code copied the real database and UPDATEd it
        in place, which leaves the real values as byte residue in free pages.
        Now the source is opened read-only, every row is masked in memory
        (structured pass over all tables first, so the free-text pass knows
        every real value), and only finished rows are INSERTed into a NEW
        database built from the source's CREATE statements, with
        secure_delete on and a rollback journal (no WAL), VACUUMed at the end.
        That file is `<target>.partial`; it is moved to the target name only
        after validation passes. On ANY failure the partial and its
        -journal/-wal/-shm siblings are removed. A target left by an earlier
        successful run is not touched by a failed run.

        Both guards judge by the SAME manifest, the one passed here. There is
        no default and no search for one: `check`, `run` and `validate` must
        all read the file the caller names (C05/C72).

        Args:
            source_db: Source database (real values). Never written.
            target_db: Target database (pseudonymised output).
            manifest_path: The PII manifest (pii_schema.yaml). Required.

        Returns:
            Statistics dict

        Raises:
            SchemaDriftError: schema does not match the manifest
            PseudonymizationLeakError: personal data survived
        """
        from .errors import SchemaDriftError
        from .schema_guard import SchemaGuard
        from .validate import PseudonymizationValidator

        source_db = Path(source_db)
        target_db = Path(target_db)
        manifest_path = Path(manifest_path)
        partial = target_db.with_name(target_db.name + '.partial')

        logger.info("pseudonymize_database started")

        # --- Guard 1: schema must be fully classified -----------------
        guard = SchemaGuard(manifest_path)
        guard.verify_or_raise(source_db)
        logger.info("Schema verified against PII manifest")

        src = sqlite3.connect(f"{source_db.resolve().as_uri()}?mode=ro", uri=True)
        try:
            # --- Guard 1b: the schema TEXT is copied, so it must be clean --
            # The output is built from the source's CREATE statements. A view,
            # trigger or index body, or a CHECK/DEFAULT literal, is copied
            # verbatim and would carry a real value past every row check
            # (CP2 review R1). Refused here, before any file is touched.
            schema = _plain_table_schema(src)
        except BaseException:
            src.close()
            raise

        _remove_db_files(partial)   # a stale partial from an earlier crash
        dst: sqlite3.Connection | None = None
        tables_processed: list[tuple[str, int]] = []
        try:
            order = guard.processing_order(source_db)
            tables = [name for name, _ in schema]
            unordered = sorted(set(tables) - set(order))
            if unordered:
                # Every table's rows are copied; one the manifest's order does
                # not cover would be copied unmasked.
                raise SchemaDriftError(
                    f"Tables not in the manifest's processing order: {unordered}"
                )

            dst = sqlite3.connect(str(partial))
            dst.execute('PRAGMA secure_delete=ON')
            dst.execute('PRAGMA journal_mode=DELETE')
            for _, sql in schema:
                dst.execute(sql)

            # --- Pass 1: structured PII, learned in memory -------------
            # Runs over every table first so the mapping knows every real
            # value before free text is scrubbed against it. Nothing is
            # written here.
            for table in order:
                columns = guard.pii_columns(table)
                _, rows = self._read_rows(src, table)
                changed = 0
                for row in rows:
                    masked = self._mask_row(row, columns, [], freetext=False)
                    changed += masked != row
                    self.stats['rows_processed'] += 1
                tables_processed.append((f"{table} (structured)", changed))

            # --- Pass 2: free text, then INSERT finished rows ----------
            self._build_scrub_index()

            # Track which mappings are learned from free text alone.
            #
            # Values captured by the Mollie/PayPal regex are guesses: on
            # real data it mapped product words like "t-shirt", "deposit"
            # and "workshop" as if they were people, because it assumes
            # "Mollie Payment - X - Y" always names a person. Those are
            # product descriptions.
            #
            # Over-pseudonymizing is safe for privacy but noisy for
            # analysis, so we record provenance rather than pretending
            # the distinction does not exist: a value seen in a
            # structured PII column is confirmed personal data, one only
            # ever guessed from free text is advisory.
            structured_origins = set(self.forward_map)
            reused_before = self.stats['reused_mappings']

            for table in order:
                pii_cols = guard.pii_columns(table)
                freetext_cols = guard.freetext_columns(table)
                columns, rows = self._read_rows(src, table)
                finished: list[tuple] = []
                changed = 0
                for row in rows:
                    new_before = self.stats['new_mappings']
                    after_structured = self._mask_row(row, pii_cols, [], freetext=False)
                    if self.stats['new_mappings'] != new_before:
                        # Pass 1 learned every structured value; a new one here
                        # means the two passes disagree. Stop rather than guess.
                        raise RuntimeError(
                            f"{table}: structured values changed between passes"
                        )
                    masked = self._mask_row(
                        after_structured, {}, freetext_cols, freetext=True
                    )
                    changed += any(
                        masked[c] != after_structured[c] for c in freetext_cols
                    )
                    finished.append(tuple(masked[c] for c in columns))
                if finished:
                    col_list = ', '.join(_quote(c) for c in columns)
                    marks = ', '.join('?' for _ in columns)
                    dst.executemany(
                        f'INSERT INTO {_quote(table)} ({col_list}) VALUES ({marks})',
                        finished,
                    )
                if freetext_cols:
                    tables_processed.append((f"{table} (freetext)", changed))

            # Pass 2 re-applies pass 1's structured transform; every value
            # is already in the key, so it is counted once (in pass 1).
            self.stats['reused_mappings'] = reused_before
            self.freetext_derived = set(self.forward_map) - structured_origins

            # No indexes, triggers or views: _plain_table_schema refused them.
            dst.commit()
            dst.execute('VACUUM')
            dst.close()
            dst = None
            logger.info(
                "Free-text pass complete",
                extra={'freetext_only_mappings': len(self.freetext_derived)},
            )

            self.save_mapping()

            # --- Guard 2: nothing may survive (always runs, C34) -------
            validator = PseudonymizationValidator(
                partial,
                manifest_path=manifest_path,
                mapping=self.store,
            )
            result = validator.validate()
            validation_summary = {
                'passed': result.passed,
                'blocking': len(result.blocking),
                'advisory': len(result.advisory),
            }
            if not result.passed:
                logger.error(
                    "Validation failed - output not written",
                    extra={'blocking': len(result.blocking)},
                )
                raise PseudonymizationLeakError(
                    f"Personal data survived pseudonymization; nothing was "
                    f"written to {target_db}.\n\n"
                    + result.format_report()
                )
            logger.info("Output validated - no personal data detected")

            # Sidecars of an earlier target would pair with the new file and
            # could hold that run's pages (CP2 review R5). Removal failing is
            # an OSError, which aborts the run before the move.
            _remove_sidecars(target_db)
            os.replace(partial, target_db)
        except BaseException:
            if dst is not None:
                dst.close()
            _remove_db_files(partial)
            raise
        finally:
            src.close()

        logger.info(
            "pseudonymize_database finished",
            extra={
                'rows_processed': self.stats['rows_processed'],
                'new_mappings': self.stats['new_mappings'],
            },
        )

        return {
            'source': str(source_db),
            'target': str(target_db),
            'tables': tables_processed,
            'stats': self.stats.copy(),
            'validation': validation_summary,
        }

    # NOTE: the hardcoded _pseudonymize_financial_mutations / _payments /
    # _invoices / _contacts methods were removed. They targeted
    # column names that do not exist in the real Moneybird schema
    # (`contact` vs `contact_name`, `reference` vs `payment_reference`,
    # `id` vs `invoice_id`) and a `contacts` table that is never fetched,
    # so they silently pseudonymized nothing while reporting success.
    # Their replacement is the manifest-driven pass in pseudonymize_database().

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - save mapping."""
        if exc_type is None:
            self.save_mapping()

    def __repr__(self) -> str:
        return f"UnifiedPseudonymizer(mappings={len(self.forward_map)})"


def create_pseudonymizer(
    settings: Settings, mapping_path: Path | None = None
) -> UnifiedPseudonymizer:
    """Factory function to create configured pseudonymizer."""
    return UnifiedPseudonymizer(settings, mapping_path)


def _quote(identifier: str) -> str:
    """An SQL identifier, double-quoted (a name with a space or quote is safe)."""
    return '"' + str(identifier).replace('"', '""') + '"'


# A name SQLite reserves for itself. `_` is a LIKE wildcard, so it is escaped:
# a user table called `sqlite1data` must not match (CP2 review R7).
_NOT_INTERNAL = r"name NOT LIKE 'sqlite\_%' ESCAPE '\'"


def _schema_text_problem(sql: str) -> str | None:
    """Why this CREATE TABLE text may not be copied, or None when it may.

    Fail closed on anything that can hold a value: a string or blob literal
    ('...' / x'...') and a comment (-- / /* */). Quoted identifiers ("...",
    `...`, [...]) are skipped; their names are judged by the manifest.
    """
    i, n = 0, len(sql)
    closers = {'"': '"', '`': '`', '[': ']'}
    while i < n:
        ch = sql[i]
        if ch in closers:
            end = sql.find(closers[ch], i + 1)
            if end < 0:
                return 'an unterminated quoted name'
            i = end + 1
            continue
        if ch == "'":
            return 'a string or blob literal'
        if sql.startswith('--', i) or sql.startswith('/*', i):
            return 'a comment'
        i += 1
    return None


def _plain_table_schema(src: sqlite3.Connection) -> list[tuple[str, str]]:
    """(name, CREATE TABLE sql) for every user object, or SchemaDriftError.

    Only plain tables whose text holds no literal or comment are allowed;
    their own autoindexes (NULL sql, `sqlite_` names) are rebuilt by SQLite.
    The message names the object and its type, never its SQL (R1).
    """
    from .errors import SchemaDriftError

    rows = src.execute(
        f"SELECT type, name, sql FROM sqlite_master WHERE {_NOT_INTERNAL} ORDER BY rowid"
    ).fetchall()
    out: list[tuple[str, str]] = []
    for kind, name, sql in rows:
        if kind != 'table':
            raise SchemaDriftError(
                f"The source has a {kind} named {name!r}. Only plain tables are "
                f"copied, because a {kind}'s definition is copied as written and "
                f"can carry personal data. Nothing was written."
            )
        if not sql or not re.match(r'\s*CREATE\s+TABLE\b', sql, re.IGNORECASE):
            raise SchemaDriftError(
                f"Table {name!r} is not a plain CREATE TABLE (virtual or "
                f"unreadable). Nothing was written."
            )
        problem = _schema_text_problem(sql)
        if problem:
            raise SchemaDriftError(
                f"The definition of table {name!r} holds {problem} (a CHECK, DEFAULT "
                f"or similar), which would be copied as written and can carry "
                f"personal data. Nothing was written."
            )
        out.append((name, sql))
    return out


def _remove_sidecars(db_path: Path) -> None:
    """Remove `<db>-journal/-wal/-shm`; an OSError (not 'missing') propagates."""
    for suffix in ('-journal', '-wal', '-shm'):
        Path(f"{db_path}{suffix}").unlink(missing_ok=True)


def _remove_db_files(db_path: Path) -> None:
    """Remove a database file and its -journal/-wal/-shm siblings, if present."""
    for suffix in ('', '-journal', '-wal', '-shm'):
        Path(f"{db_path}{suffix}").unlink(missing_ok=True)
