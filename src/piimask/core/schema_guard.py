"""
Schema Guard - fail-closed schema verification for pseudonymization.

WHY THIS EXISTS
---------------
An earlier version of the pseudonymizer used fail-OPEN schema guards:

    columns = {c['name'] for c in db.get_table_info('sales_invoices')}
    for col in ['contact_id', 'contact', 'reference']:
        if col in columns:
            select_cols.append(col)
    if len(select_cols) == 1:
        return 0          # <-- silent no-op, reported as success

The real schema has `contact_name`, not `contact`. So this returned 0,
the pipeline printed "PSEUDONYMIZATION COMPLETE", and real customer
names shipped in a database documented as "safe to share".

This module inverts that default. Every column must be explicitly
classified in config/pii_schema.yaml. Anything unclassified is treated as
potentially-PII and ABORTS the run before a single row is written.

Deliberate consequence: when Moneybird adds a field, the pipeline breaks
loudly instead of leaking quietly. Breaking is the safe failure mode.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from piimask.core.errors import SchemaDriftError

# Classifications that mean "this column carries PII and must be transformed"
PII_CLASSIFICATIONS: set[str] = {
    'person', 'company', 'contact', 'account',
    'email', 'reference', 'identifier', 'freetext',
}

# The full set of legal classifications
VALID_CLASSIFICATIONS: set[str] = PII_CLASSIFICATIONS | {'safe'}


def quote_identifier(name: str) -> str:
    """An SQLite identifier in double quotes, inner quotes doubled."""
    return '"' + str(name).replace('"', '""') + '"'


@dataclass
class SchemaReport:
    """Result of comparing a live database against the PII manifest."""

    tables_checked: list[str] = field(default_factory=list)
    tables_missing: list[str] = field(default_factory=list)
    tables_undeclared: list[str] = field(default_factory=list)
    unclassified_columns: list[str] = field(default_factory=list)
    declared_but_absent: list[str] = field(default_factory=list)
    invalid_classifications: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """True only when nothing at all is ambiguous."""
        return not (
            self.tables_undeclared
            or self.unclassified_columns
            or self.invalid_classifications
        )

    def format_failure(self) -> str:
        """Human-readable explanation of why the run must not proceed."""
        lines = ["Schema does not match config/pii_schema.yaml.", ""]

        if self.tables_undeclared:
            lines.append("UNDECLARED TABLES (present in DB, absent from manifest):")
            lines += [f"    - {t}" for t in self.tables_undeclared]
            lines.append("")

        if self.unclassified_columns:
            lines.append("UNCLASSIFIED COLUMNS (present in DB, absent from manifest):")
            lines += [f"    - {c}" for c in self.unclassified_columns]
            lines.append("")

        if self.invalid_classifications:
            lines.append("INVALID CLASSIFICATIONS in manifest:")
            lines += [f"    - {c}" for c in self.invalid_classifications]
            lines.append("")

        lines += [
            "No output was written. To resolve, open config/pii_schema.yaml and",
            "classify each item above as one of:",
            f"    {', '.join(sorted(VALID_CLASSIFICATIONS))}",
            "",
            "Classify as 'safe' ONLY after confirming the column cannot contain",
            "a name, address, email, phone, IBAN, BTW/KvK number or free text.",
        ]
        return "\n".join(lines)

    def format_summary(self) -> str:
        """Short report for a successful check."""
        lines = [f"Schema verified against manifest ({len(self.tables_checked)} tables)."]
        if self.tables_missing:
            lines.append(
                f"  Declared but not in this DB (skipped): {', '.join(self.tables_missing)}"
            )
        if self.declared_but_absent:
            lines.append(
                f"  Columns declared but absent (skipped): {len(self.declared_but_absent)}"
            )
        return "\n".join(lines)


class SchemaGuard:
    """
    Loads the PII manifest and verifies a database against it.

    Usage:
        guard = SchemaGuard(manifest_path)
        guard.verify_or_raise(db_path)          # aborts on any drift

        for table in guard.processing_order(db_path):
            for column, classification in guard.pii_columns(table).items():
                ...
    """

    def __init__(self, manifest_path: Path):
        """
        Args:
            manifest_path: Path to pii_schema.yaml. Required: there is no
                default and no search. A guard that went looking for "a"
                manifest is how `check` and `run` came to judge by different
                files (C05).
        """
        self.manifest_path = Path(manifest_path)
        if not self.manifest_path.exists():
            raise SchemaDriftError(
                f"PII manifest not found: {self.manifest_path}\n"
                "Pseudonymization cannot run without an explicit column "
                "classification manifest."
            )

        with open(self.manifest_path, 'r', encoding='utf-8') as f:
            loaded = yaml.safe_load(f)
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise SchemaDriftError(
                f"PII manifest is not a mapping: {self.manifest_path}"
            )
        self.manifest: dict[str, Any] = loaded

        self.tables: dict[str, Any] = self.manifest.get('tables', {}) or {}
        self.validation: dict[str, Any] = self.manifest.get('validation', {}) or {}

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @staticmethod
    def _live_schema(db_path: Path) -> dict[str, list[str]]:
        """Read {table: [columns]} straight from the database.

        Opened READ-ONLY: the guard can never create, change or journal the
        real database. A missing path is a clear error, never a fresh empty DB
        (which would have no tables and so look "safe").
        """
        path = Path(db_path)
        if not path.is_file():
            raise FileNotFoundError(f"Database not found: {path}")
        # as_uri() percent-encodes '?', '#' and '%' in the path.
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            cursor = conn.cursor()
            # `_` is a LIKE wildcard: unescaped, 'sqlite_%' also skips a user
            # table such as `sqlite1data`, which then escapes the check (R7).
            cursor.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
            )
            table_names = [row[0] for row in cursor.fetchall()]

            schema: dict[str, list[str]] = {}
            for table in table_names:
                # Quoted: a table name with a space, a quote or a keyword
                # must not break (or steer) the scan.
                cursor.execute(f"PRAGMA table_info({quote_identifier(table)})")
                schema[table] = [row[1] for row in cursor.fetchall()]
            return schema
        finally:
            conn.close()

    def check(self, db_path: Path) -> SchemaReport:
        """
        Compare a database against the manifest without raising.

        Returns:
            SchemaReport; inspect `.is_safe` before proceeding.
        """
        report = SchemaReport()
        live = self._live_schema(Path(db_path))

        # Validate the manifest's own classifications first
        for table, spec in self.tables.items():
            for column, classification in (spec.get('columns', {}) or {}).items():
                if classification not in VALID_CLASSIFICATIONS:
                    report.invalid_classifications.append(
                        f"{table}.{column} = '{classification}'"
                    )

        # Tables in the DB that the manifest never mentions
        for table in live:
            if table not in self.tables:
                report.tables_undeclared.append(table)

        # Compare declared tables against reality
        for table, spec in self.tables.items():
            declared_cols = spec.get('columns', {}) or {}

            if table not in live:
                report.tables_missing.append(table)
                continue

            report.tables_checked.append(table)
            live_cols = set(live[table])

            for column in live_cols:
                if column not in declared_cols:
                    report.unclassified_columns.append(f"{table}.{column}")

            for column in declared_cols:
                if column not in live_cols:
                    report.declared_but_absent.append(f"{table}.{column}")

        return report

    def verify_or_raise(self, db_path: Path) -> SchemaReport:
        """
        Verify a database, raising SchemaDriftError on any ambiguity.

        This is the call that enforces fail-closed behaviour. Everything
        downstream may assume every column is accounted for.
        """
        report = self.check(db_path)
        if not report.is_safe:
            raise SchemaDriftError(report.format_failure())
        return report

    # ------------------------------------------------------------------
    # Accessors used by the pseudonymizer
    # ------------------------------------------------------------------

    def processing_order(self, db_path: Path | None = None) -> list[str]:
        """
        Tables in the order they must be processed.

        Structured PII first, freetext last: freetext scrubbing depends on
        the mapping already knowing the real values it needs to redact.
        """
        order = self.manifest.get('processing_order') or list(self.tables)
        if db_path is None:
            return order
        live = set(self._live_schema(Path(db_path)))
        return [t for t in order if t in live]

    def primary_key(self, table: str) -> str:
        """Primary key column for a table (schemas differ per table)."""
        spec = self.tables.get(table, {})
        pk = spec.get('primary_key')
        if not pk:
            raise SchemaDriftError(
                f"No primary_key declared for table '{table}' in "
                f"{self.manifest_path}. Cannot build a safe UPDATE statement."
            )
        return pk

    def pii_columns(self, table: str) -> dict[str, str]:
        """{column: classification} for PII columns only, excluding freetext."""
        columns = (self.tables.get(table, {}).get('columns', {}) or {})
        return {
            col: cls for col, cls in columns.items()
            if cls in PII_CLASSIFICATIONS and cls != 'freetext'
        }

    def freetext_columns(self, table: str) -> list[str]:
        """Columns needing full free-text scrubbing."""
        columns = (self.tables.get(table, {}).get('columns', {}) or {})
        return [col for col, cls in columns.items() if cls == 'freetext']

    def all_pii_columns(self, table: str) -> dict[str, str]:
        """{column: classification} for every PII column including freetext."""
        columns = (self.tables.get(table, {}).get('columns', {}) or {})
        return {
            col: cls for col, cls in columns.items()
            if cls in PII_CLASSIFICATIONS
        }


# ----------------------------------------------------------------------
# CLI - check a database without running pseudonymization
# ----------------------------------------------------------------------

def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description='Verify a database schema against the PII manifest.'
    )
    parser.add_argument('database', type=Path, help='SQLite database to check')
    parser.add_argument(
        '--manifest', '-m', type=Path, required=True,
        help='Path to pii_schema.yaml'
    )
    args = parser.parse_args()

    if not args.database.exists():
        print(f"Database not found: {args.database}")
        return 2

    try:
        guard = SchemaGuard(args.manifest)
    except SchemaDriftError as e:
        print(str(e))
        return 2
    except (OSError, yaml.YAMLError) as e:
        print(f"Cannot read the PII manifest {args.manifest}: {e.__class__.__name__}")
        return 2

    report = guard.check(args.database)

    print("=" * 70)
    print("SCHEMA GUARD")
    print("=" * 70)
    print(f"Database: {args.database}")
    print(f"Manifest: {guard.manifest_path}")
    print()

    if report.is_safe:
        print(report.format_summary())
        print()
        print("PASS - safe to pseudonymize.")
        return 0

    print(report.format_failure())
    print()
    print("FAIL - pseudonymization is blocked.")
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
