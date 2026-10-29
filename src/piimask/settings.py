"""
Explicit settings for the piimask core.

Replaces the legacy `utilities/config.py` singleton, which read
`config/settings.yaml` AT IMPORT, walked the filesystem for a project root and
resolved `${ENV}` references inside the values. That made every import a hidden
read of whichever settings file happened to be found first, and made the core
untestable without an import-order trap.

Here nothing happens at import. A caller (the CLI, a test, a library user)
decides where the home is and builds a `Settings` once:

    settings = Settings.load(home)        # reads home/config/settings.yaml
    settings = Settings.defaults(home)    # no file needed (library use, tests)

and passes it down. The core never looks up an environment variable and never
searches for a file on its own.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PREFIXES: Mapping[str, str] = MappingProxyType({
    'person': 'PERSON',
    'company': 'COMPANY',
    'account': 'ACCT',
    'email': 'EMAIL',
    'reference': 'REF',
    'contact': 'CONTACT',
    'invoice': 'INV',
})

DEFAULT_DUTCH_TITLES: tuple[str, ...] = ('Mw', 'Dhr', 'Mr', 'Mrs', 'Ms', 'Dr')

DEFAULT_COUNTER_START = 1000
DEFAULT_ORIGINAL_DB = 'moneybird.db'
DEFAULT_PSEUDO_DB = 'moneybird_pseudo.db'
DEFAULT_MAPPING_FILE = 'pseudonym_mapping.json'
DEFAULT_SECURE_FILE_MODE = 0o600

# Fixed layout inside a home: the manifest is not configurable from
# settings.yaml, so `check`, `run` and `validate` can only ever read one file.
CONFIG_DIRNAME = 'config'
SETTINGS_FILENAME = 'settings.yaml'
MANIFEST_FILENAME = 'pii_schema.yaml'


def coerce_file_mode(value: Any, default: int = DEFAULT_SECURE_FILE_MODE) -> int:
    """
    Turn a config file-mode into an int os.chmod will accept.

    Handles the three shapes settings.yaml can produce: a real int, the
    string "0o600" (PyYAML's reading of `0o600`), and "600"/"0600".
    Anything unrecognised falls back to owner-only, never wider.
    """
    if isinstance(value, int):
        return value

    text = str(value).strip().lower()
    try:
        if text.startswith('0o'):
            return int(text, 0)
        return int(text, 8)
    except (ValueError, TypeError):
        logger.warning(
            f"Unparseable file mode {value!r}; falling back to 0o600"
        )
        return default


@dataclass(frozen=True)
class Settings:
    """Everything the core reads, as explicit fields. Built once, passed down."""

    home: Path
    data_dir: Path
    secure_dir: Path
    logs_dir: Path
    manifest_path: Path
    original_db_name: str = DEFAULT_ORIGINAL_DB
    pseudo_db_name: str = DEFAULT_PSEUDO_DB
    mapping_filename: str = DEFAULT_MAPPING_FILE
    prefixes: Mapping[str, str] = field(default_factory=lambda: DEFAULT_PREFIXES)
    counter_start: int = DEFAULT_COUNTER_START
    dutch_titles: tuple[str, ...] = DEFAULT_DUTCH_TITLES
    secure_file_mode: int = DEFAULT_SECURE_FILE_MODE

    # -- derived paths -------------------------------------------------

    @property
    def config_dir(self) -> Path:
        return self.home / CONFIG_DIRNAME

    @property
    def settings_path(self) -> Path:
        return self.config_dir / SETTINGS_FILENAME

    @property
    def original_db(self) -> Path:
        return self.data_dir / self.original_db_name

    @property
    def pseudo_db(self) -> Path:
        return self.data_dir / self.pseudo_db_name

    @property
    def mapping_path(self) -> Path:
        return self.secure_dir / self.mapping_filename

    # -- construction --------------------------------------------------

    @classmethod
    def defaults(cls, home: Path) -> Settings:
        """The shipped defaults for a home, without reading any file."""
        home = Path(home)
        return cls(
            home=home,
            data_dir=home / 'data',
            secure_dir=home / 'secure',
            logs_dir=home / 'logs',
            manifest_path=home / CONFIG_DIRNAME / MANIFEST_FILENAME,
        )

    @classmethod
    def load(cls, home: Path) -> Settings:
        """
        Read home/config/settings.yaml. A missing file is an error (the caller
        decides whether defaults are acceptable instead). Keys the file leaves
        out fall back to the shipped defaults.
        """
        import yaml  # lazy: importing this module must never need PyYAML

        home = Path(home)
        path = home / CONFIG_DIRNAME / SETTINGS_FILENAME
        with open(path, encoding='utf-8') as f:
            raw = yaml.safe_load(f) or {}
        if not isinstance(raw, dict):
            raise TypeError(f"{path}: top level is not a mapping")
        return cls.from_mapping(home, raw)

    @classmethod
    def from_mapping(cls, home: Path, raw: Mapping[str, Any]) -> Settings:
        """Build Settings from an already-parsed settings.yaml structure."""
        home = Path(home)
        base = cls.defaults(home)

        def get(dotted: str, default: Any = None) -> Any:
            value: Any = raw
            for key in dotted.split('.'):
                if isinstance(value, Mapping) and key in value:
                    value = value[key]
                else:
                    return default
            return value

        def resolve(rel: Any, fallback: Path) -> Path:
            if rel is None or str(rel).strip() == '':
                return fallback
            p = Path(str(rel))
            return p if p.is_absolute() else home / p

        prefixes = get('pseudonymization.prefixes')
        titles = get('pseudonymization.patterns.dutch_titles')

        return cls(
            home=home,
            data_dir=resolve(
                get('paths.data.databases', get('paths.data.root')), base.data_dir),
            secure_dir=resolve(get('paths.secure.root'), base.secure_dir),
            logs_dir=resolve(get('paths.logs'), base.logs_dir),
            manifest_path=base.manifest_path,
            original_db_name=str(get('database.files.original', DEFAULT_ORIGINAL_DB)),
            pseudo_db_name=str(get('database.files.pseudonymized', DEFAULT_PSEUDO_DB)),
            mapping_filename=str(get('pseudonymization.mapping_file', DEFAULT_MAPPING_FILE)),
            prefixes=(MappingProxyType({**DEFAULT_PREFIXES, **prefixes})
                      if isinstance(prefixes, Mapping) else DEFAULT_PREFIXES),
            counter_start=int(get('pseudonymization.counter_start', DEFAULT_COUNTER_START)),
            dutch_titles=(tuple(str(t) for t in titles)
                          if isinstance(titles, list) else DEFAULT_DUTCH_TITLES),
            secure_file_mode=coerce_file_mode(
                get('pseudonymization.secure_file_mode', DEFAULT_SECURE_FILE_MODE)),
        )
