"""
Load the detector's packaged word lists.

The rules ask two questions of a Titlecase word: is it an ordinary Dutch or
English word, and is it a known Dutch proper name.
The answers come from three lists built once by `tools/build_lexicon.py` from
pinned upstreams and shipped inside the package as gzip
(`piimask/detect/data/*.txt.gz`; licences in `data/LICENSES.md`, hashes in
`docs/provenance.md`).

`load_default()` reads them through `importlib.resources`, so it works the
same from a source checkout and from an installed wheel, and caches the
result: the lists are large (several hundred thousand words) and immutable,
so one process reads them once.

The lists are already normalised by the builder (common words lowercase,
names NFC Titlecase), so they are passed straight into `Lexicon` without a
second normalisation pass.

A missing file is a broken install, never a reason to run with fewer words:
a detector with an empty name list would quietly mask less.
So it fails loudly with a `RuntimeError` naming the missing file only, and
never any word from it.

Stdlib only; no `piimask.core` or evaluation-harness import.
"""

from __future__ import annotations

import functools
import gzip
from importlib.resources import files

from piimask.detect.types import Lexicon

_PACKAGE = "piimask.detect.data"
_FILES = ("nl_words.txt.gz", "nl_names.txt.gz", "en_words.txt.gz")


def _read(name: str) -> frozenset[str]:
    resource = files(_PACKAGE).joinpath(name)
    if not resource.is_file():
        raise RuntimeError(f"detector word lists missing: {name}")
    with gzip.open(resource.open("rb"), mode="rt", encoding="utf-8") as fh:
        return frozenset(line for line in fh.read().split("\n") if line)


@functools.cache
def load_default() -> Lexicon:
    """The packaged Dutch words, Dutch names and English words, read once."""
    nl_words, nl_names, en_words = (_read(name) for name in _FILES)
    return Lexicon(nl_words=nl_words, nl_names=nl_names, en_words=en_words)
