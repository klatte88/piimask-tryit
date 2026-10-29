"""
piimask.core - the masking core (schema guard, pseudonymiser, leak validator).

Nothing is imported eagerly here. `python -m piimask.core.validate` must run
with the standard library alone (C23/C71), and the pseudonymiser pulls in
PyYAML through the schema guard - so the package names below resolve lazily,
on first attribute access.
"""

from __future__ import annotations

from typing import Any

__all__ = ["UnifiedPseudonymizer", "create_pseudonymizer"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import pseudonymize

        return getattr(pseudonymize, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
