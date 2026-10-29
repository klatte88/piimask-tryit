"""
The try-it layer: the free-text masker as a practitioner meets it in a browser tab.

A practitioner pastes a prompt, sees it masked, takes the masked prompt to
their own AI, pastes the answer back and sees the real values return; then
flags what went wrong and exports a feedback file they read before sending.
This package is the Python side of that page: `session` wraps the existing
span masker, rules detector and pseudonymiser over a key held only in memory
and answers the page in plain JSON; `feedback` builds the privacy-safe
feedback document.

It never changes masker behaviour: open product decisions (D41, a prompt
already holding a token; D42, an already-masked address) are surfaced as
warnings and codes, never decided here.

It never writes a file and never touches a keychain: the key lives in an
in-memory store for the life of the tab, so the same code runs unchanged in
Pyodide, where there is no disk and no keychain, and in CPython, where the
parity proof compares the two byte for byte.

Nothing is imported here on purpose: importing one submodule must never drag
in another (the same rule as `piimask.detect`).
"""
