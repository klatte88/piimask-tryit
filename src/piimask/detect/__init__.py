"""
The free-text detector: deterministic rules that find PII spans in a prompt.

This package finds people, companies, emails, IBANs, VAT numbers and phones
in free text with code over word lists, never a model, so the same text
always yields the same spans.
It sits in front of the LLM proxy: the span masker replaces exactly the
detected spans with pseudonyms from the shared key, so literal text is never
edited and reveal is byte-exact by construction.

The modules:

- `types` holds the shared contract (`Detected`, `SOURCES`, `ALL_RULES`,
  `Lexicon`, `DetectorProtocol`), written first so the other modules,
  built in parallel, import one fixed set of names.
- `lexicon` loads the packaged word lists.
- `rules` and `detector` run the rules in a fixed order.
- `masker` replaces and reveals spans through the core pseudonymiser.

Nothing is imported here on purpose: importing one submodule must never drag
in another, so a module still being built cannot break one already done.
"""
