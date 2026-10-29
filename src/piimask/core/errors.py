"""
The core's exceptions, in one stdlib-only module.

Every one of these is a HARD failure. None is meant to be caught so a run can
carry on: each means the tool cannot vouch for what it would write.
"""

from __future__ import annotations


class SchemaDriftError(Exception):
    """
    Raised when the database schema does not match the PII manifest.

    This is a HARD failure. Do not catch it to continue the run; the whole
    point is that an unrecognised column may contain personal data that no
    pseudonymization rule covers.
    """


class PseudonymizationLeakError(Exception):
    """
    Raised when personal data survived pseudonymization.

    The offending output file is deleted before this is raised. Do not
    catch this to continue: a partially-pseudonymized database is more
    dangerous than no database, because everything downstream trusts the
    "_pseudo" filename and treats it as safe to share.
    """


class MappingUnreadableError(Exception):
    """
    Raised when a pseudonym key exists but cannot be read or parsed.

    Starting from an empty key instead would reuse pseudonyms that already
    mean someone else in data shared earlier, and `reveal` would then give the
    wrong name. The message names the path, never the contents.

    `reason` is an optional short Dutch sentence the key store sets (CP3): it
    says WHY the key cannot be opened (no keychain entry, wrong passphrase,
    damaged file) and, like the message, never holds a value from the key.
    """

    def __init__(self, message: str = "", *, reason: str | None = None):
        super().__init__(message)
        self.reason = reason


class PlaintextKeyError(MappingUnreadableError):
    """
    Raised when an OLD, unencrypted key file sits where the encrypted key
    belongs (CP3). It is never read as the key, never encrypted on the fly and
    never overwritten: moving it into the encrypted store is a deliberate step
    (`migrate_plaintext`), taken on the owner's word.
    """


__all__ = [
    "MappingUnreadableError",
    "PlaintextKeyError",
    "PseudonymizationLeakError",
    "SchemaDriftError",
]
