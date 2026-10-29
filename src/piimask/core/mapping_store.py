"""
The pseudonym key, encrypted at rest (CP3, ledger C37/C38).

The key file is the one thing that turns a pseudonym back into a real name,
so it is never written in the clear. On disk it is two parts:

    {"format":"piimask-mapping","kdf":"keyring","salt":null,"store_id":"<32 hex>","version":1}\\n
    <Fernet token>

The first line is a small JSON header that holds no secret: which way the
encryption key is found (`kdf`), the store's id and, for a passphrase, the
Scrypt salt. The rest is a Fernet token (AES-128-CBC + HMAC-SHA256) over the
JSON key data.

WHERE THE ENCRYPTION KEY LIVES
------------------------------
1. The operating system's keychain through `keyring`: service
   "pii-masking-saas", account "mapping-" + the header's `store_id`. A
   fresh `Fernet.generate_key()` is stored there on the first save. Only
   keychains that really protect a secret are trusted (an allow-list: macOS
   Keychain, Windows Credential Manager, Secret Service, KWallet, libsecret,
   or a chainer made only of those). Any other backend - a plaintext file
   keyring, a null backend - counts as "no keychain".
2. No trusted keychain: a passphrase from PIIMASK_PASSPHRASE, or typed at a
   hidden prompt when - and only when - stdin is a terminal. Scrypt n=2**15,
   r=8, p=1, a 16-byte random salt kept in the header. A NEW store needs a
   passphrase of at least 12 characters; an existing store opens with
   whatever it was made with. Without a terminal and without the variable
   the store stops with a clear message; it never waits on a prompt nobody
   can see.

THE STORE ID
------------
A random id, `secrets.token_hex(16)` (32 lowercase hex characters), made on
the first save and kept in the header as `store_id`. The keychain account is
"mapping-" + that id. Because the id travels with the file, a moved or
renamed home still opens its own key; two stores never share an entry; and
the id says nothing about the key's contents or where it lives. A keychain
header without a valid `store_id` is a bad header (refused). The passphrase
path also writes an id but does not use it: its key comes from the
passphrase and the salt alone.

FAIL CLOSED
-----------
A wrong or missing keychain entry, a wrong passphrase, a flipped byte, a bad
header, an old plaintext key at the store path, or a symlink at the store
path whose target cannot be reached all raise MappingUnreadableError (the
plaintext case its subclass PlaintextKeyError) with "De sleutel kan niet
worden geopend - er wordt níets overschreven." and the path. Nothing is ever
written over an existing file the store cannot open, and the store never
starts fresh over one: `save` first proves it can decrypt what is already
there with the key it is about to use.

NO LOST UPDATES
---------------
`save` over an existing file needs this store object to have read (or
written) exactly those bytes before; if the file changed since - another run
saved in between - or was never read, it refuses and writes nothing. A first
save creates the file exclusively: if a store appeared at the path since it
was found missing, that save refuses too. (The window between the final
check and the move is not locked; two runs racing inside it is not covered.)

WRITES
------
Owner-only from the first byte: a temp sibling opened O_CREAT|O_EXCL with
mode 0o600 (never under the umask) and O_BINARY where it exists, fsync-ed,
then moved over the key with os.replace (atomic, and works over an existing
file on Windows too) - or, for a first save, linked/renamed into place only
if nothing is there. A failed write removes the temp file and leaves the
previous key intact (C14/C15/C16). A valid symlink at the store path is
written through (its target is updated), never replaced by a plain file.

This module needs `cryptography`; `keyring` is imported only when the
keychain is consulted. The standalone validator imports this module lazily,
only when a store is in play, so its stdlib-only mode (C23/C71) still holds.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from piimask.core.errors import MappingUnreadableError, PlaintextKeyError

SERVICE = "pii-masking-saas"
FORMAT = "piimask-mapping"
VERSION = 1
KDF_KEYRING = "keyring"
KDF_SCRYPT = "scrypt"
PASSPHRASE_ENV = "PIIMASK_PASSPHRASE"
MIN_PASSPHRASE = 12

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16

_O_BINARY = getattr(os, "O_BINARY", 0)

# Keychain backends trusted to keep a secret (qualified class names). The
# last one is the tests' file backend (tests/support/test_keyring.py); it
# only exists on a test PYTHONPATH.
TRUSTED_BACKENDS = frozenset({
    "keyring.backends.macOS.Keyring",
    "keyring.backends.Windows.WinVaultKeyring",
    "keyring.backends.SecretService.Keyring",
    "keyring.backends.kwallet.DBusKeyring",
    "keyring.backends.kwallet.DBusKeyringKWallet4",
    "keyring.backends.libsecret.Keyring",
    "test_keyring.FileKeyring",
})
_CHAINER = "keyring.backends.chainer.ChainerBackend"

# The one sentence every refusal opens with.
CANNOT_OPEN = "De sleutel kan niet worden geopend — er wordt níets overschreven."

PLAINTEXT_REASON = (
    "Op deze plek staat nog een ONVERSLEUTELD sleutelbestand (het oude formaat). "
    "Het wordt niet gelezen, niet versleuteld en niet overschreven. Zet het eerst "
    "bewust om naar de versleutelde opslag (migrate_plaintext in "
    "piimask.core.mapping_store) en probeer het daarna opnieuw."
)

DANGLING_REASON = (
    "Het sleutelbestand verwijst naar een plek die nu niet bereikbaar is (een "
    "snelkoppeling naar bijvoorbeeld een losgekoppelde schijf). Sluit die plek "
    "weer aan en probeer het opnieuw; er is niets overschreven."
)

CHANGED_REASON = (
    "Het sleutelbestand is veranderd sinds het werd gelezen (draaide er tegelijk "
    "nog een run?). Er is niets geschreven; start de run opnieuw."
)

_REAL_KEYCHAIN_HINT = (
    "Komt het sleutelbestand van een andere computer of uit een back-up? De "
    "sleutel zelf staat in de sleutelhanger van de computer waarop het bestand "
    "is gemaakt."
)

_STORE_ID = re.compile(r"[0-9a-f]{32}")


def _account(store_id: str) -> str:
    """The keychain account name for a store id (see module doc)."""
    return f"mapping-{store_id}"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_temp(path: Path, data: bytes) -> Path:
    """`data` in an owner-only (0o600 from creation), fsync-ed temp sibling."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write `data` to `path` via an owner-only temp file + fsync + os.replace.

    Moved here from pseudonymize._atomic_write_json (CP3): the key store is
    the one writer of the key. The temp file is mode 600 from creation; on any
    failure it is removed and the previous file is left untouched.
    """
    path = Path(path)
    tmp = _write_temp(path, data)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _create_exclusive(path: Path, data: bytes) -> bool:
    """Put `data` at `path` only if nothing is there; False when something is.

    POSIX: hard-link the finished temp file into place (link fails if the name
    exists). Windows: os.rename, which refuses an existing target.
    """
    path = Path(path)
    tmp = _write_temp(path, data)
    try:
        if os.name == "nt":
            os.rename(tmp, path)
        else:
            os.link(tmp, path)
            tmp.unlink()
    except FileExistsError:
        tmp.unlink(missing_ok=True)
        return False
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return True


def _zero_file(path: Path, size: int) -> None:
    """Overwrite the first `size` bytes of `path` with zeros, in place, fsync."""
    fd = os.open(path, os.O_WRONLY | _O_BINARY)
    try:
        zeros = b"\0" * min(size, 1 << 20)
        remaining = size
        while remaining:
            remaining -= os.write(fd, zeros[:remaining])
        os.fsync(fd)
    finally:
        os.close(fd)


def _is_plaintext_key(raw: bytes) -> bool:
    """True for the OLD key format: a whole-file JSON object with 'forward'."""
    if not raw.lstrip().startswith(b"{"):
        return False
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(data, dict) and "forward" in data


class MappingStore:
    """The encrypted pseudonym key at one path. See the module docstring.

    API: `exists()`, `load() -> dict`, `save(data: dict)`.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        # Read from the header of an existing file, or made on the first save.
        self.store_id: str | None = None
        # Cached after the first successful open/creation, so a run asks for
        # a passphrase once, not on every load and save.
        self._kdf: str | None = None
        self._salt: bytes | None = None
        self._fernet_key: bytes | None = None
        # sha256 of the file's bytes as this object last read or wrote them
        # (K3: a save refuses when the file changed since).
        self._seen_digest: str | None = None

    def __repr__(self) -> str:
        return f"MappingStore({str(self.path)!r})"

    # -- public --------------------------------------------------------

    def exists(self) -> bool:
        """True when ANYTHING is at the path - a dangling symlink included, so
        an unreachable key is never mistaken for "no key yet" (K1)."""
        return os.path.lexists(self.path)

    def load(self) -> dict:
        """Decrypt and return the key data. Raises MappingUnreadableError when
        the file is missing, unreachable, damaged, plaintext, or cannot be
        opened."""
        if not self.exists():
            raise self._error("Het sleutelbestand bestaat niet.")
        raw, header, token = self._read()
        key = self._key_for(header)
        data = self._decrypt(key, token)
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise self._error("De inhoud van het sleutelbestand is beschadigd.") from None
        if not isinstance(parsed, dict):
            raise self._error("De inhoud van het sleutelbestand is beschadigd.")
        self._seen_digest = _digest(raw)
        return parsed

    def save(self, data: dict) -> None:
        """Encrypt `data` and write it atomically, owner-only.

        Over an existing file this first proves the file opens with the key it
        is about to use, and that it is byte for byte what this object last
        read or wrote (fail closed: never overwrite what cannot be opened or
        what changed since, never re-key silently, never write over a
        plaintext key). A first save creates the file exclusively.
        """
        if not isinstance(data, dict):
            raise TypeError("the key data must be a dict")
        if self.exists():
            raw, header, token = self._read()
            key = self._key_for(header)
            self._decrypt(key, token)      # the proof: wrong key -> refuse
            if self._seen_digest is None or not hmac.compare_digest(
                    self._seen_digest, _digest(raw)):
                raise self._error(CHANGED_REASON)
            blob = self._blob(data, header, key)
            atomic_write_bytes(self._target(), blob)
        else:
            header, key = self._new_key()
            blob = self._blob(data, header, key)
            if not _create_exclusive(self.path, blob):
                raise self._error(CHANGED_REASON)
        self._seen_digest = _digest(blob)

    # -- internals -----------------------------------------------------

    def _target(self) -> Path:
        """Where the bytes go: through a (valid) symlink, never replacing it."""
        if self.path.is_symlink():
            return Path(os.path.realpath(self.path))
        return self.path

    @staticmethod
    def _blob(data: dict, header: dict, key: bytes) -> bytes:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        token = Fernet(key).encrypt(payload)
        line = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("ascii")
        return line + b"\n" + token

    def _error(self, reason: str, *, plaintext: bool = False) -> MappingUnreadableError:
        cls = PlaintextKeyError if plaintext else MappingUnreadableError
        return cls(f"{CANNOT_OPEN}\n{reason}\nBestand: {self.path}", reason=reason)

    def _read(self) -> tuple[bytes, dict, bytes]:
        """(raw, header, token) of the file at self.path; refuses anything else."""
        if self.path.is_symlink() and not self.path.exists():
            raise self._error(DANGLING_REASON)
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise self._error(
                f"Het sleutelbestand kan niet gelezen worden ({type(exc).__name__})."
            ) from None
        first, sep, token = raw.partition(b"\n")
        header: Any = None
        if sep:
            try:
                header = json.loads(first.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                header = None
        if not (isinstance(header, dict) and header.get("format") == FORMAT):
            if _is_plaintext_key(raw):
                raise self._error(PLAINTEXT_REASON, plaintext=True)
            raise self._error("Het sleutelbestand heeft geen geldige kop (beschadigd?).")
        if header.get("version") != VERSION:
            raise self._error("Deze versie van het sleutelbestand wordt niet herkend.")
        kdf = header.get("kdf")
        salt_b64 = header.get("salt")
        store_id = header.get("store_id")
        if store_id is not None and not (
                isinstance(store_id, str) and _STORE_ID.fullmatch(store_id)):
            raise self._error("Het sleutelbestand heeft een ongeldige kop.")
        if kdf == KDF_KEYRING:
            if salt_b64 is not None or store_id is None:
                raise self._error("Het sleutelbestand heeft een ongeldige kop.")
        elif kdf == KDF_SCRYPT:
            salt = self._decode_salt(salt_b64)
            if salt is None:
                raise self._error("Het sleutelbestand heeft een ongeldige kop.")
        else:
            raise self._error("Het sleutelbestand heeft een ongeldige kop.")
        if not token:
            raise self._error("Het sleutelbestand is leeg of afgekapt.")
        # Canonical base64 only: a flip in a padding bit, or a character the
        # lenient decoder would skip, still decodes to the same ciphertext -
        # the file was changed, so it is refused all the same.
        try:
            decoded = base64.urlsafe_b64decode(token)
        except (binascii.Error, ValueError):
            decoded = None
        if decoded is None or base64.urlsafe_b64encode(decoded) != token:
            raise self._error("Het sleutelbestand is beschadigd of aangepast.")
        return raw, header, token

    @staticmethod
    def _decode_salt(salt_b64: Any) -> bytes | None:
        if not isinstance(salt_b64, str):
            return None
        try:
            salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            return None
        return salt if len(salt) == SALT_BYTES else None

    def _decrypt(self, key: bytes, token: bytes) -> bytes:
        try:
            return Fernet(key).decrypt(token)
        except (InvalidToken, ValueError, TypeError):
            if self._kdf == KDF_SCRYPT:
                reason = "Verkeerd wachtwoord, of het sleutelbestand is beschadigd."
            else:
                reason = ("De sleutel in de sleutelhanger past niet bij dit bestand, "
                          "of het sleutelbestand is beschadigd.")
            # Forget a key that does not open the file.
            self._kdf = self._salt = self._fernet_key = None
            raise self._error(reason) from None

    def _key_for(self, header: dict) -> bytes:
        """The Fernet key for an EXISTING file, from the source its header names."""
        kdf = header["kdf"]
        if kdf == KDF_KEYRING:
            if (self._kdf == KDF_KEYRING and self._fernet_key is not None
                    and self.store_id == header["store_id"]):
                return self._fernet_key
            self.store_id = header["store_id"]
            key = self._keyring_get()
            if key is None:
                raise self._error(
                    "De sleutel staat niet in de sleutelhanger van deze computer. "
                    + _REAL_KEYCHAIN_HINT)
            self._kdf, self._salt, self._fernet_key = KDF_KEYRING, None, key
            return key
        salt = self._decode_salt(header["salt"])
        assert salt is not None  # checked in _read
        self.store_id = header.get("store_id")
        if (self._kdf == KDF_SCRYPT and self._salt == salt
                and self._fernet_key is not None):
            return self._fernet_key
        key = _derive(self._passphrase(new=False), salt)
        self._kdf, self._salt, self._fernet_key = KDF_SCRYPT, salt, key
        return key

    def _new_key(self) -> tuple[dict, bytes]:
        """(header, key) for a store that has no file yet."""
        if (self._kdf is not None and self._fernet_key is not None
                and self.store_id is not None):
            salt = self._salt
            header = {"format": FORMAT, "version": VERSION, "kdf": self._kdf,
                      "salt": base64.b64encode(salt).decode("ascii") if salt else None,
                      "store_id": self.store_id}
            return header, self._fernet_key
        self.store_id = secrets.token_hex(16)
        if _keyring_usable(note=True):
            key = self._keyring_get_or_create()
            if key is not None:
                self._kdf, self._salt, self._fernet_key = KDF_KEYRING, None, key
                return ({"format": FORMAT, "version": VERSION, "kdf": KDF_KEYRING,
                         "salt": None, "store_id": self.store_id}, key)
        salt = os.urandom(SALT_BYTES)
        key = _derive(self._passphrase(new=True), salt)
        self._kdf, self._salt, self._fernet_key = KDF_SCRYPT, salt, key
        return ({"format": FORMAT, "version": VERSION, "kdf": KDF_SCRYPT,
                 "salt": base64.b64encode(salt).decode("ascii"),
                 "store_id": self.store_id}, key)

    # -- keychain ------------------------------------------------------

    def _keyring_get(self) -> bytes | None:
        """The stored Fernet key, None when there is no entry. Any keychain
        failure (none trusted, locked, denied) refuses."""
        import keyring
        from keyring.errors import KeyringError

        if not _keyring_usable():
            raise self._error(
                "Dit sleutelbestand gebruikt de sleutelhanger, maar op deze computer "
                "is geen vertrouwde sleutelhanger beschikbaar.")
        assert self.store_id is not None
        try:
            value = keyring.get_password(SERVICE, _account(self.store_id))
        except KeyringError as exc:
            raise self._error(
                f"De sleutelhanger gaf geen toegang ({type(exc).__name__}).") from None
        if value is None:
            return None
        key = value.encode("ascii", errors="replace")
        try:
            Fernet(key)
        except (ValueError, TypeError, binascii.Error):
            raise self._error(
                "De sleutel in de sleutelhanger is ongeldig.") from None
        return key

    def _keyring_get_or_create(self) -> bytes | None:
        """First save on a machine with a trusted keychain: store a fresh key
        (an existing entry under the new id is reused, never overwritten).
        None = no keychain after all (NoKeyringError) -> passphrase."""
        import keyring
        from keyring.errors import KeyringError, NoKeyringError

        try:
            existing = self._keyring_get()
        except MappingUnreadableError:
            if not _keyring_usable():
                return None
            raise
        if existing is not None:
            return existing
        key = Fernet.generate_key()
        assert self.store_id is not None
        try:
            keyring.set_password(SERVICE, _account(self.store_id), key.decode("ascii"))
        except NoKeyringError:
            return None
        except KeyringError as exc:
            raise self._error(
                f"De sleutel kon niet in de sleutelhanger worden gezet "
                f"({type(exc).__name__}).") from None
        # Read it back: a keychain that silently drops writes must not leave
        # us with an encrypted file nobody can open.
        stored = self._keyring_get()
        if stored is None or not hmac.compare_digest(stored, key):
            raise self._error("De sleutelhanger bewaarde de nieuwe sleutel niet.")
        return key

    # -- passphrase ----------------------------------------------------

    def _passphrase(self, *, new: bool) -> str:
        """The passphrase, from the environment or a hidden prompt (terminal
        only). A NEW store needs at least MIN_PASSPHRASE characters."""
        value = os.environ.get(PASSPHRASE_ENV)
        if not value:
            stdin = sys.stdin
            if stdin is None or not stdin.isatty():
                raise self._error(
                    "Er is geen sleutelhanger beschikbaar en geen wachtwoord. Zet het "
                    f"wachtwoord in de omgevingsvariabele {PASSPHRASE_ENV}, of start het "
                    "programma in een terminal zodat het erom kan vragen.")
            value = getpass.getpass("Wachtwoord voor de pseudoniemsleutel: ")
            if not value:
                raise self._error("Er is geen wachtwoord ingevuld.")
            if new:
                self._check_length(value)
                second = getpass.getpass("Nog een keer, ter controle: ")
                if not hmac.compare_digest(value.encode("utf-8"), second.encode("utf-8")):
                    raise self._error("De twee wachtwoorden zijn niet gelijk.")
        if new:
            self._check_length(value)
        return value

    def _check_length(self, value: str) -> None:
        if len(value) < MIN_PASSPHRASE:
            raise self._error(
                f"Het wachtwoord voor een nieuwe sleutel moet minstens {MIN_PASSPHRASE} "
                "tekens lang zijn. Er is niets aangemaakt.")


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _qualname(obj: Any) -> str:
    cls = type(obj)
    return f"{cls.__module__}.{cls.__qualname__}"


def _backend_trusted(backend: Any) -> bool:
    """On the allow-list - or a chainer whose every backend is."""
    name = _qualname(backend)
    if name in TRUSTED_BACKENDS:
        return True
    if name == _CHAINER:
        inner = list(getattr(backend, "backends", []) or [])
        return bool(inner) and all(_qualname(b) in TRUSTED_BACKENDS for b in inner)
    return False


_noted_untrusted: set[str] = set()


def _keyring_usable(*, note: bool = False) -> bool:
    """True only for a TRUSTED keychain backend (K4). Anything else - no
    keyring, the fail backend, a plaintext or null backend - is "no
    keychain"; with `note`, an untrusted real backend gets a one-line Dutch
    note on stderr (once per process)."""
    try:
        import keyring
        from keyring.backends import fail
    except ImportError:
        return False
    try:
        backend = keyring.get_keyring()
    except Exception:  # noqa: BLE001 - any backend-resolution failure means "no keychain"
        return False
    if isinstance(backend, fail.Keyring):
        return False
    if _backend_trusted(backend):
        return True
    name = _qualname(backend)
    if note and name not in _noted_untrusted:
        _noted_untrusted.add(name)
        print(f"Let op: sleutelhanger-backend {name} wordt niet vertrouwd; de sleutel "
              "wordt met een wachtwoord versleuteld.", file=sys.stderr)
    return False


# ----------------------------------------------------------------------
# Moving an old plaintext key into the encrypted store
# ----------------------------------------------------------------------

MIGRATED_NOTE = (
    "Het oude, onversleutelde sleutelbestand is overschreven met nullen en "
    "verwijderd: {src}\n"
    "De sleutel staat nu versleuteld in: {dest}\n"
    "Let op: of de oude bytes ook echt van de schijf verdwenen zijn, kan niet "
    "gegarandeerd worden (een SSD of APFS schrijft niet altijd op dezelfde plek). "
    "Zet daarom schijfversleuteling aan: FileVault op een Mac, BitLocker op Windows."
)


def _verified(store: MappingStore, path: Path, data: dict) -> bool:
    """Decrypt the file at `path` with a FRESH store object (sharing only the
    key already in hand, so no second passphrase prompt) and compare."""
    check = MappingStore(path)
    check.store_id, check._kdf, check._salt, check._fernet_key = (
        store.store_id, store._kdf, store._salt, store._fernet_key)
    try:
        return check.load() == data
    except MappingUnreadableError:
        return False


def migrate_plaintext(src_json: Path | str, store: MappingStore) -> str:
    """Encrypt an old plaintext key into `store`, verify, then remove the old file.

    No handle on the old file is open while any file is moved or renamed (a
    Windows rename over a name another handle holds open fails), so:

    1. Read the old file whole, close it, check it is an old plaintext key.
    2. Encrypt into a verified copy:
       - other path: create the store file exclusively (refuse if anything is
         there), then `load()` it back and compare;
       - same path (the old key sits at the store path): write the encrypted
         key to a 0o600 temp sibling and decrypt-and-compare THAT file.
    3. Overwrite the old file's bytes with zeros in place (its own short-lived
       handle), fsync, close.
    4. Same path: move the verified temp over the (now zeroed) name; other
       path: unlink the zeroed old file.

    Guaranteed: the old file's own bytes are overwritten through the file
    system before it goes, and it is gone from its path. NOT guaranteed: that
    the zeros land on the same disk blocks (copy-on-write file systems, SSD
    wear levelling) - hence the advice to turn on disk encryption. Crash
    window (same path only): between steps 3 and 4 the store path holds zeros
    (refused as unreadable) and the verified encrypted key is the
    `.<name>.<pid>.tmp` sibling; renaming it back restores the store.
    Before step 3 a failure leaves the old file exactly as it was.
    Windows: written for it (no open handle across a rename, O_BINARY), not
    run there from this machine.
    """
    src = Path(src_json)
    same_path = os.path.realpath(src) == os.path.realpath(store.path)
    if not src.is_file():
        raise store._error(f"Het oude sleutelbestand bestaat niet: {src}")
    if store.exists() and not same_path:
        raise store._error(
            "Op de plek van de versleutelde sleutel staat al een bestand; er wordt "
            "niets overschreven.")

    fd = os.open(src, os.O_RDONLY | _O_BINARY)
    try:
        chunks = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
    finally:
        os.close(fd)
    original = b"".join(chunks)
    if not _is_plaintext_key(original):
        raise store._error(f"Dit is geen oud sleutelbestand: {src}")
    data = json.loads(original.decode("utf-8"))

    if same_path:
        target = store._target()
        header, key = store._new_key()
        blob = store._blob(data, header, key)
        tmp = _write_temp(target, blob)
        try:
            if not _verified(store, tmp, data):
                raise store._error(
                    "De versleutelde kopie kwam niet overeen; er is niets veranderd.")
            _zero_file(src, len(original))
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        store._seen_digest = _digest(blob)
    else:
        store.save(data)
        if not _verified(store, store.path, data):
            store.path.unlink(missing_ok=True)
            raise store._error("De versleutelde kopie kwam niet overeen; er is niets veranderd.")
        _zero_file(src, len(original))
        src.unlink()
    return MIGRATED_NOTE.format(src=src, dest=store.path)


__all__ = [
    "CANNOT_OPEN",
    "MappingStore",
    "atomic_write_bytes",
    "migrate_plaintext",
]
