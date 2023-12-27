import abc
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, TypeVar


class KDFSaltConst(bytes, Enum):
    AUTH_ID_ENCRYPTION_KEY = b"AES Auth ID Encryption"
    AEAD_RESP_HEADER_LEN_KEY = b"AEAD Resp Header Len Key"
    AEAD_RESP_HEADER_LEN_IV = b"AEAD Resp Header Len IV"
    AEAD_RESP_HEADER_PAYLOAD_KEY = b"AEAD Resp Header Key"
    AEAD_RESP_HEADER_PAYLOAD_IV = b"AEAD Resp Header IV"
    VMESS_AEAD_KDF = b"VMess AEAD KDF"
    VMESS_HEADER_PAYLOAD_AEAD_KEY = b"VMess Header AEAD Key"
    VMESS_HEADER_PAYLOAD_AEAD_IV = b"VMess Header AEAD Nonce"
    VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY = b"VMess Header AEAD Key_Length"
    VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV = b"VMess Header AEAD Nonce_Length"


_T = TypeVar("_T")


class VMessHash(abc.ABC):
    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def digest(self) -> bytes:
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    def copy(self: _T) -> _T:
        raise NotImplementedError  # pragma: no cover


class Sha256Hash(VMessHash):
    def __init__(self, hash: Optional["hashlib._Hash"] = None) -> None:
        self._hash = hash or hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._hash.update(data)

    def copy(self):
        return Sha256Hash(self._hash.copy())

    def digest(self) -> bytes:
        return self._hash.digest()


@dataclass
class RecursiveHash(VMessHash):
    inner: VMessHash
    outer: VMessHash
    in_: bytes
    out: bytes

    @classmethod
    def create(cls, key: bytes, hasher: VMessHash):
        assert len(key) <= 64
        in_ = bytes(char ^ 0x36 for char in key.ljust(64, b"\x00"))
        out = bytes(char ^ 0x5C for char in key.ljust(64, b"\x00"))
        inner = hasher.copy()
        outer = hasher
        inner.update(in_)
        return cls(inner, outer, in_, out)

    def copy(self):
        new_inner = self.inner.copy()
        new_outer = self.outer.copy()
        return type(self)(new_inner, new_outer, self.in_, self.out)

    def update(self, data: bytes):
        self.inner.update(data)

    def digest(self):
        inner_result = self.inner.digest()[:32]
        self.outer.update(self.out)
        self.outer.update(inner_result)
        return self.outer.digest()


def kdf(key: bytes, path: List[bytes]):
    current = RecursiveHash.create(KDFSaltConst.VMESS_AEAD_KDF, Sha256Hash())
    for item in path:
        current = RecursiveHash.create(item, current)
    current.update(key)
    return current.digest()


def kdf16(key: bytes, path: List[bytes]):
    return kdf(key, path)[:16]


def kdf12(key: bytes, path: List[bytes]):
    return kdf(key, path)[:12]
