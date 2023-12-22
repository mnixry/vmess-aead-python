import hashlib
import uuid
from functools import lru_cache


@lru_cache(maxsize=1)
def cmd_key(uuid: uuid.UUID) -> bytes:
    hasher = hashlib.md5()
    hasher.update(uuid.bytes)
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
    return hasher.digest()


def fnv1a32(data: bytes) -> int:
    hash_ = 0x811C9DC5
    for byte in data:
        hash_ ^= byte
        hash_ *= 0x01000193
    return hash_ & 0xFFFFFFFF
