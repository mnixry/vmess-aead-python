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


class Shake128Stream:
    def __init__(
        self,
        nonce: bytes,
        initial_length: int = 32,
        increase_length: int = 32,
    ) -> None:
        self.hasher = hashlib.shake_128(nonce)
        self.buffer = self.hasher.digest(initial_length)
        self.increase_length = increase_length
        self.buffer_cursor = 0

    @property
    def buffer_size(self) -> int:
        return len(self.buffer)

    def next_byte(self) -> int:
        if self.buffer_cursor >= self.buffer_size:
            self.buffer = self.hasher.digest(self.increase_length)
        byte = self.buffer[self.buffer_cursor]
        self.buffer_cursor += 1
        return byte

    def next_bytes(self, length: int) -> bytes:
        return bytes(self.next_byte() for _ in range(length))

    def next_uint16(self) -> int:
        return int.from_bytes(self.next_bytes(2), "big")


def generate_chacha20_poly1305_key(b: bytes) -> bytes:
    key = hashlib.md5(b).digest()
    key += hashlib.md5(key).digest()
    return key
