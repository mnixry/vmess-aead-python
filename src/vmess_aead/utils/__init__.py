import hashlib
import uuid
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
            self.buffer = self.hasher.digest(self.buffer_size + self.increase_length)
            self.increase_length *= 2
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


def generate_response_key(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()[0:16]


class SM4GCM:
    def __init__(self, key: bytes) -> None:
        assert len(key) == 16
        self._algorithm = algorithms.SM4(key)

    def encrypt(
        self, nonce: bytes, data: bytes, associated_data: bytes | None
    ) -> bytes:
        assert len(nonce) == 12
        encryptor = Cipher(self._algorithm, modes.GCM(nonce)).encryptor()
        if associated_data is not None:
            encryptor.authenticate_additional_data(associated_data)
        cipher_text = encryptor.update(data) + encryptor.finalize()
        assert encryptor.tag is not None
        return cipher_text + encryptor.tag

    def decrypt(
        self,
        nonce: bytes,
        data: bytes,
        associated_data: bytes | None,
        tag: bytes | None = None,
    ) -> bytes:
        assert len(nonce) == 12
        if tag is None:
            tag = tag or data[-16:]
            data = data[:-16]
        decryptor = Cipher(self._algorithm, modes.GCM(nonce, tag)).decryptor()
        if associated_data is not None:
            decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(data) + decryptor.finalize()
