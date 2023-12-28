from dataclasses import dataclass
from functools import cached_property
from secrets import token_bytes
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vmess_aead.enums import VMessBodyCommand, VMessBodyOptions, VMessBodySecurity
from vmess_aead.kdf import kdf16
from vmess_aead.utils import Shake128Stream, fnv1a32, generate_chacha20_poly1305_key
from vmess_aead.utils.reader import BaseReader, StreamCipherReader


@dataclass
class VMessBodyEncoder:
    body_key: bytes
    body_iv: bytes
    options: VMessBodyOptions
    security: VMessBodySecurity
    command: VMessBodyCommand
    authenticated_length_key: Optional[bytes] = None
    authenticated_length_iv: Optional[bytes] = None

    _count: int = 0

    @property
    def count(self) -> int:
        return self._count

    @count.setter
    def count(self, value: int):
        self._count = value & 0xFFFF

    @cached_property
    def masker(self):
        return Shake128Stream(self.body_iv)

    @cached_property
    def aead(self):
        if self.security is VMessBodySecurity.AES_128_GCM:
            return AESGCM(self.body_key)
        elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
            return ChaCha20Poly1305(generate_chacha20_poly1305_key(self.body_key))
        return  # pragma: no cover

    @property
    def aead_nonce(self) -> bytes:
        return self.count.to_bytes(2, "big") + self.body_iv[2:12]

    @cached_property
    def length_aead(self):
        length_key = kdf16(
            self.authenticated_length_key or self.body_key, [b"auth_len"]
        )
        if self.security is VMessBodySecurity.AES_128_GCM:
            return AESGCM(length_key)
        elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
            return ChaCha20Poly1305(generate_chacha20_poly1305_key(length_key))
        return

    @property
    def length_aead_nonce(self) -> bytes:
        length_iv = self.authenticated_length_iv or self.body_iv
        return self.count.to_bytes(2, "big") + length_iv[2:12]

    @cached_property
    def cipher_pair(self):
        if self.security is not VMessBodySecurity.AES_128_CFB:
            return
        return (
            Cipher(algorithms.AES(self.body_key), modes.CFB(self.body_iv)).encryptor(),
            Cipher(algorithms.AES(self.body_key), modes.CFB(self.body_iv)).decryptor(),
        )

    def encode(
        self, data: bytes, padding_generator: Callable[[int], bytes] = token_bytes
    ) -> bytes:
        assert self.options & VMessBodyOptions.CHUNK_STREAM, "Not implemented"

        if self.security is VMessBodySecurity.NONE:
            encrypted_data = data
        elif self.security is VMessBodySecurity.AES_128_CFB:
            encrypted_data = fnv1a32(data).to_bytes(4, "big") + data
        elif self.aead is not None:
            encrypted_data = self.aead.encrypt(self.aead_nonce, data, None)
        else:
            raise ValueError(f"Unknown security: {self.security!r}")  # pragma: no cover

        if self.options & VMessBodyOptions.GLOBAL_PADDING and not (
            self.security is VMessBodySecurity.NONE
            and self.command in (VMessBodyCommand.TCP, VMessBodyCommand.MUX)
        ):
            padding_length = self.masker.next_uint16() % 64
        else:
            padding_length = 0
        padding = padding_generator(padding_length)

        length = len(encrypted_data) + padding_length

        if (
            self.options & VMessBodyOptions.AUTHENTICATED_LENGTH
            and self.length_aead is not None
        ):
            encrypted_length = self.length_aead.encrypt(
                self.length_aead_nonce, (length - 16).to_bytes(2, "big"), None
            )
        elif self.options & VMessBodyOptions.CHUNK_MASKING:
            encrypted_length = (self.masker.next_uint16() ^ length).to_bytes(2, "big")
        else:
            encrypted_length = length.to_bytes(2, "big")

        packet = encrypted_length + encrypted_data + padding
        if self.cipher_pair is not None:
            encryptor, _ = self.cipher_pair
            packet = encryptor.update(packet)

        self.count += 1
        return packet

    def decode_once(self, reader: BaseReader, verify_checksum: bool = True) -> bytes:
        assert self.options & VMessBodyOptions.CHUNK_STREAM, "Not implemented"

        if self.options & VMessBodyOptions.GLOBAL_PADDING and not (
            self.security is VMessBodySecurity.NONE
            and self.command in (VMessBodyCommand.TCP, VMessBodyCommand.MUX)
        ):
            padding_length = self.masker.next_uint16() % 64
        else:
            padding_length = 0

        if self.cipher_pair is not None:
            _, decryptor = self.cipher_pair
            reader = StreamCipherReader(reader, decryptor)

        if (
            self.options & VMessBodyOptions.AUTHENTICATED_LENGTH
            and self.length_aead is not None
        ):
            encrypted_length = reader.read(2 + 16)
            decrypted_length = self.length_aead.decrypt(
                self.length_aead_nonce, encrypted_length, None
            )
            length = int.from_bytes(decrypted_length, "big") + 16
        elif self.options & VMessBodyOptions.CHUNK_MASKING:
            length = reader.read_uint16() ^ self.masker.next_uint16()
        else:
            length = reader.read_uint16()

        content_length = length - padding_length

        if self.security is VMessBodySecurity.NONE:
            data = reader.read(content_length)
        elif self.security is VMessBodySecurity.AES_128_CFB:
            checksum = reader.read_uint32()
            data = reader.read(content_length - 4)
            assert not verify_checksum or checksum == fnv1a32(data)
        elif self.aead is not None:
            encrypted_data = reader.read(content_length)
            data = self.aead.decrypt(self.aead_nonce, encrypted_data, None)
        else:
            raise ValueError(f"Unknown security: {self.security!r}")  # pragma: no cover
        if padding_length > 0:
            reader.read(padding_length)
        self.count += 1
        return data
