from dataclasses import dataclass
from functools import cached_property
from secrets import token_bytes as random_bytes
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vmess_aead.enums import VMessBodyOptions, VMessBodySecurity
from vmess_aead.kdf import kdf16
from vmess_aead.utils import Shake128Stream, fnv1a32, generate_chacha20_poly1305_key
from vmess_aead.utils.reader import BaseReader, StreamCipherReader


@dataclass
class VMessBodyEncoder:
    body_key: bytes
    body_iv: bytes
    options: VMessBodyOptions
    security: VMessBodySecurity
    authenticated_length_key: Optional[bytes] = None
    authenticated_length_iv: Optional[bytes] = None

    count: int = 0

    @cached_property
    def masker(self):
        if not self.options & VMessBodyOptions.CHUNK_MASKING:
            return None
        return Shake128Stream(self.body_iv)

    @property
    def aead_nonce(self) -> bytes:
        return self.count.to_bytes(2, "big") + self.body_iv[2:12]

    def encode(self, data: bytes) -> bytes:
        assert self.options & VMessBodyOptions.CHUNK_STREAM, "Not implemented"
        assert self.count <= 0xFFFF, "Count overflow"

        if self.security is VMessBodySecurity.NONE:
            encrypted_data = data
        elif self.security is VMessBodySecurity.AES_128_CFB:
            encrypted_data = fnv1a32(data).to_bytes(4, "big") + data
        elif self.security is VMessBodySecurity.AES_128_GCM:
            cipher = AESGCM(self.body_key)
            encrypted_data = cipher.encrypt(self.aead_nonce, data, None)
        elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
            cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(self.body_key))
            encrypted_data = cipher.encrypt(self.aead_nonce, data, None)
        else:
            raise ValueError(f"Unknown security: {self.security!r}")

        if self.options & VMessBodyOptions.GLOBAL_PADDING and self.masker is not None:
            padding_length = self.masker.next_uint16() % 64
        else:
            padding_length = 0
        padding = random_bytes(padding_length)

        length = len(encrypted_data) + padding_length

        if self.options & VMessBodyOptions.AUTHENTICATED_LENGTH:
            length_key = self.authenticated_length_key or self.body_key
            length_iv = self.authenticated_length_iv or self.body_iv
            key = kdf16(length_key, [b"auth_len"])
            nonce = self.count.to_bytes(2, "big") + length_iv[2:12]
            if self.security is VMessBodySecurity.AES_128_GCM:
                cipher = AESGCM(key)
            elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
                cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(key))
            else:
                raise ValueError(
                    f"Authenticated length is not supported for {self.security!r}"
                )
            encrypted_length = cipher.encrypt(
                nonce, (length - 16).to_bytes(2, "big"), None
            )
        elif self.masker is not None:
            encrypted_length = (self.masker.next_uint16() ^ length).to_bytes(2, "big")
        else:
            encrypted_length = length.to_bytes(2, "big")

        packet = encrypted_length + encrypted_data + padding
        if self.security is VMessBodySecurity.AES_128_CFB:
            cipher = Cipher(
                algorithms.AES(self.body_key), modes.CFB(self.body_iv)
            ).encryptor()
            packet = cipher.update(packet) + cipher.finalize()

        self.count += 1
        return packet

    def decode_once(self, reader: BaseReader, verify_checksum: bool = True) -> bytes:
        assert self.options & VMessBodyOptions.CHUNK_STREAM, "Not implemented"
        assert self.count <= 0xFFFF, "Count overflow"

        if self.options & VMessBodyOptions.GLOBAL_PADDING and self.masker is not None:
            padding_length = self.masker.next_uint16() % 64
        else:
            padding_length = 0

        if self.security is VMessBodySecurity.AES_128_CFB:
            cipher = Cipher(
                algorithms.AES(self.body_key), modes.CFB(self.body_iv)
            ).decryptor()
            reader = StreamCipherReader(reader, cipher)

        if self.options & VMessBodyOptions.AUTHENTICATED_LENGTH:
            length_key = self.authenticated_length_key or self.body_key
            length_iv = self.authenticated_length_iv or self.body_iv
            nonce = self.count.to_bytes(2, "big") + length_iv[2:12]
            key = kdf16(length_key, [b"auth_len"])
            if self.security is VMessBodySecurity.AES_128_GCM:
                cipher = AESGCM(key)
            elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
                cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(key))
            else:
                raise ValueError(
                    f"Authenticated length is not supported for {self.security!r}"
                )
            encrypted_length = reader.read(2 + 16)  # AEAD tag size is 16 bytes
            decrypted_length = cipher.decrypt(nonce, encrypted_length, None)
            length = int.from_bytes(decrypted_length, "big") + 16
        elif self.masker is not None:
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
        elif self.security is VMessBodySecurity.AES_128_GCM:
            cipher = AESGCM(self.body_key)
            encrypted_data = reader.read(content_length)
            data = cipher.decrypt(self.aead_nonce, encrypted_data, None)
        elif self.security is VMessBodySecurity.CHACHA20_POLY1305:
            cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(self.body_key))
            encrypted_data = reader.read(content_length)
            data = cipher.decrypt(self.aead_nonce, encrypted_data, None)
        else:
            raise ValueError(f"Unknown security: {self.security!r}")
        if padding_length > 0:
            reader.read(padding_length)
        self.count += 1
        return data
