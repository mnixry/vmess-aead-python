import itertools
from dataclasses import dataclass
from secrets import token_bytes as random_bytes
from typing import TYPE_CHECKING, Iterable, Literal, Optional
from uuid import UUID

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vmess_aead.enums import (
    VMessBodyOptions,
    VMessBodySecurity,
    VMessResponseBodyOptions,
)
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.utils import Shake128Stream, fnv1a32, generate_chacha20_poly1305_key

if TYPE_CHECKING:
    from .request import VMessAEADRequestPacketHeader


@dataclass
class VMessResponseCommand:
    command_id: int

    def _wrap(self, command_packet: bytes):
        packet = b""
        packet += self.command_id.to_bytes(1, "big")
        packet += len(command_packet).to_bytes(1, "big")
        packet += fnv1a32(command_packet).to_bytes(4, "big")
        packet += command_packet
        return packet

    def to_packet(self):
        raise NotImplementedError


@dataclass
class VMessResponseCommandSwitchAccount(VMessResponseCommand):
    command_id: Literal[0x01]

    host: str
    """Host, variable length, zero length means no change"""
    port: int
    """Port, uint16, big endian"""
    id_: UUID
    """ID, 16 bytes"""
    alter_ids: int
    """Alter IDs, uint16, big endian"""
    level: int
    """Level, uint8"""
    valid_minutes: int
    """Valid time duration in minutes, uint8, big endian"""

    def to_packet(self):
        packet = b""
        packet += len(self.host).to_bytes(1, "big")
        packet += self.host.encode()
        packet += self.port.to_bytes(2, "big")
        packet += self.id_.bytes
        packet += self.alter_ids.to_bytes(2, "big")
        packet += self.level.to_bytes(1, "big")
        packet += self.valid_minutes.to_bytes(1, "big")
        return self._wrap(packet)


@dataclass
class VMessAEADResponsePacketHeader:
    """Packet send from server to client"""

    body_key: bytes
    """Body key, 16 bytes, should be sha256(request.body_key)"""
    body_iv: bytes
    """Body IV, 16 bytes, should be sha256(request.body_iv)"""
    response_header: int
    """Response header, uint8, should be request.response_header"""
    options: VMessResponseBodyOptions
    """Options, uint8 (bitmask)"""
    command: Optional[VMessResponseCommand]
    """Command, optional"""

    def to_packet(self):
        plain_packet = b""
        plain_packet += self.response_header.to_bytes(1, "big")
        plain_packet += self.options.to_bytes(1, "big")
        plain_packet += self.command.to_packet() if self.command else b"\x00\x00"

        packet = b""
        resp_header_length_key = kdf16(
            self.body_key, [KDFSaltConst.AEAD_RESP_HEADER_LEN_KEY]
        )
        resp_header_length_nonce = kdf12(
            self.body_iv, [KDFSaltConst.AEAD_RESP_HEADER_LEN_IV]
        )
        resp_header_length = len(plain_packet).to_bytes(2, "big")
        packet += AESGCM(resp_header_length_key).encrypt(
            resp_header_length_nonce, resp_header_length, None
        )

        resp_header_key = kdf16(
            self.body_key, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_KEY]
        )
        resp_header_nonce = kdf12(
            self.body_iv, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_IV]
        )
        packet += AESGCM(resp_header_key).encrypt(resp_header_nonce, plain_packet, None)
        return packet

    def encode_body(
        self, request: "VMessAEADRequestPacketHeader", buffer: Iterable[bytes]
    ):
        # TODO: move this function to separate class
        masker = None
        if request.payload.options & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Stream(self.body_iv)

        for count, data in zip(itertools.count(), buffer):
            # TODO: add check if not using chunked data
            if request.payload.security is VMessBodySecurity.NONE:
                encrypted_data = data
            elif request.payload.security is VMessBodySecurity.AES_128_CFB:
                encryptor = Cipher(
                    algorithms.AES(self.body_key),
                    modes.CFB(self.body_iv),
                ).encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                encrypted_data += fnv1a32(data).to_bytes(4, "big")
            elif request.payload.security is VMessBodySecurity.AES_128_GCM:
                cipher = AESGCM(self.body_key)
                aead_nonce = count.to_bytes(2, "big") + self.body_iv[2:12]
                encrypted_data = cipher.encrypt(aead_nonce, data, None)
            elif request.payload.security is VMessBodySecurity.CHACHA20_POLY1305:
                cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(self.body_key))
                aead_nonce = count.to_bytes(2, "big") + self.body_iv[2:12]
                encrypted_data = cipher.encrypt(aead_nonce, data, None)
            else:
                raise ValueError(f"Unknown security: {request.payload.security!r}")

            if (
                request.payload.options & VMessBodyOptions.GLOBAL_PADDING
                and masker is not None
            ):
                padding_length = masker.next_uint16() % 64
            else:
                padding_length = 0
            padding = random_bytes(padding_length)

            length = len(encrypted_data) + padding_length
            if request.payload.options & VMessBodyOptions.AUTHENTICATED_LENGTH:
                key = kdf16(request.payload.body_key, [b"auth_len"])
                aead_nonce = count.to_bytes(2, "big") + request.payload.body_iv[2:12]
                if request.payload.security is VMessBodySecurity.AES_128_GCM:
                    cipher = AESGCM(key)
                elif request.payload.security is VMessBodySecurity.CHACHA20_POLY1305:
                    cipher = ChaCha20Poly1305(generate_chacha20_poly1305_key(key))
                else:
                    raise ValueError(
                        f"Authenticated length is not supported for {request.payload.security!r}"
                    )
                encrypted_length = cipher.encrypt(
                    aead_nonce, (length - 16).to_bytes(2, "big"), None
                )
            elif masker is not None:
                encrypted_length = (masker.next_uint16() ^ length).to_bytes(2, "big")
            else:
                encrypted_length = length.to_bytes(2, "big")

            yield encrypted_length + encrypted_data + padding
        return
