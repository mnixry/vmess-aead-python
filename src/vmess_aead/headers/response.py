from dataclasses import dataclass
from typing import Literal, Optional
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vmess_aead.enums import VMessResponseBodyOptions
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.utils import fnv1a32


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
