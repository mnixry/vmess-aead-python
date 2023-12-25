import abc
from dataclasses import dataclass
from typing import Generic, Literal, Optional, TypeVar
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vmess_aead.enums import VMessResponseBodyOptions
from vmess_aead.kdf import KDFSaltConst, kdf12, kdf16
from vmess_aead.utils import fnv1a32
from vmess_aead.utils.reader import BaseReader, BytesReader


@dataclass
class VMessResponseCommand(abc.ABC):
    command_id: int

    @staticmethod
    def unwrap(reader: BaseReader, verify_checksum: bool = True):
        command_id = reader.read_byte()
        length = reader.read_byte()
        if command_id == 0x00:
            return None
        elif command_id not in command_registries:
            raise ValueError(f"unknown command id {command_id}")
        checksum = reader.read_uint32()
        command_packet = reader.read(length)
        assert not verify_checksum or checksum == fnv1a32(command_packet)
        return command_registries[command_id].from_packet(command_id, command_packet)

    @abc.abstractclassmethod  # type: ignore
    def from_packet(cls, command_id: int, packet: bytes) -> "VMessResponseCommand":
        raise NotImplementedError

    def _wrap(self, command_packet: bytes):
        packet = b""
        packet += self.command_id.to_bytes(1, "big")
        packet += len(command_packet).to_bytes(1, "big")
        packet += fnv1a32(command_packet).to_bytes(4, "big")
        packet += command_packet
        return packet

    @abc.abstractmethod
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

    @classmethod
    def from_packet(cls, command_id: int, packet: bytes) -> "VMessResponseCommand":
        assert command_id == 0x01
        reader = BytesReader(packet)
        host = reader.read(reader.read_byte()).decode()
        port = reader.read_uint16()
        id_ = UUID(bytes=reader.read(16))
        alter_ids = reader.read_uint16()
        level = reader.read_byte()
        valid_minutes = reader.read_byte()
        return cls(
            command_id,
            host,
            port,
            id_,
            alter_ids,
            level,
            valid_minutes,
        )

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


command_registries = {
    0x01: VMessResponseCommandSwitchAccount,
}

_CT = TypeVar("_CT", bound=VMessResponseCommand)


@dataclass
class VMessAEADResponsePacketHeader(Generic[_CT]):
    """Packet send from server to client"""

    response_header: int
    """Response header, uint8, should be request.response_header"""
    options: VMessResponseBodyOptions
    """Options, uint8 (bitmask)"""
    command: Optional[_CT]
    """Command, optional"""

    @classmethod
    def from_packet(
        cls,
        reader: BaseReader,
        body_key: bytes,
        body_iv: bytes,
        verify_checksum: bool = True,
    ) -> "VMessAEADResponsePacketHeader":
        resp_header_length_key = kdf16(
            body_key, [KDFSaltConst.AEAD_RESP_HEADER_LEN_KEY]
        )
        resp_header_length_nonce = kdf12(
            body_iv, [KDFSaltConst.AEAD_RESP_HEADER_LEN_IV]
        )
        encrypted_resp_header_length = reader.read(2 + 16)
        resp_header_length = int.from_bytes(
            AESGCM(resp_header_length_key).decrypt(
                resp_header_length_nonce, encrypted_resp_header_length, None
            ),
            "big",
        )

        resp_header_key = kdf16(body_key, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_KEY])
        resp_header_nonce = kdf12(body_iv, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_IV])
        encrypted_resp_header = reader.read(resp_header_length + 16)
        resp_header = AESGCM(resp_header_key).decrypt(
            resp_header_nonce, encrypted_resp_header, None
        )
        reader = BytesReader(resp_header)
        response_header = reader.read_byte()
        options = VMessResponseBodyOptions(reader.read_byte())
        command = VMessResponseCommand.unwrap(reader, verify_checksum)
        return cls(response_header, options, command)

    def to_packet(self, body_key: bytes, body_iv: bytes):
        plain_packet = b""
        plain_packet += self.response_header.to_bytes(1, "big")
        plain_packet += self.options.to_bytes(1, "big")
        plain_packet += self.command.to_packet() if self.command else b"\x00\x00"

        packet = b""
        resp_header_length_key = kdf16(
            body_key, [KDFSaltConst.AEAD_RESP_HEADER_LEN_KEY]
        )
        resp_header_length_nonce = kdf12(
            body_iv, [KDFSaltConst.AEAD_RESP_HEADER_LEN_IV]
        )
        resp_header_length = len(plain_packet).to_bytes(2, "big")
        packet += AESGCM(resp_header_length_key).encrypt(
            resp_header_length_nonce, resp_header_length, None
        )

        resp_header_key = kdf16(body_key, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_KEY])
        resp_header_nonce = kdf12(body_iv, [KDFSaltConst.AEAD_RESP_HEADER_PAYLOAD_IV])
        packet += AESGCM(resp_header_key).encrypt(resp_header_nonce, plain_packet, None)
        return packet
